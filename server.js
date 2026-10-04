// EIN Launch Pad — single-file bundle for deploy.
// Built from ~/workspace/ein-launch-pad/ by build-deploy-bundle.js.
// Do NOT edit by hand; rebuild from source.
require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const cookie = require('cookie');
const { DatabaseSync } = require('node:sqlite');

// ================= db.js =================
// SQLite storage (Node built-in node:sqlite — no native addons needed).
// EVERY table that holds customer content has a user_id column.
// All queries MUST filter by user_id = req.user.id so buyers never see
// each other's data.

const DB_PATH = process.env.DB_PATH
  ? path.resolve(process.env.DB_PATH)
  : path.join(__dirname, '..', 'data', 'einlaunch.db');

let db = null;

function getDb() {
  if (!db) {
    fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
    db = new DatabaseSync(DB_PATH);
    db.exec('PRAGMA journal_mode = WAL;');
    initSchema(db);
  }
  return db;
}

function initSchema(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      stripe_customer_id TEXT,
      stripe_session_id TEXT,
      paid_at TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      expires_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS pending_purchases (
      session_id TEXT PRIMARY KEY,
      email TEXT,
      paid_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS ein_applications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
      entity_type TEXT NOT NULL DEFAULT '',
      eligibility_json TEXT NOT NULL DEFAULT '{}',
      legal_name TEXT NOT NULL DEFAULT '',
      trade_name TEXT NOT NULL DEFAULT '',
      mailing_address TEXT NOT NULL DEFAULT '',
      responsible_party TEXT NOT NULL DEFAULT '',
      ssn_itin TEXT NOT NULL DEFAULT '',
      business_activity TEXT NOT NULL DEFAULT '',
      employees_first_year TEXT NOT NULL DEFAULT '',
      fiscal_year_end TEXT NOT NULL DEFAULT '',
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_ein_app_user ON ein_applications(user_id);
  `);
}

// Fetch (or lazily create) the single EIN application row for a user.
function getApplication(userId) {
  const db = getDb();
  let row = db.prepare('SELECT * FROM ein_applications WHERE user_id = ?').get(userId);
  if (!row) {
    db.prepare('INSERT INTO ein_applications (user_id) VALUES (?)').run(userId);
    row = db.prepare('SELECT * FROM ein_applications WHERE user_id = ?').get(userId);
  }
  return row;
}

function saveApplication(userId, fields) {
  const allowed = [
    'entity_type', 'eligibility_json', 'legal_name', 'trade_name',
    'mailing_address', 'responsible_party', 'ssn_itin',
    'business_activity', 'employees_first_year', 'fiscal_year_end',
  ];
  const cols = Object.keys(fields).filter((c) => allowed.includes(c));
  if (!cols.length) return;
  getApplication(userId); // ensure the row exists
  getDb().prepare(
    `UPDATE ein_applications SET ${cols.map((c) => `${c} = ?`).join(', ')}, updated_at = datetime('now') WHERE user_id = ?`
  ).run(...cols.map((c) => fields[c]), userId);
}


// ================= auth.js =================
// Auth: email+password login with DB-backed sessions.
// Passwords are hashed with bcrypt. Session tokens are random 256-bit
// values stored in the sessions table and sent as an httpOnly cookie.

const COOKIE_NAME = 'einlaunch_session';
const SESSION_DAYS = 30;

async function hashPassword(pw) {
  return bcrypt.hash(pw, 10);
}

async function verifyPassword(pw, hash) {
  return bcrypt.compare(pw, hash);
}

function createSession(userId) {
  const db = getDb();
  // One active login per account: a new login kicks out any other device.
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + SESSION_DAYS * 864e5);
  db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?,?,?)')
    .run(token, userId, expires.toISOString().slice(0, 19).replace('T', ' '));
  return { token, expires };
}

function destroySession(token) {
  if (token) getDb().prepare('DELETE FROM sessions WHERE token = ?').run(token);
}

function getCookieToken(req) {
  const parsed = cookie.parse(req.headers.cookie || '');
  return parsed[COOKIE_NAME] || null;
}

function setSessionCookie(req, res, token, expires) {
  const isProd = process.env.NODE_ENV === 'production';
  const serialized = cookie.serialize(COOKIE_NAME, token, {
    httpOnly: true,
    path: '/',
    sameSite: 'lax',
    secure: isProd,
    expires,
  });
  res.setHeader('Set-Cookie', serialized);
}

function clearSessionCookie(res) {
  const isProd = process.env.NODE_ENV === 'production';
  res.setHeader('Set-Cookie', cookie.serialize(COOKIE_NAME, '', {
    httpOnly: true, path: '/', sameSite: 'lax', secure: isProd, expires: new Date(0),
  }));
}

// Attaches req.user = { id, email, paidAt } | null
function sessionMiddleware(req, res, next) {
  req.user = null;
  try {
    const token = getCookieToken(req);
    if (token) {
      const row = getDb().prepare(`
        SELECT u.id AS id, u.email AS email, u.paid_at AS paidAt
        FROM sessions s JOIN users u ON u.id = s.user_id
        WHERE s.token = ? AND s.expires_at > datetime('now')
      `).get(token);
      if (row) req.user = { id: row.id, email: row.email, paidAt: row.paidAt };
    }
  } catch (e) { /* fail closed: req.user stays null */ }
  next();
}

function requireAuth(req, res, next) {
  if (!req.user) {
    if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Not signed in' });
    return res.redirect('/login');
  }
  next();
}


// ================= views/landing.js =================
// Landing page templates for EIN Launch Pad's public sales site.
// Pure functions that return HTML strings. All interpolated user content
// must go through esc().
// HONESTY RULES: this app prepares a draft — it does NOT file with the IRS
// and does NOT issue EINs. Never claim otherwise. No testimonials, no user
// counts, no invented figures.
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[c]));

const PRICE = '13.99';

function layout({ title, body, extraHead = '' }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<meta name="description" content="EIN Launch Pad — guided IRS EIN (Form SS-4) preparation in about 3 minutes. Pay $13.99 once, own it forever.">
<style>/* style.css (inlined for single-file deploy) */
/* Shared base styles. Feature CSS lives in public/app.css (dashboard)
   and public/landing.css (sales site) — do not put feature styles here. */
:root {
  --bg: #0f1420;
  --bg-soft: #161d2e;
  --card: #1b2338;
  --border: #2a3450;
  --text: #eef2ff;
  --muted: #9aa6c4;
  --accent: #4f7cff;
  --accent-hover: #3d68f0;
  --green: #34d399;
  --red: #f87171;
  --radius: 12px;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  line-height: 1.5;
}
a { color: var(--accent); }
.muted { color: var(--muted); }
.small { font-size: 0.85rem; }
.error {
  background: rgba(248,113,113,.12); border: 1px solid var(--red);
  color: var(--red); padding: 0.6rem 0.9rem; border-radius: 8px;
}
.btn {
  display: inline-block; border: 0; cursor: pointer; border-radius: 8px;
  padding: 0.7rem 1.4rem; font-size: 1rem; font-weight: 600; text-decoration: none;
}
.btn-primary { background: var(--accent); color: #fff; }
.btn-primary:hover { background: var(--accent-hover); }
.btn-ghost { background: transparent; color: var(--text); border: 1px solid var(--border); }
input, select, textarea {
  width: 100%; padding: 0.65rem 0.8rem; margin: 0.25rem 0 0.9rem;
  background: var(--bg-soft); border: 1px solid var(--border); color: var(--text);
  border-radius: 8px; font-size: 1rem;
}
label { display: block; font-size: 0.9rem; color: var(--muted); }
.auth-body { display: flex; min-height: 100vh; align-items: center; justify-content: center; padding: 1rem; }
.auth-card {
  background: var(--card); border: 1px solid var(--border); border-radius: var(--radius);
  padding: 2rem; width: 100%; max-width: 400px;
}
.auth-card h1 { margin: 0 0 0.25rem; font-size: 1.4rem; }
.card {
  background: var(--card); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 1.25rem;
}
table { width: 100%; border-collapse: collapse; font-size: 0.95rem; }
th, td { text-align: left; padding: 0.6rem 0.5rem; border-bottom: 1px solid var(--border); }
th { color: var(--muted); font-weight: 600; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.04em; }
.empty { text-align: center; color: var(--muted); padding: 2.5rem 1rem; }
.empty p { margin: 0.4rem 0 1rem; }
</style>
<style>/* landing.css (inlined for single-file deploy) */
/* EIN Launch Pad sales site. Dark theme matching shared vars in style.css.
   Base link/button/form styles come from /style.css; everything here is
   landing-specific. */

.l-wrap {
  max-width: 1080px;
  margin: 0 auto;
  padding: 0 1.25rem;
}

/* ---- sticky nav ---- */
.l-nav {
  position: sticky;
  top: 0;
  z-index: 50;
  background: rgba(15, 20, 32, 0.92);
  backdrop-filter: blur(8px);
  border-bottom: 1px solid var(--border);
}
.l-nav-inner {
  display: flex;
  align-items: center;
  gap: 1.5rem;
  padding-top: 0.8rem;
  padding-bottom: 0.8rem;
}
.l-logo {
  font-weight: 800;
  font-size: 1.15rem;
  color: var(--text);
  text-decoration: none;
  letter-spacing: 0.01em;
  white-space: nowrap;
}
.l-nav-links {
  display: flex;
  gap: 1.25rem;
  margin-left: auto;
}
.l-nav-links a {
  color: var(--muted);
  text-decoration: none;
  font-size: 0.95rem;
}
.l-nav-links a:hover { color: var(--text); }
.l-nav-cta {
  display: flex;
  align-items: center;
  gap: 0.9rem;
}
.l-signin {
  color: var(--muted);
  text-decoration: none;
  font-size: 0.95rem;
}
.l-signin:hover { color: var(--text); }

/* ---- hero ---- */
.l-hero {
  text-align: center;
  padding: 4.5rem 0 3rem;
  background: radial-gradient(ellipse 70% 45% at 50% 0%, rgba(79, 124, 255, 0.14), transparent);
}
.l-eyebrow {
  color: var(--accent);
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  font-size: 0.8rem;
  margin: 0 0 1rem;
}
.l-hero h1 {
  font-size: 2.9rem;
  line-height: 1.12;
  margin: 0 auto 1rem;
  max-width: 16em;
}
.l-sub {
  color: var(--muted);
  font-size: 1.15rem;
  max-width: 34em;
  margin: 0 auto 1.8rem;
}
.l-hero-cta { margin-bottom: 2.5rem; }
.l-cta-big {
  font-size: 1.1rem;
  padding: 0.9rem 2rem;
}
.l-hero-cta .muted { margin-top: 0.7rem; }

/* ---- stylized dashboard mock (illustration, not a screenshot) ---- */
.mock {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  max-width: 820px;
  margin: 0 auto;
  text-align: left;
  box-shadow: 0 24px 60px rgba(0, 0, 0, 0.45);
  overflow: hidden;
}
.mock-bar {
  display: flex;
  align-items: center;
  gap: 0.45rem;
  padding: 0.7rem 1rem;
  border-bottom: 1px solid var(--border);
}
.mock-dot {
  width: 11px;
  height: 11px;
  border-radius: 50%;
  background: var(--border);
}
.mock-bar-title {
  margin-left: 0.5rem;
  color: var(--muted);
  font-size: 0.85rem;
}
.mock-body { padding: 1.1rem; }
.mock-cards {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 0.75rem;
  margin-bottom: 0.75rem;
}
.mock-card {
  background: var(--bg-soft);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0.7rem 0.85rem;
  display: flex;
  flex-direction: column;
  gap: 0.2rem;
}
.mock-k {
  color: var(--muted);
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}
.mock-v { font-size: 1.35rem; font-weight: 700; }
.mock-green { color: var(--green); }
.mock-cols {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.75rem;
  margin-bottom: 0.75rem;
}
.mock-panel {
  background: var(--bg-soft);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0.7rem 0.85rem;
}
.mock-row {
  display: flex;
  justify-content: space-between;
  padding: 0.35rem 0;
  font-size: 0.9rem;
  border-top: 1px solid var(--border);
}
.mock-row:first-of-type { border-top: 0; }
.mock-row b { font-weight: 600; }
.mock-chart {
  display: flex;
  align-items: flex-end;
  gap: 8px;
  height: 90px;
  background: var(--bg-soft);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 12px 14px;
}
.mock-chart span {
  flex: 1;
  border-radius: 4px 4px 0 0;
  background: linear-gradient(to top, var(--accent), #7fa1ff);
  opacity: 0.85;
}
.mock-bar1 { height: 35%; }
.mock-bar2 { height: 55%; }
.mock-bar3 { height: 42%; }
.mock-bar4 { height: 75%; }
.mock-bar5 { height: 95%; }
.mock-caption {
  margin: 0;
  padding: 0.6rem 1.1rem;
  color: var(--muted);
  font-size: 0.78rem;
  border-top: 1px solid var(--border);
}

/* ---- sections ---- */
.l-section { padding: 4rem 0; }
.l-alt { background: var(--bg-soft); border-top: 1px solid var(--border); border-bottom: 1px solid var(--border); }
.l-section h2 {
  font-size: 2rem;
  margin: 0 0 0.6rem;
  text-align: center;
}
.l-lead {
  text-align: center;
  max-width: 42em;
  margin: 0 auto 2.2rem;
}
.l-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 1rem;
}
.l-feature h3 { margin: 0 0 0.5rem; font-size: 1.08rem; }
.l-feature p { margin: 0; font-size: 0.95rem; }

/* ---- how it works ---- */
.l-steps {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 1rem;
  margin-top: 2rem;
}
.l-step {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 1.6rem 1.4rem;
  text-align: center;
}
.l-step-num {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 2.6rem;
  height: 2.6rem;
  border-radius: 50%;
  background: var(--accent);
  color: #fff;
  font-weight: 800;
  font-size: 1.2rem;
  margin-bottom: 0.9rem;
}
.l-step h3 { margin: 0 0 0.4rem; }
.l-step p { margin: 0; }

/* ---- pricing ---- */
.l-price-card {
  max-width: 520px;
  margin: 2rem auto 0;
  text-align: center;
  padding: 2.2rem;
}
.l-price-name { font-weight: 700; font-size: 1.1rem; margin: 0 0 0.4rem; }
.l-price { font-size: 3.2rem; font-weight: 800; margin: 0 0 1.4rem; }
.l-price .muted { font-size: 1.1rem; font-weight: 400; }
.l-includes {
  list-style: none;
  margin: 0 0 1.8rem;
  padding: 0;
  text-align: left;
}
.l-includes li {
  padding: 0.45rem 0 0.45rem 1.9rem;
  position: relative;
  border-top: 1px solid var(--border);
}
.l-includes li:first-child { border-top: 0; }
.l-includes li::before {
  content: "✓";
  color: var(--green);
  font-weight: 800;
  position: absolute;
  left: 0.4rem;
}

/* ---- faq ---- */
.l-faq { max-width: 680px; margin: 2rem auto 0; }
.l-faq-item {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  margin-bottom: 0.75rem;
  padding: 0.4rem 1.2rem;
}
.l-faq-item summary {
  cursor: pointer;
  font-weight: 700;
  padding: 0.8rem 0;
  font-size: 1.02rem;
}
.l-faq-item p { margin: 0 0 1rem; }

/* ---- footer ---- */
.l-footer {
  border-top: 1px solid var(--border);
  padding: 1.6rem 0;
}
.l-footer-inner {
  display: flex;
  align-items: center;
  gap: 1.2rem;
  flex-wrap: wrap;
}
.l-footer-inner .muted { margin-left: auto; }
.l-footer-inner a.muted { text-decoration: none; }
.l-footer-inner a.muted:hover { color: var(--text); }

/* ---- responsive ---- */
@media (max-width: 860px) {
  .l-grid { grid-template-columns: 1fr 1fr; }
  .l-hero h1 { font-size: 2.2rem; }
  .l-nav-links { display: none; }
  .mock-cards { grid-template-columns: 1fr 1fr; }
}
@media (max-width: 600px) {
  .l-grid, .l-steps { grid-template-columns: 1fr; }
  .mock-cols { grid-template-columns: 1fr; }
  .l-hero h1 { font-size: 1.8rem; }
  .l-nav-cta .btn { padding: 0.6rem 1rem; font-size: 0.9rem; }
}
</style>
${extraHead}
</head>
<body>
${body}
</body>
</html>`;
}

function nav() {
  return `<header class="l-nav">
  <div class="l-wrap l-nav-inner">
    <a class="l-logo" href="/">EIN Launch Pad</a>
    <nav class="l-nav-links">
      <a href="/#features">Features</a>
      <a href="/#pricing">Pricing</a>
      <a href="/#faq">FAQ</a>
    </nav>
    <div class="l-nav-cta">
      <a class="l-signin" href="/login">Sign in</a>
      <a class="btn btn-primary" href="/#pricing">Get it for $${PRICE}</a>
    </div>
  </div>
</header>`;
}

// Stylized CSS-only mock of the guided flow — clearly labelled as an
// illustration. Never presented as a screenshot or real data.
function flowMock() {
  return `<div class="mock" aria-label="Illustration of the EIN Launch Pad guided flow">
  <div class="mock-bar">
    <span class="mock-dot"></span><span class="mock-dot"></span><span class="mock-dot"></span>
    <span class="mock-bar-title">EIN Launch Pad — Your application</span>
  </div>
  <div class="mock-body">
    <div class="mock-cards">
      <div class="mock-card"><span class="mock-k">Step 1</span><span class="mock-v mock-green">Entity ✓</span></div>
      <div class="mock-card"><span class="mock-k">Step 2</span><span class="mock-v mock-green">Eligible ✓</span></div>
      <div class="mock-card"><span class="mock-k">Step 3</span><span class="mock-v">Form SS-4</span></div>
      <div class="mock-card"><span class="mock-k">Step 4</span><span class="mock-v">Review</span></div>
    </div>
    <div class="mock-cols">
      <div class="mock-panel">
        <span class="mock-k">Form SS-4 · Draft</span>
        <div class="mock-row"><span>Legal name</span><b>Northwind Logistics LLC</b></div>
        <div class="mock-row"><span>Entity type</span><b>LLC</b></div>
        <div class="mock-row"><span>Responsible party</span><b>A. Rivera</b></div>
        <div class="mock-row"><span>SSN / ITIN</span><b>•••-••-6789</b></div>
      </div>
      <div class="mock-panel">
        <span class="mock-k">Eligibility checklist</span>
        <div class="mock-row"><span>U.S. mailing address</span><b class="mock-green">✓</b></div>
        <div class="mock-row"><span>SSN or ITIN</span><b class="mock-green">✓</b></div>
        <div class="mock-row"><span>U.S. business</span><b class="mock-green">✓</b></div>
        <div class="mock-row"><span>New EIN</span><b class="mock-green">✓</b></div>
      </div>
    </div>
  </div>
  <p class="mock-caption">Illustration — stylized mock-up, not a screenshot or real data.</p>
</div>`;
}

function hero() {
  return `<section class="l-hero">
  <div class="l-wrap">
    <p class="l-eyebrow">For new business owners</p>
    <h1>Get your EIN application ready in about 3 minutes.</h1>
    <p class="l-sub">EIN Launch Pad walks you through IRS Form SS-4 step by step — entity selection, eligibility checklist, and a guided draft you file with the IRS yourself. No wrestling with IRS paperwork alone.</p>
    <div class="l-hero-cta">
      <a class="btn btn-primary l-cta-big" href="/billing/checkout">Get EIN Launch Pad — $${PRICE}</a>
      <p class="muted small">One-time payment. Yours forever. No subscription.</p>
    </div>
    ${flowMock()}
  </div>
</section>`;
}

const FEATURES = [
  ['Guided Form SS-4 walkthrough', 'Every field of the EIN application explained in plain language as you fill it in — legal name, mailing address, responsible party, business activity, and more.'],
  ['Tax entity selection', 'Pick LLC, Corporation, Partnership, Sole Proprietorship, or Nonprofit. Your choice pre-fills the rest of the application.'],
  ['IRS eligibility checklist', 'Confirm the five basics the IRS requires before you start, so you don\u2019t waste time on an application that can\u2019t go through.'],
  ['Your draft, saved as you go', 'Your progress is saved to your private account. Come back any time and pick up where you left off.'],
  ['SS-4 style review', 'A clean review page styled like the IRS form shows everything you entered — masked where it counts — ready for you to file.'],
  ['Private — your data is yours', 'Your application lives in your own account on your own hosting. No trackers, no data resale. Your business details stay yours.'],
];

function features() {
  const cards = FEATURES.map(([t, d]) => `<div class="card l-feature"><h3>${esc(t)}</h3><p class="muted">${esc(d)}</p></div>`).join('\n');
  return `<section class="l-section" id="features">
  <div class="l-wrap">
    <h2>Everything you need to prepare your EIN application</h2>
    <p class="muted l-lead">This app prepares your draft — it does not file with the IRS or issue EINs. You submit your finished application to the IRS yourself.</p>
    <div class="l-grid">${cards}</div>
  </div>
</section>`;
}

function howItWorks() {
  return `<section class="l-section l-alt" id="how">
  <div class="l-wrap">
    <h2>How it works</h2>
    <div class="l-steps">
      <div class="l-step"><span class="l-step-num">1</span><h3>Pay $${PRICE} once</h3><p class="muted">Secure checkout, 30-day refund promise.</p></div>
      <div class="l-step"><span class="l-step-num">2</span><h3>Create your account</h3><p class="muted">Your email and password — you're signed straight in.</p></div>
      <div class="l-step"><span class="l-step-num">3</span><h3>Finish in ~3 minutes</h3><p class="muted">Entity, eligibility, guided form, review. Then file your draft with the IRS yourself.</p></div>
    </div>
  </div>
</section>`;
}

function pricing() {
  return `<section class="l-section" id="pricing">
  <div class="l-wrap">
    <h2>Simple pricing</h2>
    <div class="l-price-card card">
      <p class="l-price-name">EIN Launch Pad</p>
      <p class="l-price">$${PRICE}<span class="muted"> one-time</span></p>
      <ul class="l-includes">
        <li>Lifetime access — pay once, use it forever</li>
        <li>Guided Form SS-4 walkthrough</li>
        <li>Entity selection &amp; eligibility checklist</li>
        <li>Private draft saved to your account</li>
        <li>No subscription, no per-filing fees, no upsells</li>
        <li>30-day money-back promise</li>
      </ul>
      <a class="btn btn-primary l-cta-big" href="/billing/checkout">Get it for $${PRICE}</a>
      <p class="muted small">Secure payment. No subscription.</p>
    </div>
  </div>
</section>`;
}

const FAQ = [
  ['Is it really one-time?',
    `Yes. You pay $${PRICE} once and get lifetime access to EIN Launch Pad. There is no subscription, no renewal, and no per-filing fee.`],
  ['Does this file my EIN with the IRS for me?',
    'No. EIN Launch Pad prepares your application draft — entity selection, eligibility check, and a guided Form SS-4. You submit the finished application to the IRS yourself. The IRS issues EINs; no private app can do that for you.'],
  ['Does it guarantee I\u2019ll get an EIN?',
    'No. Whether the IRS issues your EIN is the IRS\u2019s decision. What this does is make sure your application is complete and correct before you submit it.'],
  ['Do you see my data?',
    'No. Your application lives in your own account against your own database. We have no backdoor and no analytics pipeline — your business details stay yours.'],
  ['Can I get a refund?',
    `Yes — within 30 days of purchase, no questions asked. After you buy, you create your account right away; if it\u2019s not for you, we\u2019ll refund the $${PRICE}.`],
  ['I paid but closed the tab before creating my account — what now?',
    'No problem. Visit the claim page, enter the email you paid with, and you\u2019ll get a link to create your account.'],
];

function faq() {
  const items = FAQ.map(([q, a], i) => `<details class="l-faq-item"${i === 0 ? ' open' : ''}>
      <summary>${esc(q)}</summary>
      <p class="muted">${i === 5 ? `No problem. Visit <a href="/billing/claim">the claim page</a>, enter the email you paid with, and you\u2019ll get a link to create your account.` : esc(a)}</p>
    </details>`).join('\n');
  return `<section class="l-section l-alt" id="faq">
  <div class="l-wrap">
    <h2>Frequently asked questions</h2>
    <div class="l-faq">${items}</div>
  </div>
</section>`;
}

function footer() {
  return `<footer class="l-footer">
  <div class="l-wrap l-footer-inner">
    <span class="l-logo">EIN Launch Pad</span>
    <span class="muted small">Pay once. Prepare your EIN application. File it yourself.</span>
    <a class="muted small" href="/login">Sign in</a>
  </div>
</footer>`;
}

function landingPage() {
  return layout({
    title: 'EIN Launch Pad — Prepare your IRS EIN application in ~3 minutes',
    body: nav() + hero() + features() + howItWorks() + pricing() + faq() + footer(),
  });
}

// Generic full-page billing layout: full HTML doc, shared base styles.
function billingPage({ title, heading, sub, body, error }) {
  return layout({
    title,
    body: `<div class="auth-body"><main class="auth-card">
      <h1>${esc(heading)}</h1>
      ${sub ? `<p class="muted">${esc(sub)}</p>` : ''}
      ${error ? `<p class="error">${esc(error)}</p>` : ''}
      ${body}
    </main></div>`,
  });
}


// ================= views/app.js =================
// Templates for the logged-in EIN Launch Pad guided flow (/app/*).
// All functions return HTML strings. Every piece of user content goes
// through esc(). The SSN/ITIN is masked on the review page.
// IMPORTANT: this app prepares a draft — it does NOT file with the IRS
// and does NOT issue EINs. Never imply otherwise.
const escApp = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[c]));

const STEPS = [
  ['entity', 'Entity', '/app/entity'],
  ['checklist', 'Eligibility', '/app/checklist'],
  ['form', 'Form SS-4', '/app/form'],
  ['review', 'Review', '/app/review'],
];

function maskSsn(v) {
  const digits = String(v || '').replace(/\D/g, '');
  if (!digits) return '—';
  const last4 = digits.slice(-4).padStart(4, '•');
  return `•••-••-${last4}`;
}

function appLayout(title, user, active, status, content) {
  const links = STEPS.map(([key, label, href]) => {
    const done = status[key];
    const cls = ['step-link'];
    if (active === key) cls.push('active');
    if (done) cls.push('done');
    return `<a href="${href}" class="${cls.join(' ')}">${done ? '✓ ' : ''}${label}</a>`;
  }).join('');
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} — EIN Launch Pad</title>
<style>/* style.css (inlined for single-file deploy) */
/* Shared base styles. Feature CSS lives in public/app.css (dashboard)
   and public/landing.css (sales site) — do not put feature styles here. */
:root {
  --bg: #0f1420;
  --bg-soft: #161d2e;
  --card: #1b2338;
  --border: #2a3450;
  --text: #eef2ff;
  --muted: #9aa6c4;
  --accent: #4f7cff;
  --accent-hover: #3d68f0;
  --green: #34d399;
  --red: #f87171;
  --radius: 12px;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  line-height: 1.5;
}
a { color: var(--accent); }
.muted { color: var(--muted); }
.small { font-size: 0.85rem; }
.error {
  background: rgba(248,113,113,.12); border: 1px solid var(--red);
  color: var(--red); padding: 0.6rem 0.9rem; border-radius: 8px;
}
.btn {
  display: inline-block; border: 0; cursor: pointer; border-radius: 8px;
  padding: 0.7rem 1.4rem; font-size: 1rem; font-weight: 600; text-decoration: none;
}
.btn-primary { background: var(--accent); color: #fff; }
.btn-primary:hover { background: var(--accent-hover); }
.btn-ghost { background: transparent; color: var(--text); border: 1px solid var(--border); }
input, select, textarea {
  width: 100%; padding: 0.65rem 0.8rem; margin: 0.25rem 0 0.9rem;
  background: var(--bg-soft); border: 1px solid var(--border); color: var(--text);
  border-radius: 8px; font-size: 1rem;
}
label { display: block; font-size: 0.9rem; color: var(--muted); }
.auth-body { display: flex; min-height: 100vh; align-items: center; justify-content: center; padding: 1rem; }
.auth-card {
  background: var(--card); border: 1px solid var(--border); border-radius: var(--radius);
  padding: 2rem; width: 100%; max-width: 400px;
}
.auth-card h1 { margin: 0 0 0.25rem; font-size: 1.4rem; }
.card {
  background: var(--card); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 1.25rem;
}
table { width: 100%; border-collapse: collapse; font-size: 0.95rem; }
th, td { text-align: left; padding: 0.6rem 0.5rem; border-bottom: 1px solid var(--border); }
th { color: var(--muted); font-weight: 600; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.04em; }
.empty { text-align: center; color: var(--muted); padding: 2.5rem 1rem; }
.empty p { margin: 0.4rem 0 1rem; }
</style>
<style>/* app.css (inlined for single-file deploy) */
/* Guided-flow styles for /app/*. Pairs with /style.css (shared base).
   Dark theme tokens come from style.css :root. */

/* ---------- layout ---------- */
.app-nav {
  position: sticky; top: 0; z-index: 50;
  background: rgba(15, 20, 32, 0.95);
  border-bottom: 1px solid var(--border);
  backdrop-filter: blur(6px);
}
.nav-inner {
  max-width: 1100px; margin: 0 auto; padding: 0.7rem 1rem;
  display: flex; align-items: center; gap: 1.25rem;
}
.nav-brand {
  font-weight: 700; font-size: 1.05rem; color: var(--text);
  text-decoration: none; white-space: nowrap;
}
.nav-links { display: flex; gap: 0.25rem; flex: 1; }
.nav-links a {
  color: var(--muted); text-decoration: none; font-size: 0.95rem;
  padding: 0.45rem 0.8rem; border-radius: 8px;
}
.nav-links a:hover { color: var(--text); background: var(--bg-soft); }
.nav-links a.active { color: var(--text); background: var(--bg-soft); font-weight: 600; }
.nav-links a.done { color: var(--green); }
.nav-links a.done.active { color: var(--text); }
.nav-user { display: flex; align-items: center; gap: 0.75rem; margin-left: auto; }
.nav-logout { margin: 0; }
.nav-email { max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

.app-main { max-width: 860px; margin: 0 auto; padding: 1.5rem 1rem 3rem; }
.page-title { margin: 0 0 0.4rem; font-size: 1.6rem; }
.page-sub { margin: 0 0 1.5rem; }

/* ---------- entity cards ---------- */
.entity-grid {
  display: grid; gap: 0.75rem;
  grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
  margin-bottom: 1.5rem;
}
.entity-card {
  display: block; cursor: pointer;
  background: var(--bg-soft); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 1.1rem 1.2rem;
  transition: border-color 0.15s;
}
.entity-card:hover { border-color: var(--accent); }
.entity-card.selected { border-color: var(--accent); box-shadow: 0 0 0 1px var(--accent); }
.entity-card input[type="radio"] {
  width: auto; margin: 0 0 0.6rem; accent-color: var(--accent);
}
.entity-name { display: block; font-weight: 700; color: var(--text); font-size: 1.02rem; }
.entity-desc { display: block; margin-top: 0.25rem; }

/* ---------- checklist ---------- */
.check-list { display: flex; flex-direction: column; gap: 0.6rem; margin-bottom: 1.5rem; }
.check-row {
  display: flex; align-items: flex-start; gap: 0.8rem; cursor: pointer;
  background: var(--bg-soft); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 0.9rem 1.1rem; color: var(--text);
}
.check-row input[type="checkbox"] {
  width: 1.25rem; height: 1.25rem; margin: 0.15rem 0 0; flex-shrink: 0;
  accent-color: var(--accent);
}
.check-row span { font-size: 1rem; }

/* ---------- form ---------- */
.form-grid { display: grid; gap: 0 1rem; }
.form-grid label { margin-bottom: 0.2rem; }
.form-actions {
  display: flex; gap: 0.75rem; margin-top: 1.25rem; flex-wrap: wrap;
  align-items: center;
}
.form-actions .btn-primary { margin-left: auto; }

/* ---------- review ---------- */
.draft-label {
  text-transform: uppercase; letter-spacing: 0.06em; font-weight: 700;
  margin: 0 0 1rem;
}
.review-list { border-top: 1px solid var(--border); }
.review-row {
  display: flex; justify-content: space-between; gap: 1rem;
  padding: 0.65rem 0; border-bottom: 1px solid var(--border); font-size: 0.98rem;
}
.review-row span { flex-shrink: 0; }
.review-row b { font-weight: 600; text-align: right; word-break: break-word; }
.draft-note { margin: 1.25rem 0 0; }

/* ---------- buttons ---------- */
.btn-sm { padding: 0.4rem 0.85rem; font-size: 0.85rem; }

/* ---------- responsive ---------- */
@media (max-width: 640px) {
  .nav-inner { flex-wrap: wrap; gap: 0.6rem; }
  .nav-links { order: 3; width: 100%; overflow-x: auto; }
  .nav-email { display: none; }
  .form-actions .btn-primary { margin-left: 0; width: 100%; }
  .form-actions .btn-ghost { width: 100%; text-align: center; }
}
</style>
</head>
<body>
<header class="app-nav">
  <div class="nav-inner">
    <a class="nav-brand" href="/app">EIN Launch Pad</a>
    <nav class="nav-links">${links}</nav>
    <div class="nav-user">
      <span class="muted small nav-email">${esc(user.email)}</span>
      <form method="POST" action="/logout" class="nav-logout">
        <button type="submit" class="btn btn-ghost btn-sm">Sign out</button>
      </form>
    </div>
  </div>
</header>
<main class="app-main">
${content}
</main>
</body>
</html>`;
}

function pageHead(title, sub) {
  return `<h1 class="page-title">${esc(title)}</h1>
  ${sub ? `<p class="muted page-sub">${esc(sub)}</p>` : ''}`;
}

function entityPage(user, app, entities, status, error) {
  const cards = entities.map(([value, label, desc]) => `
    <label class="entity-card${app.entity_type === value ? ' selected' : ''}">
      <input type="radio" name="entity_type" value="${esc(value)}"${app.entity_type === value ? ' checked' : ''} required>
      <span class="entity-name">${esc(label)}</span>
      <span class="entity-desc muted small">${esc(desc)}</span>
    </label>`).join('');
  return appLayout('Choose your tax entity', user, 'entity', status, `
  ${pageHead('Choose your tax entity', 'Selecting an entity starts your application with it pre-filled. You can change it later.')}
  ${error ? `<p class="error">${esc(error)}</p>` : ''}
  <form method="POST" action="/app/entity" class="card">
    <div class="entity-grid">${cards}</div>
    <button type="submit" class="btn btn-primary">Continue to eligibility</button>
  </form>`);
}

function checklistPage(user, app, items, status, error) {
  let checked = {};
  try { checked = JSON.parse(app.eligibility_json || '{}'); } catch (e) { checked = {}; }
  const boxes = items.map(([key, label]) => `
    <label class="check-row">
      <input type="checkbox" name="${esc(key)}"${checked[key] ? ' checked' : ''}>
      <span>${esc(label)}</span>
    </label>`).join('');
  return appLayout('IRS eligibility checklist', user, 'checklist', status, `
  ${pageHead('IRS eligibility checklist', 'Confirm you meet the basics before you begin. All five must be true to continue.')}
  ${error ? `<p class="error">${esc(error)}</p>` : ''}
  <form method="POST" action="/app/checklist" class="card">
    <div class="check-list">${boxes}</div>
    <div class="form-actions">
      <a class="btn btn-ghost" href="/app/entity">Back</a>
      <button type="submit" class="btn btn-primary">Continue to Form SS-4</button>
    </div>
  </form>`);
}

function textField(name, label, opts = {}) {
  const { required = false, type = 'text', value = '', placeholder = '', rows } = opts;
  const attrs = [
    `type="${type}"`, `name="${esc(name)}"`,
    required ? 'required' : '',
    value !== '' ? `value="${esc(value)}"` : '',
    placeholder ? `placeholder="${esc(placeholder)}"` : '',
  ].filter(Boolean).join(' ');
  if (rows) {
    return `<label>${esc(label)}${required ? ' *' : ''}<textarea name="${esc(name)}" rows="${rows}"${required ? ' required' : ''}${placeholder ? ` placeholder="${esc(placeholder)}"` : ''}>${esc(value)}</textarea></label>`;
  }
  return `<label>${esc(label)}${required ? ' *' : ''}<input ${attrs}></label>`;
}

function selectField(name, label, options, selected = '') {
  const opts = options.map(([v, t]) =>
    `<option value="${esc(v)}"${v === selected ? ' selected' : ''}>${esc(t)}</option>`).join('');
  return `<label>${esc(label)}<select name="${esc(name)}">${opts}</select></label>`;
}

function formPage(user, app, entityValues, status, error) {
  const entityOpts = [['', '— keep current —']].concat(entityValues.map((v) => [v, v]));
  return appLayout('Form SS-4 — your information', user, 'form', status, `
  ${pageHead('Form SS-4 — your information', 'Fill once. Your progress saves automatically when you continue.')}
  ${error ? `<p class="error">${esc(error)}</p>` : ''}
  <form method="POST" action="/app/form" class="card form-grid">
    ${textField('legal_name', 'Legal name of entity', { required: true, value: app.legal_name, placeholder: 'e.g. Northwind Logistics LLC' })}
    ${textField('trade_name', 'Trade name / DBA (if different)', { value: app.trade_name, placeholder: 'e.g. Northwind' })}
    ${selectField('entity_type', 'Entity type', entityOpts, '')}
    ${textField('mailing_address', 'Mailing address', { required: true, rows: 3, value: app.mailing_address, placeholder: 'Street, City, State ZIP' })}
    ${textField('responsible_party', 'Responsible party (name)', { required: true, value: app.responsible_party, placeholder: 'e.g. A. Rivera' })}
    ${textField('ssn_itin', 'SSN / ITIN of responsible party', { required: true, value: app.ssn_itin, placeholder: '•••-••-1234' })}
    ${textField('business_activity', 'Principal business activity', { value: app.business_activity, placeholder: 'e.g. Freight trucking' })}
    ${textField('employees_first_year', 'Employees expected (first year)', { value: app.employees_first_year, placeholder: 'e.g. 4' })}
    ${textField('fiscal_year_end', 'Fiscal year end', { value: app.fiscal_year_end, placeholder: 'e.g. 12-31' })}
    <div class="form-actions">
      <a class="btn btn-ghost" href="/app/checklist">Back</a>
      <button type="submit" class="btn btn-primary">Continue to review</button>
    </div>
  </form>`);
}

function reviewRow(label, value) {
  return `<div class="review-row"><span class="muted">${esc(label)}</span><b>${esc(value || '—')}</b></div>`;
}

function reviewPage(user, app, status) {
  return appLayout('Review — IRS SS-4 Draft', user, 'review', status, `
  ${pageHead('IRS SS-4 Draft', 'This is your preparation draft. EIN Launch Pad does not file with the IRS or issue EINs — you submit this information to the IRS yourself.')}
  <div class="card">
    <p class="draft-label muted small">IRS Replica · Draft</p>
    <div class="review-list">
      ${reviewRow('Legal name of entity', app.legal_name)}
      ${reviewRow('Trade name / DBA', app.trade_name)}
      ${reviewRow('Entity type', app.entity_type)}
      ${reviewRow('Mailing address', app.mailing_address)}
      ${reviewRow('Responsible party', app.responsible_party)}
      ${reviewRow('SSN / ITIN', maskSsn(app.ssn_itin))}
      ${reviewRow('Business activity', app.business_activity)}
      ${reviewRow('Employees (first year)', app.employees_first_year)}
      ${reviewRow('Fiscal year end', app.fiscal_year_end)}
    </div>
    <p class="muted small draft-note">Your SSN/ITIN is masked here. Keep this draft private — it contains sensitive information.</p>
    <div class="form-actions">
      <a class="btn btn-ghost" href="/app/form">Edit answers</a>
    </div>
  </div>`);
}


// ================= routes/billing.js =================
// Stripe billing for EIN Launch Pad: $13.99 one-time checkout.
// Mounted at /billing by src/server.js BEFORE the landing billingRouter.
// IMPORTANT: the webhook route is FIRST and uses express.raw() — no
// express.json() may run before it or the Stripe signature check breaks.

const billingRouter = express.Router();

const PRICE_CENTS = parseInt(process.env.PRICE_CENTS || '1399', 10) || 1399;
const APP_URL = (process.env.APP_URL || 'http://localhost:3000').replace(/\/$/, '');

const isPlaceholder = (v) => !v || String(v).includes('PASTE_YOUR');
const stripeConfigured = () => !isPlaceholder(process.env.STRIPE_SECRET_KEY);
const webhookConfigured = () => !isPlaceholder(process.env.STRIPE_WEBHOOK_SECRET);

function stripeClient() {
  // Lazily constructed so placeholder keys never get used.
  return require('stripe')(process.env.STRIPE_SECRET_KEY);
}

// ---------------------------------------------------------------- webhook
// FIRST route in this file. Raw body required for signature verification.
billingRouter.post('/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  if (!stripeConfigured() || !webhookConfigured()) {
    // Fail closed: never record anything without a verified signature.
    return res.status(400).send('webhook not configured');
  }
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripeClient().webhooks.constructEvent(
      req.body, sig, process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    return res.status(400).send(`webhook signature verification failed: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const email = session.customer_details?.email || session.customer_email || null;
    try {
      getDb().prepare(
        'INSERT OR IGNORE INTO pending_purchases (session_id, email, paid_at) VALUES (?,?,?)'
      ).run(session.id, email, new Date().toISOString().slice(0, 19).replace('T', ' '));
    } catch (dbErr) {
      // Don't leak internals; Stripe will retry the webhook anyway.
      return res.status(500).send('webhook processing error');
    }
  }
  return res.status(200).send('ok');
});

// Body parsers for all routes below (AFTER the raw webhook route).
billingRouter.use(express.urlencoded({ extended: false }));
billingRouter.use(express.json());

// --------------------------------------------------------------- checkout
billingRouter.get('/checkout', async (req, res) => {
  if (!stripeConfigured()) {
    return res.send(billingPage({
      title: 'Checkout — EIN Launch Pad',
      heading: "Payments aren't connected yet",
      sub: 'The store owner still needs to connect Stripe before this page can take payment. If you were sent here to buy, please check back shortly.',
      body: `<p><a class="btn btn-ghost" href="/#pricing">Back to pricing</a></p>`,
    }));
  }
  try {
    const session = await stripeClient().checkout.sessions.create({
      mode: 'payment',
      line_items: [{
        price_data: {
          currency: 'usd',
          unit_amount: PRICE_CENTS,
          product_data: { name: 'EIN Launch Pad — lifetime access' },
        },
        quantity: 1,
      }],
      success_url: `${APP_URL}/billing/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${APP_URL}/#pricing`,
    });
    return res.redirect(303, session.url);
  } catch (err) {
    return res.status(500).send(billingPage({
      title: 'Checkout — EIN Launch Pad',
      heading: 'Checkout failed',
      sub: 'Something went wrong creating your payment session. Please try again in a moment.',
      body: `<p><a class="btn btn-ghost" href="/#pricing">Back to pricing</a></p>`,
    }));
  }
});

// ---------------------------------------------------------------- success
billingRouter.get('/success', async (req, res) => {
  const sessionId = String(req.query.session_id || '');
  if (!sessionId || !stripeConfigured()) {
    return res.status(400).send(billingPage({
      title: 'Create your account — EIN Launch Pad',
      heading: 'Payment could not be verified',
      sub: 'We couldn\u2019t verify a completed payment for that link. If you paid and closed the tab, you can still claim your access.',
      body: `<p><a class="btn btn-primary" href="/billing/claim">Claim your purchase</a></p>
             <p><a class="muted small" href="/#pricing">Back to pricing</a></p>`,
    }));
  }
  let session;
  try {
    session = await stripeClient().checkout.sessions.retrieve(sessionId);
  } catch (err) {
    return res.status(400).send(billingPage({
      title: 'Create your account — EIN Launch Pad',
      heading: 'Payment could not be verified',
      sub: 'That payment link doesn\u2019t look valid. If you paid and closed the tab, you can still claim your access.',
      body: `<p><a class="btn btn-primary" href="/billing/claim">Claim your purchase</a></p>`,
    }));
  }
  if (session.payment_status !== 'paid') {
    return res.status(402).send(billingPage({
      title: 'Create your account — EIN Launch Pad',
      heading: 'Payment not completed',
      sub: 'Your payment hasn\u2019t gone through yet. If you already paid, check your email or claim your purchase below.',
      body: `<p><a class="btn btn-primary" href="/billing/claim">Claim your purchase</a></p>
             <p><a class="muted small" href="/billing/checkout">Try checkout again</a></p>`,
    }));
  }
  const email = session.customer_details?.email || session.customer_email || '';
  res.send(billingPage({
    title: 'Create your account — EIN Launch Pad',
    heading: 'Payment received — create your account',
    sub: 'You\u2019re one step away. Choose a password and you\u2019ll be signed straight into your EIN application.',
    body: `<form method="POST" action="/billing/activate">
      <input type="hidden" name="session_id" value="${esc(sessionId)}">
      <label>Email<input type="email" name="email" required autocomplete="email" value="${esc(email)}"></label>
      <label>Password (8+ characters)<input type="password" name="password" required minlength="8" autocomplete="new-password"></label>
      <label>Confirm password<input type="password" name="confirm" required minlength="8" autocomplete="new-password"></label>
      <button type="submit" class="btn btn-primary">Create account &amp; start my application</button>
    </form>`,
  }));
});

// ---------------------------------------------------------------- activate
billingRouter.post('/activate', async (req, res) => {
  const sessionId = String(req.body.session_id || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const confirm = String(req.body.confirm || '');

  const fail = (msg) => res.status(400).send(billingPage({
    title: 'Create your account — EIN Launch Pad',
    heading: 'Couldn\u2019t create your account',
    sub: msg,
    body: `<p><a class="btn btn-primary" href="/billing/claim">Claim your purchase</a></p>
           <p><a class="muted small" href="/login">Already have an account? Sign in</a></p>`,
  }));

  if (!sessionId || !stripeConfigured()) return fail('That payment link isn\u2019t valid.');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return fail('Please enter a valid email address.');
  if (password.length < 8) return fail('Password must be at least 8 characters.');
  if (password !== confirm) return fail('The two passwords don\u2019t match.');

  // Re-verify with Stripe: the session must exist and be paid.
  let session;
  try {
    session = await stripeClient().checkout.sessions.retrieve(sessionId);
  } catch (err) {
    return fail('We couldn\u2019t verify that payment with Stripe. Try the claim page.');
  }
  if (session.payment_status !== 'paid') return fail('That payment hasn\u2019t completed yet.');

  const db = getDb();
  const claimed = db.prepare('SELECT id FROM users WHERE stripe_session_id = ?').get(sessionId);
  if (claimed) {
    // Already claimed — account exists, just send them to sign in.
    return res.redirect('/login');
  }
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) {
    return fail('That email is already registered. Sign in instead.');
  }

  const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
  const info = db.prepare(
    'INSERT INTO users (email, password_hash, stripe_customer_id, stripe_session_id, paid_at) VALUES (?,?,?,?,?)'
  ).run(
    email,
    await hashPassword(password),
    typeof session.customer === 'string' ? session.customer : null,
    sessionId,
    now
  );
  const { token, expires } = createSession(Number(info.lastInsertRowid));
  setSessionCookie(req, res, token, expires);
  res.redirect('/app');
});

// ------------------------------------------------------------------- claim
// Buyer paid but closed the tab before creating their account.
billingRouter.get('/claim', (req, res) => {
  res.send(billingPage({
    title: 'Claim your purchase — EIN Launch Pad',
    heading: 'Claim your purchase',
    sub: 'Paid but never created your account? Enter the email you paid with and we\u2019ll find your purchase.',
    body: `<form method="POST" action="/billing/claim">
      <label>Email you paid with<input type="email" name="email" required autocomplete="email"></label>
      <button type="submit" class="btn btn-primary">Find my purchase</button>
    </form>`,
  }));
});

billingRouter.post('/claim', (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const rows = email
    ? getDb().prepare(`
        SELECT pp.session_id AS sessionId, pp.paid_at AS paidAt
        FROM pending_purchases pp
        LEFT JOIN users u ON u.stripe_session_id = pp.session_id
        WHERE LOWER(pp.email) = LOWER(?) AND u.id IS NULL
        ORDER BY pp.paid_at DESC
      `).all(email)
    : [];
  if (!rows.length) {
    return res.status(404).send(billingPage({
      title: 'Claim your purchase — EIN Launch Pad',
      heading: 'No unclaimed purchase found',
      sub: `We couldn\u2019t find a completed payment for ${esc(email || 'that address')} that hasn\u2019t been claimed yet. Double-check the email you paid with — or buy below.`,
      body: `<form method="POST" action="/billing/claim">
        <label>Email you paid with<input type="email" name="email" required autocomplete="email" value="${esc(email)}"></label>
        <button type="submit" class="btn btn-primary">Find my purchase</button>
      </form>
      <p><a class="muted small" href="/#pricing">Get EIN Launch Pad — $13.99 one-time</a></p>`,
    }));
  }
  const buttons = rows.map((r) => `<p><a class="btn btn-primary" href="/billing/success?session_id=${esc(r.sessionId)}">Create my account (paid ${esc(r.paidAt)})</a></p>`).join('');
  res.send(billingPage({
    title: 'Claim your purchase — EIN Launch Pad',
    heading: 'Found your purchase',
    sub: 'Click below to finish creating your account and start your application.',
    body: buttons,
  }));
});

// ================= routes/landing.js =================
// Public sales site: GET / -> the EIN Launch Pad landing page.

const landingRouter = express.Router();

landingRouter.get('/', (req, res) => {
  res.send(landingPage());
});

// ================= routes/app.js =================
// EIN Launch Pad guided application router, mounted at /app in src/server.js.
// Pages are server-rendered (see src/views/app.js). Progress is saved to
// the ein_applications table, one row per user.
//
// SECURITY: every database query filters by user_id = req.user.id.
// Never trust a client-supplied user id.

const appRouter = express.Router();
appRouter.use(express.urlencoded({ extended: false }));
appRouter.use(express.json());
appRouter.use(requireAuth);

const ENTITIES = [
  ['LLC', 'Limited Liability Company', 'Flexible structure — most small businesses start here.'],
  ['Corporation', 'Corporation (C-corp / S-corp)', 'Separate legal entity; S-corp election is made separately with the IRS.'],
  ['Partnership', 'Partnership', 'Two or more people sharing ownership and profits.'],
  ['Sole Proprietorship', 'Sole Proprietorship', 'You alone own the business; simplest structure.'],
  ['Nonprofit', 'Nonprofit Organization', 'Charitable, religious, or educational purposes.'],
];
const ENTITY_VALUES = ENTITIES.map(([v]) => v);

const ELIGIBILITY = [
  ['us_address', 'You have a valid U.S. mailing address'],
  ['ssn_itin', 'You hold an SSN or ITIN as the responsible party'],
  ['us_business', 'Your principal business is located in the U.S.'],
  ['new_ein', 'This is a new EIN (not a reinstatement or reissue)'],
  ['owner_officer', 'You are the owner, partner, or corporate officer'],
];

function str(v, opts = {}) {
  const { required = false, max = 500 } = opts;
  const s = String(v ?? '').trim();
  if (required && !s) return null;
  return s.slice(0, max);
}

function parseEligibility(body) {
  // Every box must be checked to proceed.
  const out = {};
  for (const [key] of ELIGIBILITY) {
    out[key] = body[key] === 'on' || body[key] === 'true' ? true : false;
    if (!out[key]) return null;
  }
  return out;
}

function stepStatus(app) {
  const entity = !!app.entity_type;
  let elig = {};
  try { elig = JSON.parse(app.eligibility_json || '{}'); } catch (e) { elig = {}; }
  const checklist = ELIGIBILITY.every(([key]) => elig[key] === true);
  const form = !!(app.legal_name && app.mailing_address && app.responsible_party && app.ssn_itin);
  return { entity, checklist, form };
}

// ---------- pages ----------
appRouter.get('/', (req, res) => {
  const app = getApplication(req.user.id);
  const s = stepStatus(app);
  if (!s.entity) return res.redirect('/app/entity');
  if (!s.checklist) return res.redirect('/app/checklist');
  if (!s.form) return res.redirect('/app/form');
  return res.redirect('/app/review');
});

appRouter.get('/entity', (req, res) => {
  const app = getApplication(req.user.id);
  res.send(entityPage(req.user, app, ENTITIES, stepStatus(app)));
});

appRouter.post('/entity', (req, res) => {
  const entityType = str(req.body.entity_type);
  if (!ENTITY_VALUES.includes(entityType)) {
    const app = getApplication(req.user.id);
    return res.status(400).send(
      entityPage(req.user, app, ENTITIES, stepStatus(app), 'Please choose one of the entity types.')
    );
  }
  saveApplication(req.user.id, { entity_type: entityType });
  res.redirect('/app/checklist');
});

appRouter.get('/checklist', (req, res) => {
  const app = getApplication(req.user.id);
  const s = stepStatus(app);
  if (!s.entity) return res.redirect('/app/entity');
  res.send(checklistPage(req.user, app, ELIGIBILITY, s));
});

appRouter.post('/checklist', (req, res) => {
  const elig = parseEligibility(req.body || {});
  const app = getApplication(req.user.id);
  const s = stepStatus(app);
  if (!elig) {
    return res.status(400).send(
      checklistPage(req.user, app, ELIGIBILITY, s,
        'All five items must be confirmed before you continue. If any item isn\u2019t true for you, the IRS online EIN application isn\u2019t the right path — check with a tax professional.')
    );
  }
  saveApplication(req.user.id, { eligibility_json: JSON.stringify(elig) });
  res.redirect('/app/form');
});

appRouter.get('/form', (req, res) => {
  const app = getApplication(req.user.id);
  const s = stepStatus(app);
  if (!s.entity) return res.redirect('/app/entity');
  if (!s.checklist) return res.redirect('/app/checklist');
  res.send(formPage(req.user, app, ENTITY_VALUES, s));
});

appRouter.post('/form', (req, res) => {
  const app = getApplication(req.user.id);
  const s = stepStatus(app);

  const entityType = str(req.body.entity_type);
  const legalName = str(req.body.legal_name, { required: true, max: 200 });
  const tradeName = str(req.body.trade_name, { max: 200 });
  const mailingAddress = str(req.body.mailing_address, { required: true, max: 500 });
  const responsibleParty = str(req.body.responsible_party, { required: true, max: 200 });
  const ssnItin = str(req.body.ssn_itin, { required: true, max: 20 });
  const businessActivity = str(req.body.business_activity, { max: 200 });
  const employees = str(req.body.employees_first_year, { max: 20 });
  const fiscalYearEnd = str(req.body.fiscal_year_end, { max: 20 });

  const problems = [];
  if (entityType !== '' && !ENTITY_VALUES.includes(entityType)) problems.push('entity type');
  if (legalName === null) problems.push('legal name of entity');
  if (mailingAddress === null) problems.push('mailing address');
  if (responsibleParty === null) problems.push('responsible party');
  if (ssnItin === null) problems.push('SSN / ITIN');

  if (problems.length) {
    return res.status(400).send(
      formPage(req.user, app, ENTITY_VALUES, s,
        `Please complete the required fields: ${problems.join(', ')}.`)
    );
  }

  saveApplication(req.user.id, {
    entity_type: entityType || app.entity_type,
    legal_name: legalName,
    trade_name: tradeName,
    mailing_address: mailingAddress,
    responsible_party: responsibleParty,
    ssn_itin: ssnItin,
    business_activity: businessActivity,
    employees_first_year: employees,
    fiscal_year_end: fiscalYearEnd,
  });
  res.redirect('/app/review');
});

appRouter.get('/review', (req, res) => {
  const app = getApplication(req.user.id);
  const s = stepStatus(app);
  if (!s.entity) return res.redirect('/app/entity');
  if (!s.checklist) return res.redirect('/app/checklist');
  if (!s.form) return res.redirect('/app/form');
  res.send(reviewPage(req.user, app, s));
});

// ================= server.js =================
// EIN Launch Pad — standalone server (NOT Base44).
// Routers are owned by feature:
//   src/routes/landing.js  -> public sales site (GET /)
//   src/routes/billing.js  -> Stripe $13.99 one-time checkout + webhook
//   src/routes/app.js      -> logged-in guided EIN flow (/app/*)
// Auth pages (/login, /logout) live here since they are shared.
require('dotenv').config();


const app = express();
const PORT = process.env.PORT || 3000;

getDb(); // create schema on boot
app.use(sessionMiddleware);
// static CSS inlined above; no public/ dir needed

// Billing FIRST: its webhook route uses express.raw() and must see the
// raw body before any JSON parser touches it.
app.use('/billing', billingRouter);
app.use('/', landingRouter);
app.use('/app', appRouter);

// ---- shared auth pages ----
const escServer = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[c]));

function loginPage(error) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in — EIN Launch Pad</title>
<style>/* style.css (inlined for single-file deploy) */
/* Shared base styles. Feature CSS lives in public/app.css (dashboard)
   and public/landing.css (sales site) — do not put feature styles here. */
:root {
  --bg: #0f1420;
  --bg-soft: #161d2e;
  --card: #1b2338;
  --border: #2a3450;
  --text: #eef2ff;
  --muted: #9aa6c4;
  --accent: #4f7cff;
  --accent-hover: #3d68f0;
  --green: #34d399;
  --red: #f87171;
  --radius: 12px;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  line-height: 1.5;
}
a { color: var(--accent); }
.muted { color: var(--muted); }
.small { font-size: 0.85rem; }
.error {
  background: rgba(248,113,113,.12); border: 1px solid var(--red);
  color: var(--red); padding: 0.6rem 0.9rem; border-radius: 8px;
}
.btn {
  display: inline-block; border: 0; cursor: pointer; border-radius: 8px;
  padding: 0.7rem 1.4rem; font-size: 1rem; font-weight: 600; text-decoration: none;
}
.btn-primary { background: var(--accent); color: #fff; }
.btn-primary:hover { background: var(--accent-hover); }
.btn-ghost { background: transparent; color: var(--text); border: 1px solid var(--border); }
input, select, textarea {
  width: 100%; padding: 0.65rem 0.8rem; margin: 0.25rem 0 0.9rem;
  background: var(--bg-soft); border: 1px solid var(--border); color: var(--text);
  border-radius: 8px; font-size: 1rem;
}
label { display: block; font-size: 0.9rem; color: var(--muted); }
.auth-body { display: flex; min-height: 100vh; align-items: center; justify-content: center; padding: 1rem; }
.auth-card {
  background: var(--card); border: 1px solid var(--border); border-radius: var(--radius);
  padding: 2rem; width: 100%; max-width: 400px;
}
.auth-card h1 { margin: 0 0 0.25rem; font-size: 1.4rem; }
.card {
  background: var(--card); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 1.25rem;
}
table { width: 100%; border-collapse: collapse; font-size: 0.95rem; }
th, td { text-align: left; padding: 0.6rem 0.5rem; border-bottom: 1px solid var(--border); }
th { color: var(--muted); font-weight: 600; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.04em; }
.empty { text-align: center; color: var(--muted); padding: 2.5rem 1rem; }
.empty p { margin: 0.4rem 0 1rem; }
</style></head>
<body class="auth-body"><main class="auth-card">
<h1>EIN Launch Pad</h1><p class="muted">Sign in to your application</p>
${error ? `<p class="error">${esc(error)}</p>` : ''}
<form method="POST" action="/login">
<label>Email<input type="email" name="email" required autocomplete="email"></label>
<label>Password<input type="password" name="password" required autocomplete="current-password"></label>
<button type="submit" class="btn btn-primary">Sign in</button>
</form>
<p class="muted small">Don't have access yet? <a href="/#pricing">Get EIN Launch Pad — $13.99 one-time</a></p>
</main></body></html>`;
}

app.get('/login', (req, res) => {
  if (req.user) return res.redirect('/app');
  res.send(loginPage(null));
});

app.post('/login', express.urlencoded({ extended: false }), async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const user = getDb().prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !(await verifyPassword(password, user.password_hash))) {
    return res.status(401).send(loginPage('Wrong email or password.'));
  }
  const { token, expires } = createSession(user.id);
  setSessionCookie(req, res, token, expires);
  res.redirect('/app');
});

app.post('/logout', requireAuth, (req, res) => {
  destroySession(getCookieToken(req));
  clearSessionCookie(res);
  res.redirect('/');
});

app.use((req, res) => res.status(404).send('Not found'));

app.listen(PORT, () => console.log(`EIN Launch Pad listening on port ${PORT}`));
