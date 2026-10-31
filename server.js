'use strict';
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const production = process.env.NODE_ENV === 'production';
const DATA_DIR = path.resolve(process.env.DATA_DIR || __dirname);
fs.mkdirSync(DATA_DIR, { recursive: true });
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  if (production) throw new Error('SESSION_SECRET must be set to a random value of at least 32 characters.');
  process.env.SESSION_SECRET = 'dev-only-change-this-session-secret-32chars';
  console.warn('WARNING: using development SESSION_SECRET. Set a private random value before deployment.');
}
if (production && (!process.env.ADMIN_PASSWORD || process.env.ADMIN_PASSWORD.length < 14)) {
  throw new Error('Set ADMIN_PASSWORD to a strong password (at least 14 characters).');
}
if (!production && !process.env.ADMIN_PASSWORD) console.warn('WARNING: set ADMIN_PASSWORD in .env before using the admin panel.');

const db = new Database(path.join(DATA_DIR, 'luavault.sqlite'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL,
  username_key TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS scripts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  game TEXT NOT NULL,
  key_type TEXT NOT NULL DEFAULT 'free',
  views INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  image TEXT NOT NULL DEFAULT '',
  code TEXT NOT NULL,
  author TEXT NOT NULL DEFAULT ''
);
`);

app.disable('x-powered-by');
if (production) app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '7mb' }));
app.use(session({
  name: 'lv.sid',
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: DATA_DIR }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'strict', secure: production, maxAge: 1000 * 60 * 60 * 24 * 7 }
}));
// Reject cross-origin state-changing requests. Same-origin front-end requests continue to work.
app.use('/api', (req, res, next) => {
  if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    const origin = req.get('origin');
    if (origin && origin !== `${req.protocol}://${req.get('host')}`) return res.status(403).json({ error: 'Cross-origin request blocked.' });
  }
  next();
});
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false });
const submitLimiter = rateLimit({ windowMs: 60 * 1000, limit: 3, standardHeaders: true, legacyHeaders: false });
const adminLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: true, legacyHeaders: false });
const userOnly = (req, res, next) => {
  if (!req.session.user) return res.status(401).json({ error: 'Log in required.' });
  const exists = db.prepare('SELECT 1 FROM users WHERE username = ?').get(req.session.user);
  if (!exists) return res.status(401).json({ error: 'Your account is no longer active. Log in again.' });
  next();
};
const adminOnly = (req, res, next) => req.session.admin ? next() : res.status(401).json({ error: 'Admin login required.' });

function regenerateSession(req) {
  return new Promise((resolve, reject) => req.session.regenerate(err => err ? reject(err) : resolve()));
}

function cleanScript(input, partial = false) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return null;
  const str = (v, n) => String(v ?? '').slice(0, n).trim();
  const out = {};
  if (!partial || 'title' in input) out.title = str(input.title, 60);
  if (!partial || 'game' in input) out.game = str(input.game, 40) || 'Universal';
  if (!partial || 'description' in input || 'desc' in input) out.description = str(input.description ?? input.desc, 200);
  if (!partial || 'code' in input) out.code = str(input.code, 5000);
  if (!partial || 'key_type' in input || 'key' in input) out.key_type = (input.key_type ?? input.key) === 'key' ? 'key' : 'free';
  if (!partial || 'image' in input || 'img' in input) {
    const image = String(input.image ?? input.img ?? '');
    out.image = /^data:image\/(png|jpeg|webp|gif);base64,[A-Za-z0-9+/=]+$/.test(image) && image.length <= 6_800_000 ? image : '';
  }
  if (!partial && (!out.title || !out.code)) return null;
  return out;
}
function scriptRow(row) {
  return { id: row.id, title: row.title, game: row.game, key: row.key_type, views: row.views,
    date: row.created_at, desc: row.description, img: row.image, code: row.code, author: row.author };
}
const allScripts = db.prepare('SELECT * FROM scripts ORDER BY created_at DESC');

app.get('/api/session', (req, res) => {
  if (req.session.user && !db.prepare('SELECT 1 FROM users WHERE username = ?').get(req.session.user)) delete req.session.user;
  res.json({ user: req.session.user || null, admin: !!req.session.admin });
});
app.post('/api/signup', authLimiter, async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '');
  if (username.length < 2 || username.length > 30 || /[\p{Extended_Pictographic}\p{Regional_Indicator}]/u.test(username)) return res.status(400).json({ error: 'Username must be 2–30 characters and contain no emojis.' });
  if (password.length < 8 || password.length > 128) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  const hash = await bcrypt.hash(password, 12);
  try {
    db.prepare('INSERT INTO users (username, username_key, password_hash, created_at) VALUES (?, ?, ?, ?)').run(username, username.toLowerCase(), hash, Date.now());
    await regenerateSession(req);
    req.session.user = username;
    res.status(201).json({ user: username });
  } catch { res.status(409).json({ error: 'That username is already taken.' }); }
});
app.post('/api/login', authLimiter, async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '');
  const user = db.prepare('SELECT * FROM users WHERE username_key = ?').get(username.toLowerCase());
  if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'Incorrect username or password.' });
  await regenerateSession(req);
  req.session.user = user.username;
  res.json({ user: user.username });
});
app.post('/api/logout', (req, res) => req.session.destroy(() => res.clearCookie('lv.sid', { sameSite: 'strict', secure: production }).json({ ok: true })));

app.get('/api/scripts', (req, res) => res.json(allScripts.all().map(scriptRow)));
app.post('/api/scripts', userOnly, submitLimiter, (req, res) => {
  const s = cleanScript(req.body);
  if (!s) return res.status(400).json({ error: 'A title and code are required.' });
  const info = db.prepare(`INSERT INTO scripts (title, game, key_type, created_at, description, image, code, author)
    VALUES (@title, @game, @key_type, @created_at, @description, @image, @code, @author)`).run({ ...s, created_at: Date.now(), author: req.session.user });
  res.status(201).json(scriptRow(db.prepare('SELECT * FROM scripts WHERE id = ?').get(info.lastInsertRowid)));
});
app.post('/api/scripts/:id/view', (req, res) => {
  const result = db.prepare('UPDATE scripts SET views = views + 1 WHERE id = ?').run(Number(req.params.id));
  if (!result.changes) return res.status(404).json({ error: 'Script not found.' });
  res.json({ ok: true });
});

app.post('/api/admin/login', adminLimiter, (req, res) => {
  const username = String(req.body?.username || '');
  const password = String(req.body?.password || '');
  if (!process.env.ADMIN_PASSWORD || username !== 'admin' || password !== process.env.ADMIN_PASSWORD) return res.status(401).json({ error: 'Incorrect admin credentials.' });
  regenerateSession(req).then(() => { req.session.admin = true; res.json({ admin: true }); }).catch(() => res.status(500).json({ error: 'Could not start admin session.' }));
});
app.post('/api/admin/logout', adminOnly, (req, res) => { delete req.session.admin; res.json({ ok: true }); });
app.get('/api/admin/overview', adminOnly, (req, res) => {
  const scripts = allScripts.all();
  const users = db.prepare('SELECT id, username, created_at FROM users ORDER BY created_at DESC').all();
  res.json({ scripts: scripts.map(scriptRow), users: users.map(u => ({ id: u.id, name: u.username, created: u.created_at })) });
});
app.patch('/api/admin/scripts/:id', adminOnly, (req, res) => {
  const s = cleanScript(req.body, true);
  if (!s || Object.keys(s).length === 0) return res.status(400).json({ error: 'No valid changes supplied.' });
  const columns = { title: 'title', game: 'game', description: 'description', code: 'code', key_type: 'key_type', image: 'image' };
  const sets = Object.keys(s).map(k => `${columns[k]} = @${k}`).join(', ');
  const result = db.prepare(`UPDATE scripts SET ${sets} WHERE id = @id`).run({ ...s, id: Number(req.params.id) });
  if (!result.changes) return res.status(404).json({ error: 'Script not found.' });
  res.json(scriptRow(db.prepare('SELECT * FROM scripts WHERE id = ?').get(Number(req.params.id))));
});
app.delete('/api/admin/scripts/:id', adminOnly, (req, res) => {
  const result = db.prepare('DELETE FROM scripts WHERE id = ?').run(Number(req.params.id));
  if (!result.changes) return res.status(404).json({ error: 'Script not found.' });
  res.json({ ok: true });
});
app.delete('/api/admin/users/:id', adminOnly, (req, res) => {
  const user = db.prepare('SELECT username FROM users WHERE id = ?').get(Number(req.params.id));
  if (!user) return res.status(404).json({ error: 'User not found.' });
  const tx = db.transaction(() => {
    db.prepare('DELETE FROM scripts WHERE author = ?').run(user.username);
    db.prepare('DELETE FROM users WHERE id = ?').run(Number(req.params.id));
  });
  tx(); res.json({ ok: true });
});
app.get('/api/admin/export', adminOnly, (req, res) => res.json(allScripts.all().map(scriptRow)));
app.post('/api/admin/import', adminOnly, (req, res) => {
  if (!Array.isArray(req.body?.scripts) || req.body.scripts.length > 1000) return res.status(400).json({ error: 'Invalid scripts list.' });
  const insert = db.prepare(`INSERT INTO scripts (title, game, key_type, views, created_at, description, image, code, author)
    VALUES (@title, @game, @key_type, @views, @created_at, @description, @image, @code, @author)`);
  let count = 0;
  const tx = db.transaction(items => { for (const raw of items) { const s = cleanScript(raw); if (!s) continue; insert.run({ ...s, views: Math.max(0, Number(raw.views) || 0), created_at: Number(raw.date) || Date.now(), author: String(raw.author || '').slice(0,30) }); count++; } });
  tx(req.body.scripts); res.json({ imported: count });
});
app.delete('/api/admin/data', adminOnly, (req, res) => { db.transaction(() => { db.prepare('DELETE FROM scripts').run(); db.prepare('DELETE FROM users').run(); })(); delete req.session.user; res.json({ ok: true }); });

app.get('/healthz', (_req, res) => res.json({ ok: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(PORT, () => console.log(`LuaVault server listening on port ${PORT}`));
