process.on('uncaughtException', (err) => {
  console.error('💥 UNCAUGHT ERROR:', err.message);
  console.error('STACK:', err.stack);
  process.exit(1);
});
process.on('unhandledRejection', (reason) => {
  console.error('💥 UNHANDLED REJECTION:', reason);
  process.exit(1);
});import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import axios from 'axios';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import initSqlJs from 'sql.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DB_PATH = path.join(__dirname, 'coinvault.db');

// Load sql.js (pure JavaScript SQLite — no native compilation)
const SQL = await initSqlJs();

// Load existing DB from file if it exists
let raw;
if (fs.existsSync(DB_PATH)) {
  raw = new SQL.Database(fs.readFileSync(DB_PATH));
  console.log('📂 Loaded existing database');
} else {
  raw = new SQL.Database();
  console.log('🆕 Created new database');
}

// Initialize schema
raw.run(`
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, password_hash TEXT, full_name TEXT, phone TEXT, is_admin INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS cards (id INTEGER PRIMARY KEY AUTOINCREMENT, tier TEXT UNIQUE, display_name TEXT, masked_number TEXT, expiry TEXT, price REAL, potential_earnings REAL, gradient_from TEXT, gradient_to TEXT, sort_order INTEGER DEFAULT 0, active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS purchases (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, card_id INTEGER, price_paid REAL, purchased_at DATETIME DEFAULT CURRENT_TIMESTAMP, status TEXT DEFAULT 'active');
CREATE TABLE IF NOT EXISTS redemptions (id INTEGER PRIMARY KEY AUTOINCREMENT, purchase_id INTEGER, user_id INTEGER, amount REAL, redeemed_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS balances (user_id INTEGER PRIMARY KEY, amount REAL DEFAULT 0, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS deposits (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, amount REAL, reference TEXT, method TEXT, status TEXT DEFAULT 'pending', note TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, reviewed_at DATETIME, reviewed_by INTEGER);
CREATE TABLE IF NOT EXISTS balance_log (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, delta REAL, reason TEXT, admin_id INTEGER, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
`);

// Save DB to disk periodically and on mutations
function saveDb() {
  try {
    const data = Buffer.from(raw.export());
    fs.writeFileSync(DB_PATH, data);
  } catch (e) {
    console.error('Save DB error:', e.message);
  }
}

// Seed cards on startup
const seedCards = [
  ['IMPERIAL', 'Coin Vault — IMPERIAL', '4019********-1478', '08/2029', 1200, 23000, '#0a2a6b', '#0d47a1', 1],
  ['SOVEREIGN', 'Coin Vault — SOVEREIGN', '4498********-3720', '07/2028', 1700, 34500, '#0b1f4d', '#153a8a', 2],
  ['DIAMOND', 'Coin Vault — DIAMOND', '4956********-1607', '05/2029', 700, 12500, '#0a2f5c', '#1e6fd9', 3],
  ['ROYAL', 'Coin Vault — ROYAL', '4919********-4198', '04/2028', 900, 15000, '#131a3a', '#2a3f7a', 4],
  ['SILVER', 'Coin Vault — SILVER', '4309********-1297', '10/2028', 170, 2700, '#0f2a44', '#1c5a94', 5],
  ['GOLD', 'Coin Vault — GOLD', '4280********-9692', '11/2029', 250, 5000, '#0a3050', '#1565c0', 6],
];

for (const c of seedCards) {
  const stmt = raw.prepare('SELECT id FROM cards WHERE tier=?');
  stmt.bind([c[0]]);
  if (!stmt.step()) {
    raw.run('INSERT INTO cards (tier, display_name, masked_number, expiry, price, potential_earnings, gradient_from, gradient_to, sort_order) VALUES (?,?,?,?,?,?,?,?,?)', c);
  }
  stmt.free();
}
saveDb();
console.log('✅ Cards seeded');

// Helper: run a query that returns rows
function query(sql, params = []) {
  const stmt = raw.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) {
    rows.push(stmt.getAsObject());
  }
  stmt.free();
  return rows;
}

// Helper: run INSERT/UPDATE/DELETE
function exec(sql, params = []) {
  raw.run(sql, params);
  saveDb();
  const stmt = raw.prepare('SELECT last_insert_rowid() AS id');
  stmt.step();
  const { id } = stmt.getAsObject();
  stmt.free();
  return { lastInsertRowid: id };
}

// API wrapper to mimic better-sqlite3's sync API
const db = {
  prepare: (sql) => ({
    get: (...p) => query(sql, p)[0],
    all: (...p) => query(sql, p),
    run: (...p) => exec(sql, p),
  }),
  exec: (sql) => { raw.run(sql); saveDb(); },
  transaction: (fn) => () => fn(),
};

const round2 = (n) => Math.round(n * 100) / 100;
const signToken = (u) => jwt.sign({ sub: u.id, email: u.email }, process.env.JWT_SECRET, { expiresIn: '7d' });

const auth = (req, res, next) => {
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!t) return res.status(401).json({ error: 'Missing token' });
  try {
    const p = jwt.verify(t, process.env.JWT_SECRET);
    req.user = { id: p.sub, email: p.email };
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
};

const adminOnly = (req, res, next) => {
  const u = db.prepare('SELECT is_admin FROM users WHERE id=?').get(req.user.id);
  if (!u || !u.is_admin) return res.status(403).json({ error: 'Admin only' });
  next();
};

const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: '*' }));
app.use(express.json());

app.get('/api/health', (_q, s) => s.json({ ok: true, db: 'sql.js' }));

// AUTH
app.post('/api/auth/register', async (req, res) => {
  const { email, password, full_name, phone } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password too short' });
  try {
    const ex = db.prepare('SELECT id FROM users WHERE email=?').get(email);
    if (ex) return res.status(409).json({ error: 'Email already registered' });
    const hash = await bcrypt.hash(password, 10);
    const info = db.prepare('INSERT INTO users (email, password_hash, full_name, phone) VALUES (?,?,?,?)').run(email, hash, full_name || null, phone || null);
    const user = { id: info.lastInsertRowid, email };
    res.status(201).json({ token: signToken(user), user });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  try {
    const u = db.prepare('SELECT * FROM users WHERE email=?').get(email);
    if (!u) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    res.json({ token: signToken(u), user: { id: u.id, email: u.email, full_name: u.full_name, is_admin: u.is_admin } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/auth/me', auth, (req, res) => {
  const u = db.prepare('SELECT id,email,full_name,phone,is_admin,created_at FROM users WHERE id=?').get(req.user.id);
  res.json({ user: u });
});

// CARDS
app.get('/api/cards', (_q, s) => {
  const cards = db.prepare('SELECT * FROM cards WHERE active=1 ORDER BY sort_order').all();
  s.json({ cards });
});

// DASHBOARD
app.get('/api/dashboard', auth, (req, res) => {
  const purchases = db.prepare('SELECT p.*, c.potential_earnings FROM purchases p JOIN cards c ON c.id=p.card_id WHERE p.user_id=?').all(req.user.id);
  const totalRow = db.prepare('SELECT COALESCE(SUM(amount),0) AS t FROM redemptions WHERE user_id=?').get(req.user.id);
  let available = 0;
  for (const p of purchases) {
    const r = db.prepare('SELECT COALESCE(SUM(amount),0) AS t FROM redemptions WHERE purchase_id=?').get(p.id);
    const days = Math.min(365, Math.floor((Date.now() - new Date(p.purchased_at).getTime()) / 86400000));
    const accrued = (p.potential_earnings / 365) * days;
    available += Math.max(0, accrued - r.t);
  }
  const rc = db.prepare("SELECT COUNT(*) AS c FROM purchases WHERE user_id=? AND status='redeemed'").get(req.user.id);
  const bal = db.prepare('SELECT COALESCE(amount,0) AS a FROM balances WHERE user_id=?').get(req.user.id);
  res.json({ stats: { total_earnings: round2(totalRow.t + available), cards_owned: purchases.length, redeemed_cards: rc.c, balance: round2(bal ? bal.a : 0) }, currency: 'GHS' });
});

// PURCHASESget(
app.post('/api/purchases', auth, (req, res) => {
  const { tier } = req.body || {};
  if (!tier) return res.status(400).json({ error: 'tier required' });
  const card = db.prepare('SELECT * FROM cards WHERE tier=?').get(tier.toUpperCase());
  if (!card) return res.status(404).json({ error: 'Card not found' });
  const dup = db.prepare("SELECT id FROM purchases WHERE user_id=? AND card_id=? AND status='active'").get(req.user.id, card.id);
  if (dup) return res.status(409).json({ error: 'Already owned' });

  const bal = db.prepare('SELECT COALESCE(amount,0) AS a FROM balances WHERE user_id=?').get(req.user.id);
  const balance = bal ? bal.a : 0;
  if (balance < card.price) {
    return res.status(400).json({
      error: 'Insufficient balance. Deposit GH₵' + (card.price - balance).toFixed(2) + ' more.'
    });
  }

  db.prepare(`INSERT INTO balances (user_id, amount) VALUES (?,?)
    ON CONFLICT(user_id) DO UPDATE SET amount = amount - excluded.amount, updated_at = CURRENT_TIMESTAMP`)
    .run(req.user.id, card.price);
  db.prepare('INSERT INTO balance_log (user_id, delta, reason) VALUES (?,?,?)')
    .run(req.user.id, -card.price, 'Purchase: ' + card.tier);

  const info = db.prepare('INSERT INTO purchases (user_id, card_id, price_paid) VALUES (?,?,?)')
    .run(req.user.id, card.id, card.price);
  res.status(201).json({ purchase: { id: info.lastInsertRowid }, card, new_balance: round2(balance - card.price) });
});
