import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import Database from 'better-sqlite3';

import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const raw = new Database(path.join(__dirname, 'coinvault.db'));

raw.exec(`
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, password_hash TEXT, full_name TEXT, phone TEXT, is_admin INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS cards (id INTEGER PRIMARY KEY AUTOINCREMENT, tier TEXT UNIQUE, display_name TEXT, masked_number TEXT, expiry TEXT, price REAL, potential_earnings REAL, gradient_from TEXT, gradient_to TEXT, sort_order INTEGER DEFAULT 0, active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS purchases (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, card_id INTEGER, price_paid REAL, purchased_at DATETIME DEFAULT CURRENT_TIMESTAMP, status TEXT DEFAULT 'active');
CREATE TABLE IF NOT EXISTS redemptions (id INTEGER PRIMARY KEY AUTOINCREMENT, purchase_id INTEGER, user_id INTEGER, amount REAL, redeemed_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS balances (user_id INTEGER PRIMARY KEY, amount REAL DEFAULT 0, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS deposits (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, amount REAL, reference TEXT, method TEXT, status TEXT DEFAULT 'pending', note TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, reviewed_at DATETIME, reviewed_by INTEGER);
CREATE TABLE IF NOT EXISTS balance_log (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, delta REAL, reason TEXT, admin_id INTEGER, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
`);

const db = {
  prepare: (sql) => ({
    get: (...p) => new Promise((ok, no) => raw.get(sql, p, (e, r) => e ? no(e) : ok(r))),
    all: (...p) => new Promise((ok, no) => raw.all(sql, p, (e, r) => e ? no(e) : ok(r))),
    run: (...p) => new Promise((ok, no) => raw.run(sql, p, function(e) { e ? no(e) : ok({ lastInsertRowid: this.lastID, changes: this.changes }); })),
  }),
  exec: (sql) => new Promise((ok, no) => raw.exec(sql, (e) => e ? no(e) : ok())),
  transaction: (fn) => (...a) => fn(...a),
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

const adminOnly = async (req, res, next) => {
  const u = await db.prepare('SELECT is_admin FROM users WHERE id=?').get(req.user.id);
  if (!u || !u.is_admin) return res.status(403).json({ error: 'Admin only' });
  next();
};

const app = express();
app.use(helmet());
app.use(cors({ origin: '*' }));
app.use(express.json());

app.get('/api/health', (_q, s) => s.json({ ok: true }));

// AUTH
app.post('/api/auth/register', async (req, res) => {
  const { email, password, full_name, phone } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password too short' });
  try {
    const ex = await db.prepare('SELECT id FROM users WHERE email=?').get(email);
    if (ex) return res.status(409).json({ error: 'Email already registered' });
    const hash = await bcrypt.hash(password, 10);
    const info = await db.prepare('INSERT INTO users (email, password_hash, full_name, phone) VALUES (?,?,?,?)').run(email, hash, full_name || null, phone || null);
    const user = { id: info.lastInsertRowid, email };
    res.status(201).json({ token: signToken(user), user });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  try {
    const u = await db.prepare('SELECT * FROM users WHERE email=?').get(email);
    if (!u) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    res.json({ token: signToken(u), user: { id: u.id, email: u.email, full_name: u.full_name, is_admin: u.is_admin } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/auth/me', auth, async (req, res) => {
  const u = await db.prepare('SELECT id,email,full_name,phone,is_admin,created_at FROM users WHERE id=?').get(req.user.id);
  res.json({ user: u });
});

// CARDS
app.get('/api/cards', async (_q, s) => {
  const cards = await db.prepare('SELECT * FROM cards WHERE active=1 ORDER BY sort_order').all();
  s.json({ cards });
});

// DASHBOARD
app.get('/api/dashboard', auth, async (req, res) => {
  const purchases = await db.prepare('SELECT p.*, c.potential_earnings FROM purchases p JOIN cards c ON c.id=p.card_id WHERE p.user_id=?').all(req.user.id);
  const totalRow = await db.prepare('SELECT COALESCE(SUM(amount),0) AS t FROM redemptions WHERE user_id=?').get(req.user.id);
  let available = 0;
  for (const p of purchases) {
    const r = await db.prepare('SELECT COALESCE(SUM(amount),0) AS t FROM redemptions WHERE purchase_id=?').get(p.id);
    const days = Math.min(365, Math.floor((Date.now() - new Date(p.purchased_at).getTime()) / 86400000));
    const accrued = (p.potential_earnings / 365) * days;
    available += Math.max(0, accrued - r.t);
  }
  const rc = await db.prepare("SELECT COUNT(*) AS c FROM purchases WHERE user_id=? AND status='redeemed'").get(req.user.id);
  const bal = await db.prepare('SELECT COALESCE(amount,0) AS a FROM balances WHERE user_id=?').get(req.user.id);
  res.json({ stats: { total_earnings: round2(totalRow.t + available), cards_owned: purchases.length, redeemed_cards: rc.c, balance: round2(bal ? bal.a : 0) }, currency: 'GHS' });
});

// PURCHASES
app.get('/api/purchases', auth, async (req, res) => {
  const rows = await db.prepare('SELECT p.*, c.tier, c.display_name, c.masked_number, c.expiry, c.potential_earnings, c.gradient_from, c.gradient_to FROM purchases p JOIN cards c ON c.id=p.card_id WHERE p.user_id=? ORDER BY p.purchased_at DESC').all(req.user.id);
  const out = [];
  for (const r of rows) {
    const rr = await db.prepare('SELECT COALESCE(SUM(amount),0) AS t FROM redemptions WHERE purchase_id=?').get(r.id);
    const days = Math.min(365, Math.floor((Date.now() - new Date(r.purchased_at).getTime()) / 86400000));
    const accrued = (r.potential_earnings / 365) * days;
    out.push({ ...r, earnings: { accrued: round2(accrued), redeemed: round2(rr.t), available: round2(Math.max(0, accrued - rr.t)), progress_pct: round2(days / 365 * 100), potential: r.potential_earnings } });
  }
  res.json({ purchases: out });
});

app.post('/api/purchases', auth, async (req, res) => {
  const { tier } = req.body || {};
  if (!tier) return res.status(400).json({ error: 'tier required' });
  const card = await db.prepare('SELECT * FROM cards WHERE tier=?').get(tier.toUpperCase());
  if (!card) return res.status(404).json({ error: 'Card not found' });
  const dup = await db.prepare("SELECT id FROM purchases WHERE user_id=? AND card_id=? AND status='active'").get(req.user.id, card.id);
  if (dup) return res.status(409).json({ error: 'Already owned' });
  const info = await db.prepare('INSERT INTO purchases (user_id, card_id, price_paid) VALUES (?,?,?)').run(req.user.id, card.id, card.price);
  res.status(201).json({ purchase: { id: info.lastInsertRowid }, card });
});

// REDEMPTIONS
app.get('/api/redemptions', auth, async (req, res) => {
  const rows = await db.prepare('SELECT r.*, c.tier, c.display_name, c.masked_number FROM redemptions r JOIN purchases p ON p.id=r.purchase_id JOIN cards c ON c.id=p.card_id WHERE r.user_id=? ORDER BY r.redeemed_at DESC').all(req.user.id);
  res.json({ redemptions: rows });
});

app.post('/api/redemptions', auth, async (req, res) => {
  const { purchase_id } = req.body || {};
  const p = await db.prepare('SELECT * FROM purchases WHERE id=? AND user_id=?').get(purchase_id, req.user.id);
  if (!p) return res.status(404).json({ error: 'Purchase not found' });
  const card = await db.prepare('SELECT * FROM cards WHERE id=?').get(p.card_id);
  const r = await db.prepare('SELECT COALESCE(SUM(amount),0) AS t FROM redemptions WHERE purchase_id=?').get(p.id);
  const days = Math.min(365, Math.floor((Date.now() - new Date(p.purchased_at).getTime()) / 86400000));
  const accrued = (card.potential_earnings / 365) * days;
  const avail = Math.max(0, accrued - r.t);
  if (avail <= 0) return res.status(400).json({ error: 'No earnings available' });
  const info = await db.prepare('INSERT INTO redemptions (purchase_id, user_id, amount) VALUES (?,?,?)').run(p.id, req.user.id, avail);
  if (r.t + avail >= card.potential_earnings - 0.01) await db.prepare("UPDATE purchases SET status='redeemed' WHERE id=?").run(p.id);
  res.status(201).json({ redemption: { id: info.lastInsertRowid, amount: round2(avail) } });
});

// DEPOSITS
app.get('/api/deposits', auth, async (req, res) => {
  const deposits = await db.prepare('SELECT * FROM deposits WHERE user_id=? ORDER BY created_at DESC').all(req.user.id);
  const b = await db.prepare('SELECT COALESCE(amount,0) AS a FROM balances WHERE user_id=?').get(req.user.id);
  res.json({ balance: b ? b.a : 0, deposits });
});

app.post('/api/deposits', auth, async (req, res) => {
  const { amount, reference, method } = req.body || {};
  if (typeof amount !== 'number' || amount <= 0) return res.status(400).json({ error: 'Invalid amount' });
  const info = await db.prepare('INSERT INTO deposits (user_id, amount, reference, method) VALUES (?,?,?,?)').run(req.user.id, amount, reference || null, method || 'momo');
  res.status(201).json({ deposit: { id: info.lastInsertRowid } });
});

// ADMIN
app.get('/api/admin/stats', auth, adminOnly, async (_q, s) => {
  const u = await db.prepare('SELECT COUNT(*) AS c FROM users').get();
  const p = await db.prepare("SELECT COUNT(*) AS c FROM deposits WHERE status='pending'").get();
  const a = await db.prepare("SELECT COALESCE(SUM(amount),0) AS t FROM deposits WHERE status='approved'").get();
  const b = await db.prepare('SELECT COALESCE(SUM(amount),0) AS t FROM balances').get();
  const pu = await db.prepare('SELECT COUNT(*) AS c FROM purchases').get();
  const re = await db.prepare('SELECT COUNT(*) AS c FROM redemptions').get();
  s.json({ users: u.c, pending_deposits: p.c, total_deposited: round2(a.t), total_balances: round2(b.t), purchases: pu.c, redemptions: re.c });
});

app.get('/api/admin/users', auth, adminOnly, async (_q, s) => {
  const users = await db.prepare('SELECT u.id, u.email, u.full_name, u.phone, u.created_at, u.is_admin, COALESCE(b.amount,0) AS balance FROM users u LEFT JOIN balances b ON b.user_id=u.id ORDER BY u.created_at DESC').all();
  s.json({ users });
});

app.post('/api/admin/users/:id/balance', auth, adminOnly, async (req, res) => {
  const { delta, reason } = req.body || {};
  if (typeof delta !== 'number' || delta === 0) return res.status(400).json({ error: 'delta must be non-zero' });
  await db.prepare('INSERT INTO balances (user_id, amount) VALUES (?,?) ON CONFLICT(user_id) DO UPDATE SET amount = amount + excluded.amount').run(req.params.id, delta);
  await db.prepare('INSERT INTO balance_log (user_id, delta, reason, admin_id) VALUES (?,?,?,?)').run(req.params.id, delta, reason || null, req.user.id);
  const b = await db.prepare('SELECT amount FROM balances WHERE user_id=?').get(req.params.id);
  res.json({ ok: true, balance: round2(b.amount) });
});

app.get('/api/admin/deposits', auth, adminOnly, async (req, res) => {
  const { status } = req.query;
  const q = status
    ? db.prepare('SELECT d.*, u.email FROM deposits d JOIN users u ON u.id=d.user_id WHERE d.status=? ORDER BY d.created_at DESC').all(status)
    : db.prepare('SELECT d.*, u.email FROM deposits d JOIN users u ON u.id=d.user_id ORDER BY d.created_at DESC').all();
  res.json({ deposits: await q });
});

app.post('/api/admin/deposits/:id/approve', auth, adminOnly, async (req, res) => {
  const d = await db.prepare('SELECT * FROM deposits WHERE id=?').get(req.params.id);
  if (!d) return res.status(404).json({ error: 'Not found' });
  if (d.status !== 'pending') return res.status(400).json({ error: 'Already reviewed' });
  await db.prepare("UPDATE deposits SET status='approved', reviewed_at=CURRENT_TIMESTAMP, reviewed_by=? WHERE id=?").run(req.user.id, d.id);
  await db.prepare('INSERT INTO balances (user_id, amount) VALUES (?,?) ON CONFLICT(user_id) DO UPDATE SET amount = amount + excluded.amount').run(d.user_id, d.amount);
  await db.prepare('INSERT INTO balance_log (user_id, delta, reason, admin_id) VALUES (?,?,?,?)').run(d.user_id, d.amount, 'Deposit approved', req.user.id);
  res.json({ ok: true });
});

app.post('/api/admin/deposits/:id/reject', auth, adminOnly, async (req, res) => {
  const d = await db.prepare('SELECT * FROM deposits WHERE id=?').get(req.params.id);
  if (!d) return res.status(404).json({ error: 'Not found' });
  if (d.status !== 'pending') return res.status(400).json({ error: 'Already reviewed' });
  await db.prepare("UPDATE deposits SET status='rejected', reviewed_at=CURRENT_TIMESTAMP, reviewed_by=? WHERE id=?").run(req.user.id, d.id);
  res.json({ ok: true });
});

// AUTO-SEED CARDS ON STARTUP
const seedCards = [
  ['IMPERIAL', 'Coin Vault — IMPERIAL', '4019********-1478', '08/2029', 1200, 23000, '#0a2a6b', '#0d47a1', 1],
  ['SOVEREIGN', 'Coin Vault — SOVEREIGN', '4498********-3720', '07/2028', 1700, 34500, '#0b1f4d', '#153a8a', 2],
  ['DIAMOND', 'Coin Vault — DIAMOND', '4956********-1607', '05/2029', 700, 12500, '#0a2f5c', '#1e6fd9', 3],
  ['ROYAL', 'Coin Vault — ROYAL', '4919********-4198', '04/2028', 900, 15000, '#131a3a', '#2a3f7a', 4],
  ['SILVER', 'Coin Vault — SILVER', '4309********-1297', '10/2028', 170, 2700, '#0f2a44', '#1c5a94', 5],
  ['GOLD', 'Coin Vault — GOLD', '4280********-9692', '11/2029', 250, 5000, '#0a3050', '#1565c0', 6],
];

(async () => {
  for (const c of seedCards) {
    const ex = await db.prepare('SELECT id FROM cards WHERE tier=?').get(c[0]);
    if (!ex) await db.prepare('INSERT INTO cards (tier, display_name, masked_number, expiry, price, potential_earnings, gradient_from, gradient_to, sort_order) VALUES (?,?,?,?,?,?,?,?,?)').run(...c);
  }
  const PORT = process.env.PORT || 4000;
  app.listen(PORT, '0.0.0.0', () => console.log('🚀 Coin Vault API on port ' + PORT));
  
