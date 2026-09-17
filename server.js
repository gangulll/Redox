require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const DATA = path.join(__dirname, 'data');
if (!fs.existsSync(DATA)) fs.mkdirSync(DATA);

function load(f, fb) {
  const p = path.join(DATA, f);
  if (!fs.existsSync(p)) { fs.writeFileSync(p, JSON.stringify(fb)); return fb; }
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return fb; }
}
function save(f, d) { fs.writeFileSync(path.join(DATA, f), JSON.stringify(d, null, 2)); }

let db = {
  users: load('users.json', []),
  sessions: load('sessions.json', []),
  orders: load('orders.json', []),
  challenges: load('challenges.json', [])
};
function nextId(arr) { return arr.length ? Math.max(...arr.map(x => x.id)) + 1 : 1; }
function persist() {
  save('users.json', db.users);
  save('sessions.json', db.sessions);
  save('orders.json', db.orders);
  save('challenges.json', db.challenges);
}

const SESSION_TTL = 7 * 24 * 60 * 60 * 1000;
const ORDER_TTL = 30 * 60 * 1000;

const PLANS = {
  '5k_2phase':   { accountSize: 5000,   priceUsd: 5,   phase: '2-Phase' },
  '10k_2phase':  { accountSize: 10000,  priceUsd: 39,  phase: '2-Phase' },
  '25k_2phase':  { accountSize: 25000,  priceUsd: 89,  phase: '2-Phase' },
  '50k_2phase':  { accountSize: 50000,  priceUsd: 179, phase: '2-Phase' },
  '100k_2phase': { accountSize: 100000, priceUsd: 349, phase: '2-Phase' }
};

const norm = e => String(e || '').trim().toLowerCase();
const okEmail = e => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const okPass = p => typeof p === 'string' && p.length >= 6;

function createSession(uid) {
  const token = crypto.randomBytes(48).toString('hex');
  db.sessions.push({ token, user_id: uid, expires_at: Date.now() + SESSION_TTL, created_at: Date.now() });
  persist();
  return token;
}
function sessionUser(token) {
  if (!token) return null;
  const s = db.sessions.find(x => x.token === token);
  if (!s) return null;
  if (s.expires_at < Date.now()) { db.sessions = db.sessions.filter(x => x.token !== token); persist(); return null; }
  const u = db.users.find(x => x.id === s.user_id);
  return u ? { id: u.id, email: u.email } : null;
}
function auth(req, res, next) {
  const u = sessionUser(req.cookies?.sid);
  if (!u) return res.status(401).json({ error: 'Not logged in' });
  req.user = u; next();
}
function adminAuth(req, res, next) {
  const pw = req.headers['x-admin-password'] || req.query.pw;
  if (!pw || pw !== process.env.ADMIN_PASSWORD) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

const signupLim = rateLimit({ windowMs: 60 * 60 * 1000, max: 20, message: { error: 'Too many attempts' } });
const loginLim  = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: { error: 'Too many login attempts' } });

app.use(express.json());
app.use(cookieParser());

app.post('/api/auth/signup', signupLim, async (req, res) => {
  try {
    const email = norm(req.body.email);
    const { password, confirmPassword } = req.body;
    if (!okEmail(email)) return res.status(400).json({ error: 'Invalid email address' });
    if (!okPass(password)) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    if (password !== confirmPassword) return res.status(400).json({ error: 'Passwords do not match' });
    if (db.users.find(u => u.email === email)) return res.status(409).json({ error: 'Email already registered. Please login.' });

    const hash = await bcrypt.hash(password, 10);
    const id = nextId(db.users);
    db.users.push({ id, email, password_hash: hash, created_at: Date.now() });
    persist();

    const token = createSession(id);
    res.cookie('sid', token, { httpOnly: true, sameSite: 'lax', maxAge: SESSION_TTL });
    res.json({ ok: true, user: { id, email } });
  } catch (e) { console.error(e.message); res.status(500).json({ error: 'Signup failed' }); }
});

app.post('/api/auth/login', loginLim, async (req, res) => {
  try {
    const email = norm(req.body.email);
    const password = String(req.body.password || '');
    const u = db.users.find(x => x.email === email);
    if (!u) return res.status(401).json({ error: 'Invalid email or password' });
    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid email or password' });
    const token = createSession(u.id);
    res.cookie('sid', token, { httpOnly: true, sameSite: 'lax', maxAge: SESSION_TTL });
    res.json({ ok: true, user: { id: u.id, email: u.email } });
  } catch (e) { console.error(e.message); res.status(500).json({ error: 'Login failed' }); }
});

app.post('/api/auth/logout', (req, res) => {
  const t = req.cookies?.sid;
  if (t) { db.sessions = db.sessions.filter(x => x.token !== t); persist(); }
  res.clearCookie('sid');
  res.json({ ok: true });
});

app.get('/api/auth/me', (req, res) => {
  const u = sessionUser(req.cookies?.sid);
  if (!u) return res.status(401).json({ error: 'Not logged in' });
  res.json({ user: u });
});

app.get('/api/me/dashboard', auth, (req, res) => {
  const ch = db.challenges.filter(c => c.user_id === req.user.id).map(c => {
    const o = db.orders.find(x => x.id === c.order_id);
    return { ...c, price_usd: o && o.price_usd, paid_at: o && o.paid_at };
  }).sort((a, b) => b.created_at - a.created_at);
  const ord = db.orders.filter(o => o.user_id === req.user.id).sort((a, b) => b.created_at - a.created_at).slice(0, 20);
  res.json({ user: req.user, challenges: ch, orders: ord });
});

app.post('/api/orders/create', auth, (req, res) => {
  try {
    const plan = PLANS[req.body.planId];
    if (!plan) return res.status(400).json({ error: 'Invalid plan' });
    const wallet = process.env.USDT_BEP20_ADDRESS;
    if (!wallet || !wallet.startsWith('0x')) return res.status(500).json({ error: 'Wallet not configured' });
    const delta = (Math.random() * 0.0099).toFixed(4);
    const amt = (plan.priceUsd + parseFloat(delta)).toFixed(4);
    const ref = 'RDX' + Date.now().toString(36).toUpperCase() + crypto.randomBytes(2).toString('hex').toUpperCase();
    const now = Date.now();
    const order = {
      id: nextId(db.orders), user_id: req.user.id, order_ref: ref, plan_id: req.body.planId,
      account_size: plan.accountSize, price_usd: plan.priceUsd, crypto_amount: amt, crypto_coin: 'USDT',
      crypto_network: 'BEP20', wallet_address: wallet, status: 'pending', txid: null,
      created_at: now, expires_at: now + ORDER_TTL, paid_at: null
    };
    db.orders.push(order); persist();
    res.json({ ok: true, order });
  } catch (e) { console.error(e.message); res.status(500).json({ error: 'Could not create order' }); }
});

app.post('/api/orders/:ref/submit-txid', auth, (req, res) => {
  try {
    const txid = String(req.body.txid || '').trim();
    if (txid.length < 10) return res.status(400).json({ error: 'Invalid TXID' });
    const order = db.orders.find(o => o.order_ref === req.params.ref && o.user_id === req.user.id);
    if (!order) return res.status(404).json({ error: 'Order not found' });
    if (order.status === 'paid') return res.status(400).json({ error: 'Already paid' });
    if (order.expires_at < Date.now()) return res.status(400).json({ error: 'Order expired. Create new one.' });
    if (db.orders.find(o => o.txid === txid && o.id !== order.id)) return res.status(400).json({ error: 'This TXID is already used' });
    order.txid = txid; order.status = 'awaiting_review'; persist();
    res.json({ ok: true, message: 'TXID submitted. Verification within 30 minutes.' });
  } catch (e) { console.error(e.message); res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/admin/orders', adminAuth, (req, res) => {
  const list = db.orders.filter(o => o.status === 'pending' || o.status === 'awaiting_review')
    .sort((a, b) => b.created_at - a.created_at)
    .map(o => ({ ...o, user_email: (db.users.find(u => u.id === o.user_id) || {}).email }));
  res.json({ orders: list });
});

app.post('/api/admin/orders/:ref/mark-paid', adminAuth, (req, res) => {
  try {
    const order = db.orders.find(o => o.order_ref === req.params.ref);
    if (!order) return res.status(404).json({ error: 'Not found' });
    if (order.status === 'paid') return res.json({ ok: true, already: true });
    const plan = PLANS[order.plan_id];
    order.status = 'paid'; order.paid_at = Date.now(); persist();
    db.challenges.push({
      id: nextId(db.challenges), user_id: order.user_id, order_id: order.id,
      plan_id: order.plan_id, account_size: plan.accountSize, phase: plan.phase,
      status: 'active', created_at: Date.now()
    });
    persist();
    res.json({ ok: true });
  } catch (e) { console.error(e.message); res.status(500).json({ error: 'Failed' }); }
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Redox running → http://localhost:' + PORT));

