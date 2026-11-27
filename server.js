const express = require('express');
require('dotenv').config();
const { MongoClient } = require('mongodb');
const crypto = require('node:crypto');
const path = require('node:path');
const app = express();
app.use(express.json({ limit: '1mb' }));
const tokenExpiryMs = 30 * 24 * 60 * 60 * 1000;
let client;
let databaseReady;
let users;
let accounts;
let sessions;

async function connectToDatabase() {
  const mongoUri = process.env.MONGODB_URI;
  if (!mongoUri) throw new Error('MONGODB_URI is not configured.');

  if (!client) client = new MongoClient(mongoUri);
  if (!databaseReady) {
    databaseReady = (async () => {
      await client.connect();
      const db = client.db(process.env.MONGODB_DB || 'ledger');
      users = db.collection('users');
      accounts = db.collection('accounts');
      sessions = db.collection('sessions');
      await Promise.all([
        users.createIndex({ username: 1 }, { unique: true }),
        accounts.createIndex({ userId: 1 }, { unique: true }),
        sessions.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 })
      ]);
    })().catch(error => {
      databaseReady = null;
      throw error;
    });
  }
  await databaseReady;
}

const requireDatabase = asyncRoute(async (req, res, next) => {
  try {
    await connectToDatabase();
    next();
  } catch (error) {
    console.error('Database unavailable:', error.message);
    res.status(503).json({ error: 'The database is unavailable. Check the MONGODB_URI environment variable and database network access.' });
  }
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/manifest.webmanifest', (req, res) => res.sendFile(path.join(__dirname, 'manifest.webmanifest')));
app.get('/assets/:name', (req, res, next) => {
  const assets = {
    'gotyme-bank-logo.svg': 'gotyme-bank-logo.svg',
    'atome-ph-app-icon.jpg': 'atome-ph-app-icon.jpg',
    'trix-track-icon.svg': 'trix-track-icon.svg',
    'trix-track-icon-180.png': 'trix-track-icon-180.png',
    'trix-track-icon-192.png': 'trix-track-icon-192.png',
    'trix-track-icon-512.png': 'trix-track-icon-512.png'
  };
  const filename = assets[req.params.name];
  if (!filename) return next();
  res.sendFile(path.join(__dirname, 'assets', filename));
});
app.use('/api', requireDatabase);

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}

function validCredentials(username, password) {
  return typeof username === 'string' && /^[a-zA-Z0-9_.-]{3,32}$/.test(username.trim()) &&
    typeof password === 'string' && password.length >= 8 && password.length <= 200;
}

function asyncRoute(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

const requireAuth = asyncRoute(async (req, res, next) => {
  const token = (req.get('authorization') || '').replace(/^Bearer\s+/i, '');
  if (!token) return res.status(401).json({ error: 'Please sign in.' });
  const session = await sessions.findOne({ token, expiresAt: { $gt: new Date() } });
  if (!session) return res.status(401).json({ error: 'Your session expired. Please sign in again.' });
  req.userId = session.userId;
  req.username = session.username;
  next();
});

app.post('/api/auth/signup', asyncRoute(async (req, res) => {
  const { username, password } = req.body || {};
  if (!validCredentials(username, password)) {
    return res.status(400).json({ error: 'Use a 3–32 character username and a password of at least 8 characters.' });
  }
  const normalized = username.trim().toLowerCase();
  if (await users.findOne({ username: normalized })) return res.status(409).json({ error: 'Username already exists.' });
  const { salt, hash } = hashPassword(password);
  await users.insertOne({ username: normalized, salt, passwordHash: hash, createdAt: new Date() });
  res.status(201).json({ ok: true });
}));

app.post('/api/auth/login', asyncRoute(async (req, res) => {
  const { username, password } = req.body || {};
  const user = typeof username === 'string' ? await users.findOne({ username: username.trim().toLowerCase() }) : null;
  if (!user || typeof password !== 'string') return res.status(401).json({ error: 'Invalid username or password.' });
  const { hash } = hashPassword(password, user.salt);
  const a = Buffer.from(hash, 'hex');
  const b = Buffer.from(user.passwordHash, 'hex');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(401).json({ error: 'Invalid username or password.' });
  const token = crypto.randomBytes(32).toString('hex');
  await sessions.insertOne({ token, userId: user._id, username: user.username, expiresAt: new Date(Date.now() + tokenExpiryMs) });
  res.json({ token, username: user.username });
}));

app.get('/api/auth/me', requireAuth, (req, res) => res.json({ username: req.username }));
app.post('/api/auth/logout', requireAuth, asyncRoute(async (req, res) => {
  const token = (req.get('authorization') || '').replace(/^Bearer\s+/i, '');
  await sessions.deleteOne({ token });
  res.json({ ok: true });
}));

app.get('/api/data', requireAuth, asyncRoute(async (req, res) => {
  const account = await accounts.findOne({ userId: req.userId });
  res.json({ ...(account?.data || {}), _version: account?.version || 0 });
}));

app.get('/api/version', requireAuth, asyncRoute(async (req, res) => {
  const account = await accounts.findOne({ userId: req.userId }, { projection: { version: 1 } });
  res.json({ version: account?.version || 0 });
}));

app.put('/api/data', requireAuth, asyncRoute(async (req, res) => {
  const { key, value } = req.body || {};
  if (!['wallets', 'categories', 'goals', 'transactions'].includes(key) || !Array.isArray(value)) {
    return res.status(400).json({ error: 'Invalid account data.' });
  }
  await accounts.updateOne(
    { userId: req.userId },
    { $set: { [`data.${key}`]: value, updatedAt: new Date() }, $setOnInsert: { userId: req.userId }, $inc: { version: 1 } },
    { upsert: true }
  );
  const account = await accounts.findOne({ userId: req.userId }, { projection: { version: 1 } });
  res.json({ ok: true, version: account?.version || 0 });
}));

app.use((error, req, res, next) => {
  console.error(error);
  res.status(500).json({ error: 'Server error. Please try again.' });
});

async function start() {
  await connectToDatabase();
  const port = Number(process.env.PORT || 3000);
  app.listen(port, () => console.log(`Trix Track running at http://localhost:${port}`));
}

if (require.main === module) {
  start().catch(error => { console.error(error); process.exit(1); });
}

module.exports = app;
