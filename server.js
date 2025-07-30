const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs'); // ✅ درست: bcryptjs
const cors = require('cors');
const path = require('path');

const app = express();
const db = new sqlite3.Database('./dolphin.db');

// ✅ تنظیم CORS برای GitHub Pages
app.use(cors({
  origin: ['https://dolphinwalletfinder.github.io'],
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type']
}));

app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

// ✅ ایجاد جدول‌ها
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email TEXT,
    password TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS wallets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    address TEXT,
    balance TEXT,
    network TEXT,
    lastTx TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS license_payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    hash TEXT,
    status TEXT DEFAULT 'pending'
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS final_transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    hash TEXT,
    status TEXT DEFAULT 'pending',
    withdraw_address TEXT
  )`);
});

// ✅ ثبت‌نام
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  db.run(
    'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
    [username, email, hashed],
    function (err) {
      if (err) return res.status(400).json({ error: 'Username already exists' });
      res.json({ success: true, userId: this.lastID });
    }
  );
});

// ✅ ورود
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, row) => {
    if (!row) return res.status(404).json({ error: 'User not found' });
    const match = await bcrypt.compare(password, row.password);
    if (!match) return res.status(401).json({ error: 'Incorrect password' });
    res.json({ success: true, userId: row.id, username: row.username });
  });
});

// ✅ ثبت کیف پول
app.post('/api/wallet', (req, res) => {
  const { userId, address, balance, network, lastTx } = req.body;
  db.run(
    'INSERT INTO wallets (user_id, address, balance, network, lastTx) VALUES (?, ?, ?, ?, ?)',
    [userId, address, balance, network, lastTx],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true });
    }
  );
});

// ✅ ثبت هش لایسنس
app.post('/api/license', (req, res) => {
  const { username, hash } = req.body;
  db.get('SELECT id FROM users WHERE username = ?', [username], (err, row) => {
    if (!row) return res.status(404).json({ error: 'User not found' });
    db.run(
      'INSERT INTO license_payments (user_id, hash) VALUES (?, ?)',
      [row.id, hash],
      err2 => {
        if (err2) return res.status(500).json({ error: err2.message });
        res.json({ success: true });
      }
    );
  });
});

// ✅ وضعیت تایید نهایی
app.get('/api/status/:username', (req, res) => {
  const username = req.params.username;
  db.get('SELECT id FROM users WHERE username = ?', [username], (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'User not found' });
    db.get(
      'SELECT status FROM final_transactions WHERE user_id = ? ORDER BY id DESC LIMIT 1',
      [user.id],
      (err2, row) => {
        if (err2) return res.status(500).json({ error: err2.message });
        res.json({ status: row?.status || 'pending' });
      }
    );
  });
});

// ✅ بررسی وضعیت لایسنس
app.get('/api/license-status/:username', (req, res) => {
  const username = req.params.username;
  db.get('SELECT id FROM users WHERE username = ?', [username], (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'User not found' });
    db.get(
      'SELECT status FROM license_payments WHERE user_id = ? ORDER BY id DESC LIMIT 1',
      [user.id],
      (err2, row) => {
        if (err2) return res.status(500).json({ error: err2.message });
        res.json({ status: row?.status || 'pending' });
      }
    );
  });
});

// ✅ تایید ادمین
app.post('/api/admin/approve', (req, res) => {
  const { username, status, type } = req.body;
  db.get('SELECT id FROM users WHERE username = ?', [username], (err, row) => {
    if (!row) return res.status(404).json({ error: 'User not found' });
    const table = type === "license" ? "license_payments" : "final_transactions";
    db.run(
      `UPDATE ${table} SET status = ? WHERE user_id = ?`,
      [status, row.id],
      (err2) => {
        if (err2) return res.status(500).json({ error: err2.message });
        res.json({ success: true });
      }
    );
  });
});

// ✅ اجرای سرور
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('✅ Server running on port', PORT));
