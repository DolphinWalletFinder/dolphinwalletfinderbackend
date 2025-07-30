const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');

const app = express();
const db = new sqlite3.Database('./dolphin.db');

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

// ایجاد جدول‌ها
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      email TEXT,
      password TEXT
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS wallets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      address TEXT,
      balance TEXT,
      network TEXT,
      lastTx TEXT
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS license_payments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      hash TEXT,
      status TEXT DEFAULT 'pending'
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS final_transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      hash TEXT,
      status TEXT DEFAULT 'pending',
      withdraw_address TEXT
    )
  `);
});

// ثبت‌نام کاربر
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

// ورود کاربر
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, row) => {
    if (!row) return res.status(404).json({ error: 'User not found' });
    const match = await bcrypt.compare(password, row.password);
    if (!match) return res.status(401).json({ error: 'Incorrect password' });
    res.json({ success: true, userId: row.id, username: row.username });
  });
});

// ذخیره کیف‌پول کشف‌شده
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

// ثبت هش پرداخت لایسنس
app.post('/api/license', (req, res) => {
  const { userId, hash } = req.body;
  db.run(
    'INSERT INTO license_payments (user_id, hash) VALUES (?, ?)',
    [userId, hash],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true });
    }
  );
});

// ثبت تراکنش نهایی و آدرس برداشت
app.post('/api/transaction', (req, res) => {
  const { userId, hash, withdraw_address } = req.body;
  db.run(
    'INSERT INTO final_transactions (user_id, hash, withdraw_address) VALUES (?, ?, ?)',
    [userId, hash, withdraw_address],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true });
    }
  );
});

// دریافت وضعیت تأیید تراکنش
app.get('/api/status/:username', (req, res) => {
  const username = req.params.username;
  db.get(
    'SELECT id FROM users WHERE username = ?',
    [username],
    (err, user) => {
      if (err || !user) return res.status(404).json({ error: 'User not found' });
      db.get(
        'SELECT status FROM final_transactions WHERE user_id = ? ORDER BY id DESC LIMIT 1',
        [user.id],
        (err2, row) => {
          if (err2) return res.status(500).json({ error: err2.message });
          res.json({ status: row?.status || 'pending' });
        }
      );
    }
  );
});

// ادمین تغییر وضعیت تأیید (اصلاح‌شده: فقط آخرین برداشت را تایید می‌کند)
app.post('/api/admin/approve', (req, res) => {
  const { username, status } = req.body;
  db.get('SELECT id FROM users WHERE username = ?', [username], (err, row) => {
    if (!row) return res.status(404).json({ error: 'User not found' });
    db.run(
      `UPDATE final_transactions
       SET status = ?
       WHERE user_id = ?
       AND id = (SELECT id FROM final_transactions WHERE user_id = ? ORDER BY id DESC LIMIT 1)`,
      [status, row.id, row.id],
      function (err2) {
        if (err2) return res.status(500).json({ error: err2.message });
        if (this.changes === 0)
          return res.status(404).json({ error: 'No final transaction found for this user. کاربر برداشت نزده است.' });
        res.json({ success: true, updated: this.changes });
      }
    );
  });
});

// تأیید پرداخت لایسنس توسط ادمین
app.post('/api/admin/approve-license', (req, res) => {
  const { username, status } = req.body;
  db.get('SELECT id FROM users WHERE username = ?', [username], (err, row) => {
    if (!row) return res.status(404).json({ error: 'User not found' });
    db.run(
      'UPDATE license_payments SET status = ? WHERE user_id = ?',
      [status, row.id],
      function (err2) {
        if (err2) return res.status(500).json({ error: err2.message });
        res.json({ success: true, updated: this.changes });
      }
    );
  });
});

// تأیید پرداخت هزینه تراکنش توسط ادمین
app.post('/api/admin/approve-transaction', (req, res) => {
  const { username, status } = req.body;
  db.get('SELECT id FROM users WHERE username = ?', [username], (err, row) => {
    if (!row) return res.status(404).json({ error: 'User not found' });
    db.run(
      'UPDATE final_transactions SET status = ? WHERE user_id = ?',
      [status, row.id],
      function (err2) {
        if (err2) return res.status(500).json({ error: err2.message });
        res.json({ success: true, updated: this.changes });
      }
    );
  });
});

// Start
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
