const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');
const fs = require('fs');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';

// مسیر دیتابیس SQLite - Railway Persistent Storage
const dbPath = process.env.DATABASE_PATH || '/mnt/data/dolphin.db';

// اطمینان از وجود پوشه دیتابیس
const dirPath = path.dirname(dbPath);
if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
    console.log(`📂 Created directory for database at: ${dirPath}`);
}

// اتصال به دیتابیس
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error("❌ Failed to connect to database:", err.message);
    } else {
        console.log(`✅ Connected to SQLite database at: ${dbPath}`);
    }
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

// ایجاد جداول
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
});

// ثبت‌نام
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password)
        return res.status(400).json({ error: 'All fields required' });

    const hashed = await bcrypt.hash(password, 10);
    db.run(
        'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
        [username, email, hashed],
        function (err) {
            if (err) return res.status(400).json({ error: 'Username already exists' });
            res.json({ success: true });
        }
    );
});

// ورود
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, row) => {
        if (!row) return res.status(404).json({ error: 'User not found' });
        const match = await bcrypt.compare(password, row.password);
        if (!match) return res.status(401).json({ error: 'Invalid password' });

        const token = jwt.sign({ id: row.id, username: row.username }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token });
    });
});

// Middleware احراز هویت
function authenticate(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: 'No token provided' });

    const token = authHeader.split(' ')[1];
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = decoded;
        next();
    });
}

// ذخیره کیف‌پول
app.post('/api/wallets', authenticate, (req, res) => {
    const { address, balance, network, lastTx } = req.body;
    db.run(
        'INSERT INTO wallets (user_id, address, balance, network, lastTx) VALUES (?, ?, ?, ?, ?)',
        [req.user.id, address, balance, network, lastTx],
        function (err) {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.json({ success: true, id: this.lastID });
        }
    );
});

// واکشی کیف‌پول‌ها
app.get('/api/wallets', authenticate, (req, res) => {
    db.all('SELECT * FROM wallets WHERE user_id = ?', [req.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(rows);
    });
});

// شروع سرور
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
