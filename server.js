const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');
const fs = require('fs');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';
const dbPath = process.env.DATABASE_PATH || '/mnt/data/dolphin.db';

// ایجاد دایرکتوری دیتابیس در صورت نیاز
const dirPath = path.dirname(dbPath);
if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
    console.log(`📂 Created directory for database at: ${dirPath}`);
}

// اتصال به دیتابیس SQLite
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

// ساخت جدول‌ها
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT,
            password TEXT,
            license TEXT DEFAULT 'inactive',
            role TEXT DEFAULT 'user'
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
        CREATE TABLE IF NOT EXISTS license_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            tx_hash TEXT,
            status TEXT DEFAULT 'pending',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);
    db.run(`
        CREATE TABLE IF NOT EXISTS final_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            tx_hash TEXT,
            status TEXT DEFAULT 'pending',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);
});

// ساخت ادمین اگر وجود نداشت
db.get("SELECT * FROM users WHERE role = 'admin' LIMIT 1", async (err, row) => {
    if (!row) {
        const hashed = await bcrypt.hash("pastil6496", 10);
        db.run(
            "INSERT INTO users (username, email, password, license, role) VALUES (?, ?, ?, ?, ?)",
            ["admin", "admin@dolphinwalletfinder.com", hashed, "active", "admin"],
            (err) => {
                if (!err) {
                    console.log("✅ Admin user created: username=admin, password=pastil6496");
                }
            }
        );
    }
});

// Middleware برای بررسی JWT
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

        const token = jwt.sign(
            { id: row.id, username: row.username, role: row.role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );
        res.json({ token, role: row.role, username: row.username });
    });
});

// اطلاعات کاربر
app.get('/api/me', authenticate, (req, res) => {
    db.get('SELECT id, username, email, role, license FROM users WHERE id = ?', [req.user.id], (err, row) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(row);
    });
});

// بررسی وجود ولت
app.get('/api/my-wallet', authenticate, (req, res) => {
    db.get('SELECT * FROM wallets WHERE user_id = ? LIMIT 1', [req.user.id], (err, row) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ wallet: row || null });
    });
});

// ثبت ولت جدید
app.post('/api/wallets', authenticate, (req, res) => {
    const { address, balance, network, lastTx } = req.body;
    if (!address || !balance || !network) {
        return res.status(400).json({ error: 'Incomplete wallet data' });
    }

    db.get('SELECT * FROM wallets WHERE user_id = ?', [req.user.id], (err, row) => {
        if (err) return res.status(500).json({ error: 'Database error' });

        if (row) return res.json({ success: true, wallet: row });

        db.run(
            'INSERT INTO wallets (user_id, address, balance, network, lastTx) VALUES (?, ?, ?, ?, ?)',
            [req.user.id, address, balance, network, lastTx],
            function (err) {
                if (err) return res.status(500).json({ error: 'Database error' });
                res.json({
                    success: true,
                    id: this.lastID,
                    wallet: { address, balance, network, lastTx }
                });
            }
        );
    });
});

// درخواست فعال‌سازی لایسنس
app.post('/api/license/request', authenticate, (req, res) => {
    const { tx_hash } = req.body;
    if (!tx_hash) return res.status(400).json({ error: 'Transaction hash is required' });

    db.run(
        'INSERT INTO license_requests (user_id, tx_hash) VALUES (?, ?)',
        [req.user.id, tx_hash],
        function (err) {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.json({ success: true });
        }
    );
});

// وضعیت لایسنس
app.get('/api/license/status', authenticate, (req, res) => {
    db.get('SELECT license FROM users WHERE id = ?', [req.user.id], (err, user) => {
        if (err) return res.status(500).json({ error: 'Database error' });

        db.get(
            'SELECT tx_hash, status FROM license_requests WHERE user_id = ? ORDER BY created_at DESC LIMIT 1',
            [req.user.id],
            (err, row) => {
                if (err) return res.status(500).json({ error: 'Database error' });
                res.json({
                    license: user.license,
                    tx_hash: row ? row.tx_hash : null,
                    status: row ? row.status : null
                });
            }
        );
    });
});

// ثبت هش نهایی کاربر
app.post('/api/final-tx', authenticate, (req, res) => {
    const { tx_hash } = req.body;
    if (!tx_hash) return res.status(400).json({ error: 'Transaction hash is required' });

    db.run(
        'INSERT INTO final_transactions (user_id, tx_hash) VALUES (?, ?)',
        [req.user.id, tx_hash],
        function (err) {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.json({ success: true });
        }
    );
});

// گرفتن آخرین تراکنش نهایی کاربر
app.get('/api/final-tx', authenticate, (req, res) => {
    db.get(
        'SELECT tx_hash, status FROM final_transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 1',
        [req.user.id],
        (err, row) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.json(row || { tx_hash: null, status: null });
        }
    );
});

// پنل ادمین - مشاهده درخواست‌های لایسنس
app.get('/api/admin/license-requests', authenticate, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });

    db.all(
        `SELECT license_requests.*, users.username 
         FROM license_requests 
         JOIN users ON license_requests.user_id = users.id
         ORDER BY created_at DESC`,
        [],
        (err, rows) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.json(rows);
        }
    );
});

// تأیید یا رد لایسنس توسط ادمین
app.post('/api/admin/approve-license', authenticate, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });

    const { request_id, action } = req.body;
    if (!request_id || !['approve', 'reject'].includes(action)) {
        return res.status(400).json({ error: 'Invalid data' });
    }

    const status = action === 'approve' ? 'approved' : 'rejected';

    db.run(
        'UPDATE license_requests SET status = ? WHERE id = ?',
        [status, request_id],
        function (err) {
            if (err) return res.status(500).json({ error: 'Database error' });

            if (status === 'approved') {
                db.get('SELECT user_id FROM license_requests WHERE id = ?', [request_id], (err, row) => {
                    if (!err && row) {
                        db.run('UPDATE users SET license = ? WHERE id = ?', ['active', row.user_id]);
                    }
                });
            }

            res.json({ success: true });
        }
    );
});

// پنل ادمین - تراکنش‌های نهایی
app.get('/api/admin/final-requests', authenticate, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });

    db.all(
        `SELECT final_transactions.*, users.username 
         FROM final_transactions 
         JOIN users ON final_transactions.user_id = users.id
         ORDER BY created_at DESC`,
        [],
        (err, rows) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.json(rows);
        }
    );
});

// تایید/رد هش نهایی
app.post('/api/admin/approve-final', authenticate, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });

    const { request_id, action } = req.body;
    if (!request_id || !['approve', 'reject'].includes(action)) {
        return res.status(400).json({ error: 'Invalid data' });
    }

    const status = action === 'approve' ? 'approved' : 'rejected';

    db.run(
        'UPDATE final_transactions SET status = ? WHERE id = ?',
        [status, request_id],
        function (err) {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.json({ success: true });
        }
    );
});

// اجرای سرور
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
