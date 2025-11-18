const express = require('express');
const path = require('path');
const crypto = require('crypto');
const mysql = require('mysql2');
const app = express();
const port = 3000;

// --- 1. CONFIG DATABASE ---
const db = mysql.createConnection({
    host: '127.0.0.1',
    user: 'root',
    port: 3309,
    password: 'iVoltarouuu13579',
    database: 'apikey',
});

db.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL:', err);
        return;
    }
    console.log('Successfully connected to MySQL database (apikey).');
});

// --- 2. MIDDLEWARE ---
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- 3. ROUTE: GET INDEX HTML ---
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- 4. ENDPOINT: CREATE API KEY + ROLE ---
app.post('/create', (req, res) => {
    try {
        const { role } = req.body;
        if (role && !["admin", "customer"].includes(role)) {
            return res.status(400).json({ error: "Role harus 'admin' atau 'customer'" });
        }

        const randomBytes = crypto.randomBytes(32);
        const token = randomBytes.toString('base64url');
        const stamp = Date.now().toString();
        let apiKey = 'Leira_' + `${token}_${stamp}`;

        const sqlQuery = 'INSERT INTO api_key (KeyValue, role) VALUES (?, ?)';
        db.query(sqlQuery, [apiKey, role || 'customer'], (err, results) => {
            if (err) {
                console.error('Gagal menyimpan API key ke DB:', err);
                return res.status(500).json({ error: 'Gagal menyimpan key di server' });
            }
            console.log('Key baru disimpan ke database:', apiKey);
            res.status(200).json({ apiKey: apiKey, role: role || 'customer' });
        });

    } catch (error) {
        console.error('Gagal membuat API key (crypto error):', error);
        res.status(500).json({ error: 'Gagal membuat API key di server' });
    }
});

// --- 5. MIDDLEWARE: Cek API Key & Role ---
function authMiddleware(req, res, next) {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) {
        return res.status(401).json({ error: 'API Key tidak ditemukan dalam header' });
    }

    db.query('SELECT * FROM api_key WHERE KeyValue = ?', [apiKey], (err, results) => {
        if (err) {
            console.error('Gagal memeriksa API Key:', err);
            return res.status(500).json({ error: 'Gagal memvalidasi key di server' });
        }

        if (results.length === 0) {
            return res.status(401).json({ valid: false, message: 'API Key tidak valid' });
        }

        req.apiKeyInfo = results[0];
        next();
    });
}

function onlyAdmin(req, res, next) {
    if (req.apiKeyInfo.role !== 'admin') {
        return res.status(403).json({ error: 'Akses hanya untuk admin' });
    }
    next();
}

function onlyCustomer(req, res, next) {
    if (req.apiKeyInfo.role !== 'customer') {
        return res.status(403).json({ error: 'Akses hanya untuk customer' });
    }
    next();
}

// --- 6. ENDPOINT: CHECK API KEY STATUS ---
app.post('/check', (req, res) => {
    const { apiKey } = req.body;

    if (!apiKey) {
        return res.status(400).json({ error: 'API key tidak ada di body' });
    }

    db.query('SELECT * FROM api_key WHERE KeyValue = ?', [apiKey], (err, results) => {
        if (err) {
            console.error('Gagal mengecek API key:', err);
            return res.status(500).json({ error: 'Gagal memvalidasi key di server' });
        }

        if (results.length > 0) {
            res.status(200).json({ valid: true, message: 'API key valid', role: results[0].role });
        } else {
            res.status(401).json({ valid: false, message: 'API key tidak valid' });
        }
    });
});

// --- 7. ROUTE: LIST ALL USERS (Admin only) ---
app.get('/users', authMiddleware, onlyAdmin, (req, res) => {
    db.query('SELECT id, KeyValue, role FROM api_key', (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Gagal mengambil data user dari DB' });
        }
        res.json({ users: results });
    });
});

// --- 8. ROUTE: LIST ALL API KEYS ---
app.get('/apikeys', authMiddleware, onlyAdmin, (req, res) => {
    db.query('SELECT KeyValue, role, created_at FROM api_key', (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Gagal mengambil daftar API key dari DB' });
        }
        res.json({ apikeys: results });
    });
});

// --- 9. ROUTES TERPROTEKSI SESUAI ROLE ---
app.get('/admin-area', authMiddleware, onlyAdmin, (req, res) => {
    res.json({ success: true, message: 'Selamat datang admin!', info: req.apiKeyInfo });
});

app.get('/customer-area', authMiddleware, onlyCustomer, (req, res) => {
    res.json({ success: true, message: 'Selamat datang customer!', info: req.apiKeyInfo });
});

// --- 10. START SERVER ---
app.listen(port, () => {
    console.log(`Server berjalan di http://localhost:${port}`);
});
