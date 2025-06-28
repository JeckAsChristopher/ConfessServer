// ---[ CORE DEPENDENCIES ]---
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const rateLimit = require('express-rate-limit');
const sanitizeHtml = require('sanitize-html');
const multer = require('multer');
const axios = require('axios');
const { Pool } = require('pg');

// ---[ INIT APP ]---
const app = express();
const UPLOAD_DIR = path.join(__dirname, 'public', 'uploads');

fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ---[ DB CONNECTION ]---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ---[ MULTER CONFIG ]---
const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOAD_DIR),
  filename: (_, file, cb) => {
    const safeName = `img_${Date.now()}${path.extname(file.originalname).toLowerCase()}`;
    cb(null, safeName);
  }
});
const upload = multer({
  storage,
  fileFilter: (_, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    cb(null, allowed.includes(file.mimetype));
  },
  limits: { fileSize: 2 * 1024 * 1024 } // 2MB
});

// ---[ MIDDLEWARE ]---
app.set('trust proxy', 1);
app.use(cors({ origin: '*', methods: ['GET', 'POST'] }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOAD_DIR));

// ---[ DDoS Rate Limiter ]---
const ddosLimiter = rateLimit({
  windowMs: 10 * 1000,
  max: 2,
  handler: (req, res) => {
    const log = `[${new Date().toISOString()}] 🚫 BLOCKED\nIP: ${req.ip}\nUA: ${req.get('User-Agent')}\nCountry: ${req.headers['cf-ipcountry'] || 'Unknown'}\n`;
    fs.appendFileSync('ddos-blocked.log', log + '\n');
    res.status(429).json({
      status: "BLOCKED DDOS ACTIVITY DETECTED",
      message: "You are detected as DDOSing the server. Your data has been logged.",
      details: { ipAddress: req.ip }
    });
  }
});
app.use('/confess', ddosLimiter);

// === ROUTES ===

// 🔹 Get all confessions
app.get('/confessions', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM confessions ORDER BY id DESC');
    res.json(result.rows);
  } catch (err) {
    console.error("❌ DB fetch error:", err.message);
    res.status(500).json({ success: false, error: 'Failed to fetch confessions' });
  }
});

// 🔹 Post a new confession
app.post('/confess', upload.single('photo'), async (req, res) => {
  const raw = req.body.message;
  if (!raw || !raw.trim()) {
    return res.status(400).json({ success: false, error: 'Message is empty' });
  }

  const message = sanitizeHtml(raw.trim(), { allowedTags: [], allowedAttributes: {} });

  const confession = {
    id: Date.now(),
    message,
    time: new Date().toLocaleString(),
    photo: req.file ? `https://confessserver.onrender.com/uploads/${req.file.filename}` : null,
    likes: 0
  };

  try {
    await pool.query(
      `INSERT INTO confessions (id, message, time, photo, likes)
       VALUES ($1, $2, $3, $4, $5)`,
      [confession.id, confession.message, confession.time, confession.photo, confession.likes]
    );

    res.status(201).json({ success: true, confession });
  } catch (err) {
    console.error("❌ DB insert error:", err.message);
    res.status(500).json({ success: false, error: 'DB insert failed' });
  }
});

// 🔹 Like a confession
app.post('/confess/:id/like', async (req, res) => {
  const id = Number(req.params.id);
  if (!id || isNaN(id)) {
    return res.status(400).json({ success: false, error: 'Invalid ID' });
  }

  try {
    const result = await pool.query(
      'UPDATE confessions SET likes = likes + 1 WHERE id = $1 RETURNING likes',
      [id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ success: false, error: 'Confession not found' });
    }

    res.json({ success: true, likes: result.rows[0].likes });
  } catch (err) {
    console.error("❌ Like update error:", err.message);
    res.status(500).json({ success: false, error: 'DB update failed' });
  }
});

// 🔹 Turnstile CAPTCHA Verification
app.post('/verify-turnstile', ddosLimiter, async (req, res) => {
  const token = req.body['cf-turnstile-response'];
  if (!token) {
    return res.status(400).json({ success: false, message: 'Missing CAPTCHA token.' });
  }

  try {
    const result = await axios.post(
      'https://challenges.cloudflare.com/turnstile/v0/siteverify',
      new URLSearchParams({
        secret: '0x4AAAAAABik13ClREk0a-QZR-AfbbDlFGQ',
        response: token,
        remoteip: req.ip
      }).toString(),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    if (result.data.success) {
      res.json({ success: true, message: 'CAPTCHA verified.' });
    } else {
      res.status(403).json({ success: false, message: 'Verification failed.', errors: result.data['error-codes'] });
    }
  } catch (err) {
    console.error("❌ CAPTCHA verify error:", err.message);
    res.status(500).json({ success: false, message: 'Internal CAPTCHA error.' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Confess Wall running on http://localhost:${PORT}`);
});
