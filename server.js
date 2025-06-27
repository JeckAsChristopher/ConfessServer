const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const rateLimit = require('express-rate-limit');
const sanitizeHtml = require('sanitize-html');
const multer = require('multer');
const axios = require('axios');

const app = express();
const DATA_FILE = path.join(__dirname, 'confessions.json');
const UPLOAD_DIR = path.join(__dirname, 'public', 'uploads');

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type']
}));

// Ensure directories
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// Load existing confessions
let confessions = [];
if (fs.existsSync(DATA_FILE)) {
  try {
    confessions = JSON.parse(fs.readFileSync(DATA_FILE, 'utf-8'));
  } catch (err) {
    console.error("❌ Failed to parse confessions.json:", err.message);
  }
}

// Multer config
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

// Middleware
app.set('trust proxy', 1);
app.use(cors({ origin: '*', methods: ['GET', 'POST'] }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOAD_DIR));

// DDoS Rate Limiter
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
app.get('/confessions', (req, res) => {
  res.json(confessions);
});

// 🔹 Post a new confession
app.post('/confess', upload.single('photo'), (req, res) => {
  const raw = req.body.message;
  if (!raw || !raw.trim()) {
    return res.status(400).json({ success: false, error: 'Message is empty' });
  }

  const message = sanitizeHtml(raw.trim(), { allowedTags: [], allowedAttributes: {} });

  const confession = {
    id: Date.now(),
    message,
    time: new Date().toLocaleString(),
    photo: req.file ? `https://confessserver-production.up.railway.app/uploads/${req.file.filename}` : null,
    likes: 0
  };

  confessions.unshift(confession);
  fs.writeFileSync(DATA_FILE, JSON.stringify(confessions, null, 2));

  res.status(201).json({ success: true, confession });
});

// 🔹 Like a confession
app.post('/confess/:id/like', (req, res) => {
  const id = Number(req.params.id);
  if (!id || isNaN(id)) {
    return res.status(400).json({ success: false, error: 'Invalid ID' });
  }

  const confession = confessions.find(c => c.id === id);
  if (!confession) {
    return res.status(404).json({ success: false, error: 'Confession not found' });
  }

  confession.likes = (confession.likes || 0) + 1;
  fs.writeFileSync(DATA_FILE, JSON.stringify(confessions, null, 2));
  console.log(`👍 Confession ${id} liked (${confession.likes} total)`);

  res.json({ success: true, likes: confession.likes });
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
