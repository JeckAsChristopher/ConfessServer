const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const rateLimit = require('express-rate-limit');
const sanitizeHtml = require('sanitize-html');
const multer = require('multer');
const axios = require('axios');

const app = express();
const PORT = 3000;
const DATA_FILE = path.join(__dirname, 'confessions.json');

// Load confessions from disk
let confessions = [];
if (fs.existsSync(DATA_FILE)) {
  try {
    confessions = JSON.parse(fs.readFileSync(DATA_FILE, 'utf-8'));
  } catch (err) {
    console.error("❌ Failed to load saved confessions:", err);
  }
}

// Ensure uploads directory exists
const UPLOAD_DIR = path.join(__dirname, 'public', 'uploads');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// Multer configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `img_${Date.now()}${ext}`);
  }
});
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    if (allowed.includes(file.mimetype)) cb(null, true);
    else cb(new Error('Only image files are allowed.'));
  },
  limits: { fileSize: 2 * 1024 * 1024 } // 2MB limit
});

// Middleware
app.set('trust proxy', 1);
app.use(cors({ origin: '*', methods: ['GET', 'POST'] }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));

// DDoS Protection
const ddosLimiter = rateLimit({
  windowMs: 10 * 1000,
  max: 2,
  handler: (req, res) => {
    const ip = req.ip;
    const ua = req.get('User-Agent') || 'Unknown';
    const country = req.headers['cf-ipcountry'] || 'Unknown';
    const now = new Date().toISOString();

    const log = `[${now}] BLOCKED DDoS ATTEMPT
IP: ${ip}
Country: ${country}
User-Agent: ${ua}
Reason: Too many requests in short time.
------------------------------\n`;

    fs.appendFileSync('ddos-blocked.log', log);

    res.status(429).json({
      status: "BLOCKED DDOS ACTIVITY DETECTED",
      message: "You are detected as DDOSing the server. Your data has been logged.",
      details: { ipAddress: ip, country, userAgent: ua }
    });
  }
});

app.use('/confess', ddosLimiter);

// Routes

// GET all confessions
app.get('/confessions', (req, res) => {
  res.json(confessions);
});

// POST a confession
app.post('/confess', upload.single('photo'), (req, res) => {
  const message = req.body.message;
  if (!message || !message.trim()) {
    return res.status(400).json({ success: false, error: 'Message is empty' });
  }

  const cleanMessage = sanitizeHtml(message.trim(), {
    allowedTags: [],
    allowedAttributes: {}
  });

  const confession = {
    id: Date.now(),
    message: cleanMessage,
    time: new Date().toLocaleString(),
    photo: req.file ? `http://localhost:3000/uploads/${req.file.filename}` : null,
    likes: 0
  };

  if (req.file) {
    console.log("📸 Uploaded file saved:", req.file.path);
  }

  confessions.unshift(confession);
  fs.writeFileSync(DATA_FILE, JSON.stringify(confessions, null, 2));
  res.status(201).json({ success: true, confession });
});

// POST like a confession
app.post('/confess/:id/like', (req, res) => {
  const id = Number(req.params.id);
  const confession = confessions.find(c => c.id === id);

  if (!confession) {
    return res.status(404).json({ success: false, error: 'Confession not found' });
  }

  confession.likes = (confession.likes || 0) + 1;
  fs.writeFileSync(DATA_FILE, JSON.stringify(confessions, null, 2));
  res.json({ success: true, likes: confession.likes });
});

// POST verify Turnstile CAPTCHA
app.post('/verify-turnstile', ddosLimiter, async (req, res) => {
  const token = req.body['cf-turnstile-response'];
  const ip = req.ip;

  if (!token) {
    return res.status(400).json({ success: false, message: 'Missing CAPTCHA token.' });
  }

  try {
    const response = await axios.post(
      'https://challenges.cloudflare.com/turnstile/v0/siteverify',
      new URLSearchParams({
        secret: '0x4AAAAAABik13ClREk0a-QZR-AfbbDlFGQ', // Replace with your real secret key
        response: token,
        remoteip: ip
      }).toString(),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    if (response.data.success) {
      res.json({ success: true, message: 'CAPTCHA verified successfully.' });
    } else {
      res.status(403).json({
        success: false,
        message: 'CAPTCHA verification failed.',
        errors: response.data['error-codes'] || []
      });
    }
  } catch (err) {
    console.error("❌ CAPTCHA verification failed:", err.message);
    res.status(500).json({ success: false, message: 'Internal server error during verification.' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`✅ Confess Wall running at http://localhost:${PORT}`);
});
