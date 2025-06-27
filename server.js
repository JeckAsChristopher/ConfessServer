const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const rateLimit = require('express-rate-limit');
const sanitizeHtml = require('sanitize-html');
const multer = require('multer');

const app = express();
const PORT = 3000;
const DATA_FILE = path.join(__dirname, 'confessions.json');

// Load confessions from file
let confessions = [];
if (fs.existsSync(DATA_FILE)) {
  try {
    confessions = JSON.parse(fs.readFileSync(DATA_FILE, 'utf-8'));
  } catch (err) {
    console.error("Failed to load saved confessions:", err);
  }
}

// Ensure uploads directory exists
const UPLOAD_DIR = path.join(__dirname, 'public', 'uploads');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// Multer setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const uniqueName = `img_${Date.now()}${ext}`;
    cb(null, uniqueName);
  }
});
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    if (allowed.includes(file.mimetype)) cb(null, true);
    else cb(new Error('Only image files are allowed.'));
  },
  limits: { fileSize: 2 * 1024 * 1024 } // 2MB
});

// Middleware
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST']
}));
app.use(express.json());
app.use(express.static('public'));

// Rate limiter
const limiter = rateLimit({
  windowMs: 10 * 1000,
  max: 5,
  message: { success: false, error: "Too many confessions. Try again later." }
});
app.use('/confess', limiter);

// Get all confessions
app.get('/confessions', (req, res) => {
  res.json(confessions);
});

// Post a confession
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
    photo: req.file ? `/uploads/${req.file.filename}` : null,
    likes: 0 // 🆕 Start with 0 likes
  };

  confessions.unshift(confession);
  fs.writeFileSync(DATA_FILE, JSON.stringify(confessions, null, 2));
  res.status(201).json({ success: true, confession });
});

// Like a confession
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

// Start server
app.listen(PORT, () => {
  console.log(`✅ Confess Wall running at http://localhost:${PORT}`);
});
