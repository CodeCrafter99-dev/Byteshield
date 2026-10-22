/**
 * ByteShield Server
 * Main Express application entry point
 */

const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });

const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');

// Initialize database (creates tables on first run)
require('./database');

const app = express();

// === Security Middleware ===

// Helmet for HTTP security headers (relaxed CSP for local development)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "blob:"],
    }
  }
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.method === 'GET' && (req.path === '/auth/me' || req.originalUrl.includes('/auth/me')),
  message: { error: 'Too many requests. Please try again later.' }
});
app.use('/api/', limiter);

// Stricter rate limit specifically for authentication attempts (login, signup)
// Protects against brute-force attacks while ensuring legitimate attempts work
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 failed attempts per 15 minutes
  skipSuccessfulRequests: true, // Legitimate logins that succeed do not count against the limit
  skip: (req) => req.method === 'GET' || req.path === '/me' || req.originalUrl.includes('/me') || req.path === '/logout' || req.originalUrl.includes('/logout'),
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts. Please try again later.' }
});
app.use('/api/auth/', authLimiter);

// === Body Parsing ===
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));

// === Session Configuration ===
app.use(session({
  secret: process.env.SESSION_SECRET || 'byteshield-fallback-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false, // false for local development (HTTP)
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// === File Upload Configuration ===
const storage = multer.diskStorage({
  destination: path.join(__dirname, 'uploads'),
  filename: (req, file, cb) => {
    const uniqueName = `${Date.now()}-${Math.round(Math.random() * 1E9)}${path.extname(file.originalname)}`;
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB max
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Only image files (JPEG, PNG, GIF, WEBP) are allowed.'));
    }
  }
});

// Make upload middleware available to routes
app.set('upload', upload);

// === Static Files ===
app.use(express.static(path.join(__dirname, '..', 'frontend')));

// === Routes ===
const authRoutes = require('./routes/auth');
app.use('/api/auth', authRoutes);

const scanRoutes = require('./routes/scan');
const historyRoutes = require('./routes/history');
const dashboardRoutes = require('./routes/dashboard');
app.use('/api/scan', scanRoutes);
app.use('/api/history', historyRoutes);
app.use('/api/dashboard', dashboardRoutes);

// === Serve Frontend Pages ===
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'frontend', 'index.html'));
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'frontend', 'dashboard.html'));
});

// === Error Handling ===
app.use((err, req, res, next) => {
  // Handle multer errors
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large. Maximum size is 5MB.' });
    }
    return res.status(400).json({ error: 'File upload error.' });
  }
  if (err.message && err.message.includes('Only image files')) {
    return res.status(400).json({ error: err.message });
  }
  console.error('[Server] Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error.' });
});

// === Start Server ===
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n  ╔══════════════════════════════════════════╗`);
  console.log(`  ║   ByteShield — AI Digital Scam Protection ║`);
  console.log(`  ║   Server running on http://localhost:${PORT}  ║`);
  console.log(`  ╚══════════════════════════════════════════╝\n`);
});
