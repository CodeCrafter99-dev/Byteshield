/**
 * ByteShield Authentication Routes
 * Handles signup, login, logout, and session check
 */

const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('../database');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

// Prepared statements for performance
const findUserByUsername = db.prepare('SELECT * FROM users WHERE username = ?');
const findUserByEmail = db.prepare('SELECT * FROM users WHERE email = ?');
const findUserByUsernameOrEmail = db.prepare('SELECT * FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)');
const insertUser = db.prepare('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)');
const findUserById = db.prepare('SELECT id, username, email, created_at FROM users WHERE id = ?');

/**
 * POST /api/auth/signup
 * Create a new user account
 */
router.post('/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validate input
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required.' });
    }

    // Validate username format
    if (username.length < 3 || username.length > 30) {
      return res.status(400).json({ error: 'Username must be 3-30 characters long.' });
    }

    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
      return res.status(400).json({ error: 'Username can only contain letters, numbers, and underscores.' });
    }

    // Validate email format
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address.' });
    }

    // Validate password strength
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
    }

    // Check if username already exists
    const existingUser = findUserByUsername.get(username);
    if (existingUser) {
      return res.status(409).json({ error: 'Username already taken.' });
    }

    // Check if email already exists
    const existingEmail = findUserByEmail.get(email);
    if (existingEmail) {
      return res.status(409).json({ error: 'Email already registered.' });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    // Insert user
    const result = insertUser.run(username, email, passwordHash);
    const userId = Number(result.lastInsertRowid);

    // Set session
    req.session.userId = userId;
    req.session.username = username;

    res.status(201).json({
      message: 'Account created successfully.',
      user: { id: userId, username, email }
    });
  } catch (error) {
    console.error('[Auth] Signup error:', error);
    res.status(500).json({ error: 'An error occurred during signup.' });
  }
});

/**
 * POST /api/auth/login
 * Authenticate user and create session
 */
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Validate input
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required.' });
    }

    // Find user (by username or email, case-insensitive)
    const user = findUserByUsername.get(username) || findUserByUsernameOrEmail.get(username, username);
    if (!user) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    // Verify password
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    // Set session
    req.session.userId = user.id;
    req.session.username = user.username;

    res.json({
      message: 'Login successful.',
      user: { id: user.id, username: user.username, email: user.email }
    });
  } catch (error) {
    console.error('[Auth] Login error:', error);
    res.status(500).json({ error: 'An error occurred during login.' });
  }
});

/**
 * POST /api/auth/logout
 * Destroy session
 */
router.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('[Auth] Logout error:', err);
      return res.status(500).json({ error: 'An error occurred during logout.' });
    }
    res.json({ message: 'Logged out successfully.' });
  });
});

/**
 * GET /api/auth/me
 * Get current authenticated user info
 */
router.get('/me', requireAuth, (req, res) => {
  const user = findUserById.get(req.session.userId);
  if (!user) {
    return res.status(404).json({ error: 'User not found.' });
  }
  res.json({ user });
});

module.exports = router;
