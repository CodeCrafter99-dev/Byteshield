/**
 * ByteShield Database Module
 * Uses Node.js built-in node:sqlite (DatabaseSync)
 * Creates tables for users and scans on initialization
 */

const { DatabaseSync } = require('node:sqlite');
const path = require('path');

// Database file path
const DB_PATH = path.join(__dirname, 'byteshield.db');

// Initialize database
const db = new DatabaseSync(DB_PATH);

// Enable WAL mode for better performance
db.exec('PRAGMA journal_mode = WAL');

// Create users table
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  )
`);

// Create scans table
db.exec(`
  CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    scan_type TEXT NOT NULL,
    input_summary TEXT,
    risk_level TEXT,
    risk_score INTEGER,
    confidence REAL,
    reasons TEXT,
    recommendation TEXT,
    analysis_source TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  )
`);

// Create index for faster user-specific queries
db.exec(`
  CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id)
`);

console.log('[DB] Database initialized at', DB_PATH);

module.exports = db;
