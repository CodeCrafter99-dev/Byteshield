/**
 * ByteShield History Routes
 * Retrieves scan history for the authenticated user
 */

const express = require('express');
const { requireAuth } = require('../middleware/auth');
const db = require('../database');

const router = express.Router();

// Prepared statement for fetching user history
const getUserScans = db.prepare(`
  SELECT id, scan_type, input_summary, risk_level, risk_score, confidence,
         reasons, recommendation, analysis_source, created_at
  FROM scans
  WHERE user_id = ?
  ORDER BY created_at DESC
  LIMIT 50
`);

/**
 * GET /api/history
 * Get scan history for the current user
 */
router.get('/', requireAuth, (req, res) => {
  try {
    const scans = getUserScans.all(req.session.userId);

    // Parse reasons JSON for each scan
    const formattedScans = scans.map(scan => ({
      ...scan,
      reasons: safeParseJSON(scan.reasons, [])
    }));

    res.json({ scans: formattedScans });
  } catch (err) {
    console.error('[History] Error fetching history:', err);
    res.status(500).json({ error: 'Failed to retrieve scan history.' });
  }
});

/**
 * Safely parse JSON string
 */
function safeParseJSON(str, fallback) {
  try {
    return JSON.parse(str);
  } catch {
    return fallback;
  }
}

module.exports = router;
