/**
 * ByteShield Dashboard Routes
 * Provides statistics for the authenticated user
 */

const express = require('express');
const { requireAuth } = require('../middleware/auth');
const db = require('../database');

const router = express.Router();

// Prepared statements for dashboard queries
const getTotalScans = db.prepare('SELECT COUNT(*) as count FROM scans WHERE user_id = ?');
const getHighRiskCount = db.prepare("SELECT COUNT(*) as count FROM scans WHERE user_id = ? AND risk_level = 'HIGH'");
const getMediumRiskCount = db.prepare("SELECT COUNT(*) as count FROM scans WHERE user_id = ? AND risk_level = 'MEDIUM'");
const getLowRiskCount = db.prepare("SELECT COUNT(*) as count FROM scans WHERE user_id = ? AND risk_level = 'LOW'");
const getRecentScans = db.prepare(`
  SELECT id, scan_type, input_summary, risk_level, risk_score, confidence, created_at
  FROM scans WHERE user_id = ?
  ORDER BY created_at DESC LIMIT 5
`);
const getScanTypeDistribution = db.prepare(`
  SELECT scan_type, COUNT(*) as count
  FROM scans WHERE user_id = ?
  GROUP BY scan_type
`);

/**
 * GET /api/dashboard
 * Get dashboard statistics for the current user
 */
router.get('/', requireAuth, (req, res) => {
  try {
    const userId = req.session.userId;

    const totalScans = getTotalScans.get(userId).count;
    const highRisk = getHighRiskCount.get(userId).count;
    const mediumRisk = getMediumRiskCount.get(userId).count;
    const lowRisk = getLowRiskCount.get(userId).count;
    const recentScans = getRecentScans.all(userId);
    const typeDistribution = getScanTypeDistribution.all(userId);

    // Format type distribution as an object
    const distribution = {
      message: 0,
      url: 0,
      screenshot: 0,
      qr: 0
    };
    typeDistribution.forEach(row => {
      if (distribution.hasOwnProperty(row.scan_type)) {
        distribution[row.scan_type] = row.count;
      }
    });

    res.json({
      stats: {
        totalScans,
        highRisk,
        mediumRisk,
        lowRisk
      },
      recentScans,
      distribution
    });
  } catch (err) {
    console.error('[Dashboard] Error fetching stats:', err);
    res.status(500).json({ error: 'Failed to retrieve dashboard data.' });
  }
});

module.exports = router;
