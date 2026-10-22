/**
 * ByteShield Scan Routes
 * Handles message, URL, screenshot, and QR code scanning
 */

const express = require('express');
const fs = require('fs');
const path = require('path');
const { requireAuth } = require('../middleware/auth');
const ruleEngine = require('../services/ruleEngine');
const geminiService = require('../services/geminiService');
const riskEngine = require('../services/riskEngine');
const urlAnalyzer = require('../services/urlAnalyzer');
const qrDecoder = require('../services/qrDecoder');
const db = require('../database');

const router = express.Router();

// Prepared statement for saving scans
const insertScan = db.prepare(`
  INSERT INTO scans (user_id, scan_type, input_summary, risk_level, risk_score, confidence, reasons, recommendation, analysis_source)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

/**
 * Save a scan result to the database
 */
function saveScan(userId, scanType, inputSummary, result) {
  try {
    // Truncate input summary for storage
    const summary = inputSummary.length > 500
      ? inputSummary.substring(0, 500) + '...'
      : inputSummary;

    insertScan.run(
      userId,
      scanType,
      summary,
      result.riskLevel,
      result.riskScore,
      result.confidence,
      JSON.stringify(result.reasons),
      result.recommendation,
      result.analysisSource
    );
  } catch (err) {
    console.error('[Scan] Error saving scan:', err.message);
  }
}

/**
 * POST /api/scan/message
 * Analyze a text message for scam indicators
 */
router.post('/message', requireAuth, async (req, res) => {
  try {
    const { message } = req.body;

    if (!message || typeof message !== 'string' || message.trim().length === 0) {
      return res.status(400).json({ error: 'Please provide a message to analyze.' });
    }

    if (message.length > 5000) {
      return res.status(400).json({ error: 'Message is too long. Maximum 5000 characters.' });
    }

    const text = message.trim();

    // Run rule engine (always available)
    const ruleResult = ruleEngine.analyzeMessage(text);

    // Try AI analysis
    let aiResult = null;
    if (geminiService.isAvailable()) {
      aiResult = await geminiService.analyzeMessage(text);
    }

    // Combine results
    const result = riskEngine.combineResults(aiResult, ruleResult, 'message');

    // Save to database
    saveScan(req.session.userId, 'message', text, result);

    res.json(result);
  } catch (err) {
    console.error('[Scan] Message scan error:', err);
    res.status(500).json({ error: 'An error occurred during message analysis.' });
  }
});

/**
 * POST /api/scan/url
 * Analyze a URL for suspicious indicators
 */
router.post('/url', requireAuth, async (req, res) => {
  try {
    const { url } = req.body;

    if (!url || typeof url !== 'string' || url.trim().length === 0) {
      return res.status(400).json({ error: 'Please provide a URL to analyze.' });
    }

    if (url.length > 2000) {
      return res.status(400).json({ error: 'URL is too long. Maximum 2000 characters.' });
    }

    const urlString = url.trim();

    // Run URL analyzer (local rule-based)
    const ruleResult = urlAnalyzer.analyzeUrl(urlString);

    // Try AI analysis
    let aiResult = null;
    if (geminiService.isAvailable()) {
      aiResult = await geminiService.analyzeUrl(urlString);
    }

    // Combine results
    const result = riskEngine.combineResults(aiResult, ruleResult, 'url');

    // Save to database
    saveScan(req.session.userId, 'url', urlString, result);

    res.json(result);
  } catch (err) {
    console.error('[Scan] URL scan error:', err);
    res.status(500).json({ error: 'An error occurred during URL analysis.' });
  }
});

/**
 * POST /api/scan/screenshot
 * Analyze a screenshot for scam indicators
 */
router.post('/screenshot', requireAuth, (req, res, next) => {
  const upload = req.app.get('upload');
  upload.single('screenshot')(req, res, async (err) => {
    if (err) {
      return res.status(400).json({ error: err.message || 'File upload failed.' });
    }

    try {
      if (!req.file) {
        return res.status(400).json({ error: 'Please upload a screenshot image.' });
      }

      const filePath = req.file.path;
      const mimeType = req.file.mimetype;

      try {
        // Read image buffer
        const imageBuffer = fs.readFileSync(filePath);

        let aiResult = null;
        let result;

        if (geminiService.isAvailable()) {
          // Use Gemini multimodal analysis
          aiResult = await geminiService.analyzeImage(imageBuffer, mimeType);
        }

        if (aiResult) {
          // Use AI result through risk engine (no rule engine for images)
          result = riskEngine.combineResults(aiResult, null, 'screenshot');
        } else {
          // AI unavailable — provide helpful fallback
          result = {
            riskLevel: 'MEDIUM',
            riskScore: 50,
            confidence: 20,
            reasons: [
              'AI image analysis is currently unavailable.',
              'Unable to analyze screenshot content without AI.',
              'For better results, try describing the screenshot content using the Message Scanner.'
            ],
            recommendation: 'AI analysis is currently unavailable. You can try describing the content of the screenshot in the Message Scanner for text-based analysis. Always verify suspicious messages through official channels.',
            analysisSource: 'Fallback (AI Unavailable)'
          };
        }

        // Save to database
        saveScan(req.session.userId, 'screenshot', `Image: ${req.file.originalname}`, result);

        res.json(result);
      } finally {
        // Clean up uploaded file
        try { fs.unlinkSync(filePath); } catch (e) { /* ignore cleanup errors */ }
      }
    } catch (err) {
      console.error('[Scan] Screenshot scan error:', err);
      res.status(500).json({ error: 'An error occurred during screenshot analysis.' });
    }
  });
});

/**
 * POST /api/scan/qr
 * Decode and analyze a QR code image
 */
router.post('/qr', requireAuth, (req, res, next) => {
  const upload = req.app.get('upload');
  upload.single('qrcode')(req, res, async (err) => {
    if (err) {
      return res.status(400).json({ error: err.message || 'File upload failed.' });
    }

    try {
      if (!req.file) {
        return res.status(400).json({ error: 'Please upload a QR code image.' });
      }

      const filePath = req.file.path;

      try {
        // Read image buffer
        const imageBuffer = fs.readFileSync(filePath);

        // Decode QR code
        const decoded = await qrDecoder.decodeQR(imageBuffer);

        if (!decoded.success) {
          return res.json({
            riskLevel: 'LOW',
            riskScore: 0,
            confidence: 30,
            reasons: [decoded.error || 'Could not decode QR code.'],
            recommendation: 'No QR code could be detected in the image. Please upload a clear image containing a QR code.',
            analysisSource: 'QR Decoder'
          });
        }

        // Analyze QR content
        const qrAnalysis = qrDecoder.analyzeQRContent(decoded.content, decoded.contentType);

        let result;

        if (decoded.contentType === 'url' || decoded.contentType === 'possible_url') {
          // If QR contains a URL, run URL analysis
          const urlContent = decoded.contentType === 'possible_url'
            ? 'https://' + decoded.content
            : decoded.content;

          const ruleResult = urlAnalyzer.analyzeUrl(urlContent);

          let aiResult = null;
          if (geminiService.isAvailable()) {
            aiResult = await geminiService.analyzeUrl(urlContent);
          }

          result = riskEngine.combineResults(aiResult, ruleResult, 'qr');

          // Prepend QR-specific info
          result.reasons = [
            `QR code decoded — contains URL: ${decoded.content.substring(0, 100)}`,
            ...result.reasons
          ];
        } else {
          // Non-URL QR content
          result = {
            riskLevel: riskEngine.getRiskLevel(qrAnalysis.score),
            riskScore: qrAnalysis.score,
            confidence: qrAnalysis.confidence,
            reasons: qrAnalysis.reasons,
            recommendation: qrAnalysis.recommendation,
            analysisSource: 'QR Decoder'
          };
        }

        // Save to database
        saveScan(req.session.userId, 'qr', `QR: ${decoded.content.substring(0, 200)}`, result);

        res.json(result);
      } finally {
        // Clean up uploaded file
        try { fs.unlinkSync(filePath); } catch (e) { /* ignore cleanup errors */ }
      }
    } catch (err) {
      console.error('[Scan] QR scan error:', err);
      res.status(500).json({ error: 'An error occurred during QR code analysis.' });
    }
  });
});

module.exports = router;
