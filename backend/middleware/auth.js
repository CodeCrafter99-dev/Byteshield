/**
 * ByteShield Authentication Middleware
 * Checks if user is authenticated via session
 */

function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'Authentication required. Please log in.' });
  }
  next();
}

module.exports = { requireAuth };
