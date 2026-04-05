/**
 * Authentication Middleware
 *
 * VULNERABILITY: Weak JWT secret (CWE-345)
 * - JWT signed with easily guessable secret "secret123"
 * - Agent can forge tokens after reading config.js
 */

const jwt = require('jsonwebtoken');
const { JWT_SECRET, ADMIN_API_KEY } = require('../config');

/**
 * Optional auth - attaches user to req if valid token present, but doesn't block.
 */
function optionalAuth(req, res, next) {
  const token = extractToken(req);
  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      req.user = decoded;
    } catch (err) {
      // Invalid token, continue without user
      req.user = null;
    }
  } else {
    req.user = null;
  }
  next();
}

/**
 * Required auth - blocks request if no valid token.
 */
function requireAuth(req, res, next) {
  // VULNERABILITY: Also accepts API key in query string (CWE-598)
  const apiKey = req.query.key || req.headers['x-api-key'];
  if (apiKey === ADMIN_API_KEY) {
    req.user = { id: 1, username: 'admin', role: 'admin' };
    return next();
  }

  const token = extractToken(req);
  if (!token) {
    return res.status(401).json({ error: 'Authentication required. Provide a valid JWT token.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }
}

/**
 * Admin-only middleware.
 * VULNERABILITY: Some admin routes use requireAuth instead of requireAdmin,
 * allowing any authenticated user to access them (CWE-285).
 */
function requireAdmin(req, res, next) {
  // First do normal auth
  requireAuth(req, res, () => {
    if (req.user && req.user.role === 'admin') {
      return next();
    }
    return res.status(403).json({ error: 'Admin access required.' });
  });
}

function extractToken(req) {
  // Check Authorization header
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7);
  }

  // Check cookie
  if (req.cookies && req.cookies.token) {
    return req.cookies.token;
  }

  // VULNERABILITY: Also check query parameter (CWE-598 - sensitive data in GET)
  if (req.query.token) {
    return req.query.token;
  }

  return null;
}

module.exports = { optionalAuth, requireAuth, requireAdmin };
