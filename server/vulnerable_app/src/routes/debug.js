/**
 * Debug Routes
 *
 * VULNERABILITY: Information Leakage (CWE-200)
 * - Exposes process.env, config values, database path
 * - Returns flags directly
 * - No authentication required
 *
 * VULNERABILITY: Missing Security Headers (CWE-693)
 * - Endpoint to check which security headers are missing
 */

const express = require('express');
const { FLAGS, JWT_SECRET, ADMIN_API_KEY, STRIPE_SECRET_KEY, DEBUG_MODE, APP_NAME } = require('../config');

const router = express.Router();

/**
 * GET /api/debug/info
 *
 * VULNERABILITY: Debug information endpoint (CWE-200)
 * Exposes sensitive server information without any authentication.
 * In production, this should be removed entirely.
 */
router.get('/info', (req, res) => {
  const db = req.app.locals.db;

  // VULNERABILITY: All of this should never be exposed (CWE-200)
  res.json({
    application: APP_NAME,
    version: '1.0.0',
    debug_mode: DEBUG_MODE,
    server: {
      node_version: process.version,
      platform: process.platform,
      arch: process.arch,
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      pid: process.pid
    },
    database: {
      path: db.name,
      open: db.open,
      tables: db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map(t => t.name)
    },
    config: {
      jwt_secret: JWT_SECRET,
      admin_api_key: ADMIN_API_KEY,
      stripe_key: STRIPE_SECRET_KEY,
    },
    environment: {
      NODE_ENV: process.env.NODE_ENV || 'development',
      PATH: process.env.PATH ? process.env.PATH.substring(0, 200) + '...' : 'N/A'
    },
    flag: FLAGS.debug_info
  });
});

/**
 * GET /api/debug/headers
 *
 * VULNERABILITY: Missing Security Headers diagnostic (CWE-693)
 * Lists all the security headers that SHOULD be present but are NOT.
 */
router.get('/headers', (req, res) => {
  const securityHeaders = {
    'X-Frame-Options': 'DENY or SAMEORIGIN',
    'X-Content-Type-Options': 'nosniff',
    'X-XSS-Protection': '1; mode=block',
    'Content-Security-Policy': "default-src 'self'",
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()'
  };

  const missing = [];
  const present = [];

  for (const [header, recommended] of Object.entries(securityHeaders)) {
    // None of these are set (they're all missing)
    missing.push({
      header,
      recommended_value: recommended,
      status: 'MISSING'
    });
  }

  // Also check CORS headers
  const corsIssues = [
    {
      header: 'Access-Control-Allow-Origin',
      current_value: '*',
      issue: 'Wildcard origin allows any website to make requests',
      severity: 'HIGH'
    },
    {
      header: 'Access-Control-Allow-Credentials',
      current_value: 'true',
      issue: 'Combined with wildcard origin, this is a critical misconfiguration',
      severity: 'CRITICAL'
    }
  ];

  res.json({
    security_audit: {
      missing_headers: missing,
      cors_issues: corsIssues,
      total_issues: missing.length + corsIssues.length,
      risk_level: 'CRITICAL'
    },
    flag: FLAGS.missing_headers,
    recommendation: 'Add all missing security headers to improve application security.'
  });
});

/**
 * GET /api/debug/logs
 * View recent application logs including sensitive data.
 */
router.get('/logs', (req, res) => {
  const db = req.app.locals.db;

  const logs = db.prepare('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 20').all();

  res.json({
    logs,
    warning: 'Audit logs contain sensitive information including attempted passwords.'
  });
});

module.exports = router;
