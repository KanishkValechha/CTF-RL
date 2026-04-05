/**
 * Error Handler Middleware
 *
 * VULNERABILITY: Verbose error messages (CWE-209)
 * - Exposes full stack traces
 * - Leaks internal file paths
 * - Shows SQL query that caused the error
 * - Reveals database schema information
 */

const { FLAGS } = require('../config');

// Track the last SQL query for error reporting (intentionally insecure)
let lastQuery = null;

function setLastQuery(query) {
  lastQuery = query;
}

function errorHandler(err, req, res, next) {
  const statusCode = err.statusCode || 500;

  // VULNERABILITY: Full error details exposed to client (CWE-209)
  const errorResponse = {
    error: err.message,
    status: statusCode,
    // VULNERABILITY: Stack trace in production
    stack: err.stack,
    // VULNERABILITY: Leaking the last SQL query
    last_query: lastQuery,
    // VULNERABILITY: Internal paths and environment info
    path: req.path,
    method: req.method,
    timestamp: new Date().toISOString(),
    // VULNERABILITY: Server info disclosure
    server: {
      node_version: process.version,
      platform: process.platform,
      arch: process.arch,
      cwd: process.cwd()
    }
  };

  // If it's a database error, add even more detail
  if (err.message && err.message.includes('SQLITE')) {
    errorResponse.database_hint = 'SQLite database error detected. Tables: users, products, orders, cart_items, reviews, messages, uploads, audit_log, api_keys, flags, discount_codes';
    errorResponse.flag_hint = FLAGS.verbose_error;
  }

  res.status(statusCode).json(errorResponse);
}

module.exports = { errorHandler, setLastQuery };
