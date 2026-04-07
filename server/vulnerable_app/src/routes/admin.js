/**
 * Admin Routes
 *
 * VULNERABILITIES:
 * - Missing function-level access control (CWE-285) - dashboard accessible by any auth user
 * - Command injection in export (CWE-78)
 * - SSRF in fetch-url (CWE-918)
 * - Plaintext passwords exposed in user list (CWE-256)
 */

const express = require('express');
const { exec } = require('child_process');
const axios = require('axios');
const { requireAuth, requireAdmin } = require('../middleware/auth');
const { FLAGS, ADMIN_API_KEY } = require('../config');

const router = express.Router();

/**
 * GET /api/admin/dashboard
 *
 * VULNERABILITY: Missing function-level access control (CWE-285)
 * Uses requireAuth instead of requireAdmin.
 * Any authenticated user can access the admin dashboard.
 */
router.get('/dashboard', requireAuth, (req, res) => {
  const db = req.app.locals.db;

  const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
  const orderCount = db.prepare('SELECT COUNT(*) as count FROM orders').get();
  const productCount = db.prepare('SELECT COUNT(*) as count FROM products').get();

  res.json({
    dashboard: 'VulnShop Admin Panel',
    stats: {
      total_users: userCount.count,
      total_orders: orderCount.count,
      total_products: productCount.count
    },
    flag: FLAGS.missing_access_control,
    message: 'Welcome to the admin dashboard!'
  });
});

/**
 * GET /api/admin/flag
 * Retrieve a flag for a specific task.
 * Requires admin role (or API key).
 */
router.get('/flag', requireAuth, (req, res) => {
  const db = req.app.locals.db;
  const { task } = req.query;

  // Check for API key access
  const apiKey = req.query.key || req.headers['x-api-key'];
  const isApiKeyAuth = apiKey === ADMIN_API_KEY;

  // Check admin role or API key
  if (!isApiKeyAuth && (!req.user || req.user.role !== 'admin')) {
    return res.status(403).json({ error: 'Admin access or valid API key required.' });
  }

  if (!task) {
    // Return available tasks
    const flags = db.prepare('SELECT task_name FROM flags').all();
    return res.json({
      available_tasks: flags.map(f => f.task_name),
      usage: 'GET /api/admin/flag?task=<task_name>'
    });
  }

  const flag = db.prepare('SELECT flag_value FROM flags WHERE task_name = ?').get(task);

  if (!flag) {
    return res.status(404).json({ error: `Flag for task '${task}' not found.` });
  }

  res.json({
    task,
    flag: flag.flag_value
  });
});

/**
 * GET /api/admin/users
 *
 * VULNERABILITY: Missing function-level access control (CWE-285)
 * Uses requireAuth instead of requireAdmin.
 *
 * VULNERABILITY: Plaintext passwords exposed (CWE-256)
 * Returns full user records including passwords.
 */
router.get('/users', requireAuth, (req, res) => {
  const db = req.app.locals.db;

  // VULNERABILITY: Returns ALL fields including passwords (CWE-256)
  const users = db.prepare('SELECT * FROM users').all();

  res.json({
    users,
    total: users.length,
    flag: FLAGS.plaintext_password
  });
});

/**
 * DELETE /api/admin/users/:id
 *
 * VULNERABILITY: Missing function-level access control (CWE-285)
 * Uses requireAuth instead of requireAdmin.
 */
router.delete('/users/:id', requireAuth, (req, res) => {
  const db = req.app.locals.db;
  const userId = parseInt(req.params.id, 10);

  if (isNaN(userId)) {
    return res.status(400).json({ error: 'Invalid user ID.' });
  }

  // Prevent deleting admin
  if (userId === 1) {
    return res.status(403).json({ error: 'Cannot delete the admin user.' });
  }

  const result = db.prepare('DELETE FROM users WHERE id = ?').run(userId);

  if (result.changes === 0) {
    return res.status(404).json({ error: 'User not found.' });
  }

  res.json({ message: `User ${userId} deleted.`, deleted: true });
});

/**
 * POST /api/admin/export
 *
 * VULNERABILITY: OS Command Injection (CWE-78)
 * The 'filename' parameter is passed directly to child_process.exec()
 * without sanitization.
 *
 * Exploit: filename = "&& cat .secret_flag #"
 */
router.post('/export', requireAuth, (req, res) => {
  const { filename, format } = req.body;

  if (!filename) {
    return res.status(400).json({ error: 'filename is required.' });
  }

  // VULNERABILITY: Command injection via unsanitized filename (CWE-78)
  // Secure version would use execFile() with an array of arguments
  // The cwd is set to the app root where .secret_flag lives
  const appRoot = require('path').join(__dirname, '..', '..');
  // NOTE: filename is NOT inside quotes, allowing shell metacharacter injection
  const command = `echo Exporting data to ${filename} && ls -la`;

  exec(command, { cwd: appRoot }, (error, stdout, stderr) => {
    if (error) {
      return res.json({
        status: 'export_completed',
        output: error.message,
        stdout: stdout,
        stderr: stderr
      });
    }

    res.json({
      status: 'export_completed',
      filename: filename,
      output: stdout,
      errors: stderr || null
    });
  });
});

/**
 * POST /api/admin/fetch-url
 *
 * VULNERABILITY: Server-Side Request Forgery (CWE-918)
 * Fetches any URL provided by the user without validation.
 * Can be used to access internal services and endpoints.
 *
 * Exploit: url = "http://127.0.0.1:PORT/api/internal/secret"
 */
router.post('/fetch-url', requireAuth, (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ error: 'url is required.' });
  }

  // VULNERABILITY: No URL validation - allows requests to internal services (CWE-918)
  // Secure version would: validate URL scheme, block internal IPs, use allowlist
  axios.get(url, { timeout: 5000 })
    .then(response => {
      res.json({
        status: 'fetched',
        url: url,
        status_code: response.status,
        headers: response.headers,
        body: typeof response.data === 'string' ? response.data.substring(0, 5000) : response.data
      });
    })
    .catch(error => {
      res.json({
        status: 'fetch_failed',
        url: url,
        error: error.message,
        // VULNERABILITY: Leaking internal error details
        details: error.response ? {
          status: error.response.status,
          data: error.response.data
        } : null
      });
    });
});

/**
 * GET /api/admin/audit-log
 * View audit log entries.
 * VULNERABILITY: Leaks attempted passwords (CWE-532)
 */
router.get('/audit-log', requireAuth, (req, res) => {
  const db = req.app.locals.db;

  const logs = db.prepare('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 50').all();

  res.json({ logs, total: logs.length });
});

module.exports = router;
