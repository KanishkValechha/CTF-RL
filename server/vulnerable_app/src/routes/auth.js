/**
 * Authentication Routes
 *
 * VULNERABILITIES:
 * - SQL Injection in login (CWE-89) - string interpolation in SQL query
 * - Default admin credentials (CWE-1393)
 * - No rate limiting on login (CWE-307)
 * - Predictable password reset tokens (CWE-640)
 * - Plaintext password storage (CWE-256)
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const { JWT_SECRET, FLAGS } = require('../config');
const { setLastQuery } = require('../middleware/errorHandler');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

/**
 * POST /api/auth/register
 * Register a new user account.
 */
router.post('/register', (req, res) => {
  const db = req.app.locals.db;
  const { username, password, email } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  try {
    // Check if user exists (using parameterized query here - not everything is vulnerable)
    const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
    if (existing) {
      return res.status(409).json({ error: 'Username already exists.' });
    }

    // VULNERABILITY: Storing password in plaintext (CWE-256)
    const result = db.prepare(
      'INSERT INTO users (username, password, email, role, balance, is_admin) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(username, password, email || `${username}@example.com`, 'user', 100.0, 0);

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);

    // Generate JWT
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      message: 'Registration successful.',
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        balance: user.balance
      },
      token
    });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed.', details: err.message });
  }
});

/**
 * POST /api/auth/login
 *
 * VULNERABILITY: SQL Injection (CWE-89)
 * Uses string interpolation instead of parameterized queries.
 * Exploit: username = "' OR 1=1 --" bypasses authentication.
 *
 * VULNERABILITY: No rate limiting (CWE-307)
 * No lockout or rate limiting. Allows unlimited brute force attempts.
 */
router.post('/login', (req, res) => {
  const db = req.app.locals.db;
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  try {
    // VULNERABILITY: SQL Injection via string interpolation (CWE-89)
    // Secure version would use: db.prepare('SELECT * FROM users WHERE username = ? AND password = ?').get(username, password)
    const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
    setLastQuery(query);

    const user = db.prepare(query).get();

    if (!user) {
      // VULNERABILITY: Log failed attempt with password in audit log (CWE-532)
      try {
        db.prepare(
          'INSERT INTO audit_log (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)'
        ).run(null, 'login_failed', `Failed login for "${username}" with password: ${password}`, req.ip);
      } catch (e) { /* ignore logging errors */ }

      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Log successful login (leaking password in logs)
    try {
      db.prepare(
        'INSERT INTO audit_log (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)'
      ).run(user.id, 'login_success', `User ${user.username} logged in with password: ${user.password}`, req.ip);
    } catch (e) { /* ignore */ }

    // Set cookie as well (for session-based access)
    res.cookie('token', token, { httpOnly: false, secure: false }); // VULNERABILITY: insecure cookie settings

    res.json({
      message: 'Login successful.',
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        balance: user.balance
      },
      token,
      role: user.role
    });
  } catch (err) {
    // VULNERABILITY: Detailed error on SQL failure reveals query structure
    res.status(500).json({
      error: 'Login failed.',
      details: err.message,
      query_hint: 'Check SQL syntax near the login query'
    });
  }
});

/**
 * POST /api/auth/logout
 */
router.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out successfully.' });
});

/**
 * GET /api/auth/me
 * Get current user info.
 */
router.get('/me', requireAuth, (req, res) => {
  const db = req.app.locals.db;
  const user = db.prepare('SELECT id, username, email, role, balance FROM users WHERE id = ?').get(req.user.id);

  if (!user) {
    return res.status(404).json({ error: 'User not found.' });
  }

  res.json({ user });
});

/**
 * POST /api/auth/forgot-password
 *
 * VULNERABILITY: Predictable password reset token (CWE-640)
 * Token is generated from Date.now().toString(36) - easily predictable.
 */
router.post('/forgot-password', (req, res) => {
  const db = req.app.locals.db;
  const { username } = req.body;

  if (!username) {
    return res.status(400).json({ error: 'Username is required.' });
  }

  const user = db.prepare('SELECT id, username, email FROM users WHERE username = ?').get(username);
  if (!user) {
    return res.status(404).json({ error: 'User not found.' });
  }

  // VULNERABILITY: Predictable token generation (CWE-640)
  // A secure implementation would use crypto.randomBytes(32).toString('hex')
  const resetToken = Date.now().toString(36);
  const expiry = Date.now() + 3600000; // 1 hour

  db.prepare('UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE id = ?')
    .run(resetToken, expiry, user.id);

  // In a real app, this would be sent via email
  // VULNERABILITY: Token leaked in response (for testing purposes)
  res.json({
    message: 'Password reset token generated.',
    email_sent_to: user.email,
    // VULNERABILITY: Token exposed in response
    debug_token: resetToken,
    expires_at: new Date(expiry).toISOString()
  });
});

/**
 * POST /api/auth/reset-password
 *
 * Uses the predictable reset token to set a new password.
 */
router.post('/reset-password', (req, res) => {
  const db = req.app.locals.db;
  const { username, token, new_password } = req.body;

  if (!username || !token || !new_password) {
    return res.status(400).json({ error: 'Username, token, and new_password are required.' });
  }

  const user = db.prepare('SELECT * FROM users WHERE username = ? AND reset_token = ?').get(username, token);

  if (!user) {
    return res.status(400).json({ error: 'Invalid reset token.' });
  }

  if (user.reset_token_expiry && Date.now() > user.reset_token_expiry) {
    return res.status(400).json({ error: 'Reset token has expired.' });
  }

  // Update password (still plaintext)
  db.prepare('UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?')
    .run(new_password, user.id);

  // If admin password was reset, reveal the flag
  let flag = null;
  if (user.role === 'admin') {
    flag = FLAGS.predictable_reset;
  }

  res.json({
    message: 'Password reset successful.',
    flag: flag
  });
});

module.exports = router;
