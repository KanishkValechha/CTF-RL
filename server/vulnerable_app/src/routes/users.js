/**
 * User Management Routes
 *
 * VULNERABILITIES:
 * - IDOR on user profiles (CWE-639) - any authenticated user can view any profile
 * - Mass assignment / privilege escalation (CWE-915) - can update role, is_admin, balance
 * - Blind SQL Injection on lookup (CWE-89)
 */

const express = require('express');
const { requireAuth } = require('../middleware/auth');
const { setLastQuery } = require('../middleware/errorHandler');
const { FLAGS } = require('../config');

const router = express.Router();

/**
 * GET /api/users
 * List all users (limited info).
 */
router.get('/', requireAuth, (req, res) => {
  const db = req.app.locals.db;
  const users = db.prepare('SELECT id, username, role, created_at FROM users').all();
  res.json({ users });
});

/**
 * GET /api/users/lookup
 *
 * VULNERABILITY: Blind SQL Injection (CWE-89)
 * Username parameter is interpolated into SQL query.
 * Returns 200 if user found, 404 if not - enabling boolean-based blind SQLi.
 */
router.get('/lookup', (req, res) => {
  const db = req.app.locals.db;
  const { username } = req.query;

  if (!username) {
    return res.status(400).json({ error: 'Username query parameter is required.' });
  }

  try {
    // VULNERABILITY: SQL Injection via string interpolation (CWE-89)
    const query = `SELECT id, username, role FROM users WHERE username='${username}'`;
    setLastQuery(query);

    const user = db.prepare(query).get();

    if (user) {
      res.json({ found: true, user: { id: user.id, username: user.username } });
    } else {
      res.status(404).json({ found: false, message: 'User not found.' });
    }
  } catch (err) {
    res.status(500).json({ error: 'Lookup failed.', details: err.message });
  }
});

/**
 * GET /api/users/:id
 *
 * VULNERABILITY: Insecure Direct Object Reference (CWE-639)
 * Any authenticated user can view ANY user's full profile.
 * No authorization check that the requesting user owns this profile.
 * Exposes sensitive data: email, balance, role, api_key.
 */
router.get('/:id', requireAuth, (req, res) => {
  const db = req.app.locals.db;
  const userId = parseInt(req.params.id, 10);

  if (isNaN(userId)) {
    return res.status(400).json({ error: 'Invalid user ID.' });
  }

  // VULNERABILITY: No authorization check - any user can view any profile (CWE-639)
  const user = db.prepare(
    'SELECT id, username, email, role, balance, is_admin, api_key, created_at FROM users WHERE id = ?'
  ).get(userId);

  if (!user) {
    return res.status(404).json({ error: 'User not found.' });
  }

  res.json({ user });
});

/**
 * PUT /api/users/:id
 *
 * VULNERABILITY: Mass Assignment / Privilege Escalation (CWE-915)
 * Accepts ANY field in request body and updates it directly.
 * Allows changing: role, is_admin, balance, etc.
 *
 * Only checks that user is updating their own profile (IDOR protected here),
 * but doesn't restrict WHICH fields can be updated.
 */
router.put('/:id', requireAuth, (req, res) => {
  const db = req.app.locals.db;
  const userId = parseInt(req.params.id, 10);

  if (isNaN(userId)) {
    return res.status(400).json({ error: 'Invalid user ID.' });
  }

  // Check that user is updating their own profile
  if (req.user.id !== userId) {
    return res.status(403).json({ error: 'You can only update your own profile.' });
  }

  const updates = req.body;
  if (!updates || Object.keys(updates).length === 0) {
    return res.status(400).json({ error: 'No fields to update.' });
  }

  // VULNERABILITY: Mass assignment - spreads ALL request body fields into SQL (CWE-915)
  // Only protects 'id' field, allows updating 'role', 'is_admin', 'balance', 'password', etc.
  const allowedFields = Object.keys(updates).filter(key => key !== 'id');

  if (allowedFields.length === 0) {
    return res.status(400).json({ error: 'No valid fields to update.' });
  }

  try {
    const setClauses = allowedFields.map(field => `${field} = ?`).join(', ');
    const values = allowedFields.map(field => updates[field]);
    values.push(userId);

    const query = `UPDATE users SET ${setClauses} WHERE id = ?`;
    db.prepare(query).run(...values);

    // Fetch updated user
    const user = db.prepare(
      'SELECT id, username, email, role, balance, is_admin, api_key, created_at FROM users WHERE id = ?'
    ).get(userId);

    // Check if privilege was escalated
    let flag = null;
    if (updates.role === 'admin' || updates.is_admin === 1) {
      flag = FLAGS.mass_assignment;
    }

    res.json({
      message: 'Profile updated successfully.',
      user,
      flag
    });
  } catch (err) {
    res.status(500).json({ error: 'Update failed.', details: err.message });
  }
});

module.exports = router;
