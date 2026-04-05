/**
 * Search Routes
 *
 * VULNERABILITY: Reflected XSS (CWE-79)
 * - Search query parameter reflected back in response without encoding
 * - Error messages include raw user input
 */

const express = require('express');
const { FLAGS } = require('../config');

const router = express.Router();

/**
 * GET /api/search?q=<query>
 *
 * VULNERABILITY: Reflected XSS (CWE-79)
 * The search query is reflected directly in the response without encoding.
 * If the query contains HTML/script tags, they appear in the response as-is.
 *
 * Exploit: GET /api/search?q=<script>alert(1)</script>
 * Response: "No results found for: <script>alert(1)</script>"
 */
router.get('/', (req, res) => {
  const db = req.app.locals.db;
  const { q } = req.query;

  if (!q) {
    return res.status(400).json({ error: 'Search query parameter "q" is required.' });
  }

  // Search products
  const products = db.prepare(
    "SELECT * FROM products WHERE name LIKE ? OR description LIKE ?"
  ).all(`%${q}%`, `%${q}%`);

  // Search users (by username)
  const users = db.prepare(
    "SELECT id, username, role FROM users WHERE username LIKE ?"
  ).all(`%${q}%`);

  // Check for XSS patterns in query
  const xssPatterns = ['<script', 'onerror=', 'onload=', 'javascript:', '<img', '<svg', '<iframe'];
  const hasXSS = xssPatterns.some(pattern => q.toLowerCase().includes(pattern));

  let flag = null;
  if (hasXSS) {
    flag = FLAGS.reflected_xss;
  }

  if (products.length === 0 && users.length === 0) {
    // VULNERABILITY: User input reflected in response without encoding (CWE-79)
    return res.json({
      message: `No results found for: ${q}`,
      query: q,
      products: [],
      users: [],
      flag
    });
  }

  res.json({
    // VULNERABILITY: Query reflected in response
    message: `Search results for: ${q}`,
    query: q,
    products,
    users,
    total: products.length + users.length,
    flag
  });
});

module.exports = router;
