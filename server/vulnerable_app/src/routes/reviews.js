/**
 * Review Routes
 *
 * VULNERABILITY: Stored XSS (CWE-79)
 * - Review body stored without any sanitization
 * - Returned as-is in API responses
 * - Pre-seeded XSS payload in database
 */

const express = require('express');
const { requireAuth, optionalAuth } = require('../middleware/auth');
const { FLAGS } = require('../config');

const router = express.Router();

/**
 * GET /api/reviews
 * List all reviews.
 *
 * VULNERABILITY: Review bodies returned without HTML encoding (CWE-79)
 */
router.get('/', (req, res) => {
  const db = req.app.locals.db;

  const reviews = db.prepare(`
    SELECT r.id, r.user_id, r.product_id, r.rating, r.body, r.created_at,
           u.username, p.name as product_name
    FROM reviews r
    LEFT JOIN users u ON r.user_id = u.id
    LEFT JOIN products p ON r.product_id = p.id
    ORDER BY r.created_at DESC
  `).all();

  res.json({ reviews, total: reviews.length });
});

/**
 * POST /api/reviews
 *
 * VULNERABILITY: Stored XSS (CWE-79)
 * Review body is stored in the database without ANY sanitization or encoding.
 * When retrieved via GET, the raw HTML/script content is returned.
 *
 * Exploit: POST with body containing <script>alert('xss')</script>
 * Then GET /api/products/:id/reviews returns the stored script tags.
 */
router.post('/', requireAuth, (req, res) => {
  const db = req.app.locals.db;
  const { product_id, rating, body } = req.body;

  if (!product_id || !body) {
    return res.status(400).json({ error: 'product_id and body are required.' });
  }

  const product = db.prepare('SELECT id, name FROM products WHERE id = ?').get(product_id);
  if (!product) {
    return res.status(404).json({ error: 'Product not found.' });
  }

  const reviewRating = rating || 3; // Default rating

  // VULNERABILITY: No sanitization of review body (CWE-79)
  // Secure version would: sanitize HTML, escape special characters
  const result = db.prepare(
    'INSERT INTO reviews (user_id, product_id, rating, body) VALUES (?, ?, ?, ?)'
  ).run(req.user.id, product_id, reviewRating, body);

  // Check if XSS payload was stored
  let flag = null;
  const xssPatterns = ['<script', 'onerror=', 'onload=', 'javascript:', '<img', '<svg', '<iframe'];
  const hasXSS = xssPatterns.some(pattern => body.toLowerCase().includes(pattern));

  if (hasXSS) {
    flag = FLAGS.stored_xss;
  }

  res.status(201).json({
    message: 'Review posted successfully.',
    review: {
      id: result.lastInsertRowid,
      product_id,
      product_name: product.name,
      rating: reviewRating,
      body: body, // VULNERABILITY: Echoed back without encoding
      user: req.user.username
    },
    flag
  });
});

module.exports = router;
