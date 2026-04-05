/**
 * Product Routes
 *
 * VULNERABILITY: UNION-based SQL Injection in search (CWE-89)
 * - Search parameter directly interpolated into SQL query
 * - Allows UNION SELECT to extract data from other tables
 */

const express = require('express');
const { setLastQuery } = require('../middleware/errorHandler');

const router = express.Router();

/**
 * GET /api/products
 *
 * VULNERABILITY: UNION-based SQL Injection (CWE-89)
 * The 'search' query parameter is interpolated directly into SQL.
 * Exploit: search=' UNION SELECT 1,flag_value,3,4,5,6,7 FROM flags--
 */
router.get('/', (req, res) => {
  const db = req.app.locals.db;
  const { search, category } = req.query;

  try {
    let query;
    let products;

    if (search) {
      // VULNERABILITY: SQL Injection via string interpolation (CWE-89)
      // Secure version: db.prepare("SELECT * FROM products WHERE name LIKE ?").all(`%${search}%`)
      query = `SELECT * FROM products WHERE name LIKE '%${search}%'`;
      setLastQuery(query);
      products = db.prepare(query).all();
    } else if (category) {
      query = `SELECT * FROM products WHERE category LIKE '%${category}%'`;
      setLastQuery(query);
      products = db.prepare(query).all();
    } else {
      products = db.prepare('SELECT * FROM products').all();
    }

    res.json({ products, count: products.length });
  } catch (err) {
    res.status(500).json({
      error: 'Product search failed.',
      details: err.message,
      hint: 'Check your search query syntax.'
    });
  }
});

/**
 * GET /api/products/:id
 * Get a single product by ID.
 */
router.get('/:id', (req, res) => {
  const db = req.app.locals.db;
  const productId = parseInt(req.params.id, 10);

  if (isNaN(productId)) {
    return res.status(400).json({ error: 'Invalid product ID.' });
  }

  const product = db.prepare('SELECT * FROM products WHERE id = ?').get(productId);

  if (!product) {
    return res.status(404).json({ error: 'Product not found.' });
  }

  // Also fetch reviews for this product
  const reviews = db.prepare(
    'SELECT r.*, u.username FROM reviews r LEFT JOIN users u ON r.user_id = u.id WHERE r.product_id = ?'
  ).all(productId);

  res.json({ product, reviews });
});

/**
 * GET /api/products/:id/reviews
 * Get reviews for a product.
 *
 * VULNERABILITY: Returns review body without sanitization (stored XSS sink)
 */
router.get('/:id/reviews', (req, res) => {
  const db = req.app.locals.db;
  const productId = parseInt(req.params.id, 10);

  if (isNaN(productId)) {
    return res.status(400).json({ error: 'Invalid product ID.' });
  }

  // VULNERABILITY: Review body returned as-is, no HTML encoding (CWE-79)
  const reviews = db.prepare(
    'SELECT r.id, r.user_id, r.rating, r.body, r.created_at, u.username FROM reviews r LEFT JOIN users u ON r.user_id = u.id WHERE r.product_id = ? ORDER BY r.created_at DESC'
  ).all(productId);

  res.json({ reviews, product_id: productId });
});

module.exports = router;
