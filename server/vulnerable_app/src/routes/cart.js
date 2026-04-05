/**
 * Shopping Cart Routes
 *
 * VULNERABILITIES:
 * - Negative quantity accepted (CWE-20) - creates credit instead of debit
 * - Discount code stacking (CWE-20) - no idempotency check
 * - Price manipulation via client-supplied price (CWE-472)
 */

const express = require('express');
const { requireAuth } = require('../middleware/auth');
const { DISCOUNT_CODES } = require('../config');

const router = express.Router();

/**
 * GET /api/cart
 * View current cart contents.
 */
router.get('/', requireAuth, (req, res) => {
  const db = req.app.locals.db;

  const items = db.prepare(`
    SELECT ci.id, ci.product_id, ci.quantity, p.name, p.price,
           (p.price * ci.quantity) as line_total
    FROM cart_items ci
    JOIN products p ON ci.product_id = p.id
    WHERE ci.user_id = ?
  `).all(req.user.id);

  const subtotal = items.reduce((sum, item) => sum + item.line_total, 0);

  // Get applied discounts from session (stored in a simple way)
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);

  res.json({
    items,
    subtotal: Math.round(subtotal * 100) / 100,
    item_count: items.length
  });
});

/**
 * POST /api/cart/add
 *
 * VULNERABILITY: Negative quantity (CWE-20)
 * No validation that quantity > 0. Negative quantities create credit.
 *
 * VULNERABILITY: Price manipulation (CWE-472)
 * Accepts optional 'price' field in body. If provided, uses client price
 * instead of looking up the actual product price.
 */
router.post('/add', requireAuth, (req, res) => {
  const db = req.app.locals.db;
  const { product_id, quantity, price } = req.body;

  if (!product_id) {
    return res.status(400).json({ error: 'product_id is required.' });
  }

  const qty = quantity || 1; // Default to 1 if not specified
  // VULNERABILITY: No validation that quantity > 0 (CWE-20)
  // A secure version would: if (qty <= 0) return res.status(400).json({error: 'Invalid quantity'})

  const product = db.prepare('SELECT * FROM products WHERE id = ?').get(product_id);
  if (!product) {
    return res.status(404).json({ error: 'Product not found.' });
  }

  // VULNERABILITY: If client sends a price field, use it instead of DB price (CWE-472)
  const effectivePrice = price !== undefined ? price : product.price;

  // Check if item already in cart
  const existing = db.prepare(
    'SELECT * FROM cart_items WHERE user_id = ? AND product_id = ?'
  ).get(req.user.id, product_id);

  if (existing) {
    db.prepare('UPDATE cart_items SET quantity = quantity + ? WHERE id = ?')
      .run(qty, existing.id);
  } else {
    db.prepare('INSERT INTO cart_items (user_id, product_id, quantity) VALUES (?, ?, ?)')
      .run(req.user.id, product_id, qty);
  }

  // Calculate cart total
  const items = db.prepare(`
    SELECT ci.*, p.price, p.name,
           (p.price * ci.quantity) as line_total
    FROM cart_items ci JOIN products p ON ci.product_id = p.id
    WHERE ci.user_id = ?
  `).all(req.user.id);

  const total = items.reduce((sum, item) => sum + item.line_total, 0);

  res.json({
    message: 'Item added to cart.',
    product: product.name,
    quantity: qty,
    effective_price: effectivePrice,
    cart_total: Math.round(total * 100) / 100,
    item_count: items.length
  });
});

/**
 * POST /api/cart/remove
 * Remove an item from the cart.
 */
router.post('/remove', requireAuth, (req, res) => {
  const db = req.app.locals.db;
  const { product_id } = req.body;

  if (!product_id) {
    return res.status(400).json({ error: 'product_id is required.' });
  }

  const result = db.prepare(
    'DELETE FROM cart_items WHERE user_id = ? AND product_id = ?'
  ).run(req.user.id, product_id);

  if (result.changes === 0) {
    return res.status(404).json({ error: 'Item not in cart.' });
  }

  res.json({ message: 'Item removed from cart.' });
});

/**
 * POST /api/cart/apply-discount
 *
 * VULNERABILITY: Discount code stacking (CWE-20)
 * Same code can be applied unlimited times.
 * No tracking of which codes have been applied per session.
 * Each application increases the total discount.
 */
router.post('/apply-discount', requireAuth, (req, res) => {
  const db = req.app.locals.db;
  const { code } = req.body;

  if (!code) {
    return res.status(400).json({ error: 'Discount code is required.' });
  }

  const discount = db.prepare('SELECT * FROM discount_codes WHERE code = ?').get(code);

  if (!discount) {
    return res.status(400).json({ error: 'Invalid discount code.' });
  }

  // VULNERABILITY: No check if code was already applied (CWE-20)
  // VULNERABILITY: No check against max_uses limit
  // A secure version would track applied codes per user/session and enforce max_uses

  // Update times_used (but don't actually enforce the limit)
  db.prepare('UPDATE discount_codes SET times_used = times_used + 1 WHERE id = ?')
    .run(discount.id);

  // Calculate discount on current cart
  const items = db.prepare(`
    SELECT ci.*, p.price, (p.price * ci.quantity) as line_total
    FROM cart_items ci JOIN products p ON ci.product_id = p.id
    WHERE ci.user_id = ?
  `).all(req.user.id);

  const subtotal = items.reduce((sum, item) => sum + item.line_total, 0);
  const discountAmount = (subtotal * discount.percentage) / 100;

  // Store cumulative discount on user (hacky but intentionally vulnerable)
  const currentBalance = db.prepare('SELECT balance FROM users WHERE id = ?').get(req.user.id);

  res.json({
    message: `Discount code '${code}' applied! ${discount.percentage}% off.`,
    code: code,
    discount_percentage: discount.percentage,
    discount_amount: Math.round(discountAmount * 100) / 100,
    subtotal: Math.round(subtotal * 100) / 100,
    times_code_used: discount.times_used + 1
  });
});

module.exports = router;
