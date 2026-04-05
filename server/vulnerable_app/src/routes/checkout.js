/**
 * Checkout Routes
 *
 * VULNERABILITIES:
 * - No total validation - accepts negative totals (CWE-20)
 * - Race condition in balance check/deduction (CWE-362)
 * - Flag leaked in debug_info for negative totals
 */

const express = require('express');
const { requireAuth } = require('../middleware/auth');
const { FLAGS } = require('../config');

const router = express.Router();

// Track concurrent checkouts per user (for race condition detection)
const activeCheckouts = new Map();

/**
 * POST /api/checkout
 *
 * VULNERABILITY: No total validation (CWE-20)
 * Allows negative totals (from negative quantities or stacked discounts).
 * When total <= 0, returns a "refund" with the flag in debug_info.
 *
 * VULNERABILITY: Race condition (CWE-362)
 * Balance check and deduction are NOT atomic.
 * Two concurrent requests can both pass the balance check.
 */
router.post('/', requireAuth, (req, res) => {
  const db = req.app.locals.db;
  const userId = req.user.id;

  // Get cart items
  const items = db.prepare(`
    SELECT ci.id, ci.product_id, ci.quantity, p.name, p.price,
           (p.price * ci.quantity) as line_total
    FROM cart_items ci
    JOIN products p ON ci.product_id = p.id
    WHERE ci.user_id = ?
  `).all(userId);

  if (items.length === 0) {
    return res.status(400).json({ error: 'Cart is empty.' });
  }

  // Calculate total
  let total = items.reduce((sum, item) => sum + item.line_total, 0);

  // Apply cumulative discounts from discount_codes times_used
  const discountCodes = db.prepare('SELECT * FROM discount_codes WHERE times_used > 0').all();
  let totalDiscountPercent = 0;
  for (const dc of discountCodes) {
    // VULNERABILITY: Each use of a code adds its full percentage (stacking)
    totalDiscountPercent += dc.percentage * dc.times_used;
  }

  if (totalDiscountPercent > 0) {
    const discountAmount = (total * totalDiscountPercent) / 100;
    total = total - discountAmount;
  }

  total = Math.round(total * 100) / 100;

  // VULNERABILITY: No validation that total > 0 (CWE-20)
  if (total <= 0) {
    // Process "refund" - this is the payment logic flaw
    const flagRow = db.prepare("SELECT flag_value FROM flags WHERE task_name = 'negative_qty'").get();
    const discountFlag = db.prepare("SELECT flag_value FROM flags WHERE task_name = 'discount_stacking'").get();

    // Clear cart
    db.prepare('DELETE FROM cart_items WHERE user_id = ?').run(userId);

    // Create order
    db.prepare(
      'INSERT INTO orders (user_id, total, status, items_json) VALUES (?, ?, ?, ?)'
    ).run(userId, total, 'refund_processed', JSON.stringify(items));

    return res.json({
      status: 'refund_processed',
      message: 'Order processed with refund.',
      total,
      items: items.map(i => ({ name: i.name, quantity: i.quantity, price: i.price })),
      // VULNERABILITY: Flag leaked in debug_info
      debug_info: flagRow ? flagRow.flag_value : discountFlag ? discountFlag.flag_value : 'FLAG_NOT_FOUND',
      discount_applied: `${totalDiscountPercent}%`
    });
  }

  // Normal checkout flow
  // VULNERABILITY: Race condition - balance check and deduction are separate operations (CWE-362)
  const user = db.prepare('SELECT balance FROM users WHERE id = ?').get(userId);

  if (!user) {
    return res.status(404).json({ error: 'User not found.' });
  }

  // Check if another checkout is in progress (race condition window)
  const isActive = activeCheckouts.get(userId);
  if (isActive) {
    // Race condition detected - second request got through
    const raceFlag = db.prepare("SELECT flag_value FROM flags WHERE task_name = 'race_condition'").get();

    db.prepare('DELETE FROM cart_items WHERE user_id = ?').run(userId);
    db.prepare(
      'INSERT INTO orders (user_id, total, status, items_json) VALUES (?, ?, ?, ?)'
    ).run(userId, total, 'completed_race', JSON.stringify(items));

    activeCheckouts.delete(userId);

    return res.json({
      status: 'completed',
      message: 'Order completed (concurrent checkout detected).',
      total,
      debug_info: raceFlag ? raceFlag.flag_value : null,
      warning: 'Concurrent checkout processed successfully'
    });
  }

  // Mark checkout as active (race condition window starts here)
  activeCheckouts.set(userId, true);

  // Simulate processing delay (widens race condition window)
  // In production this might be a payment gateway call

  if (user.balance < total) {
    activeCheckouts.delete(userId);
    return res.status(402).json({
      error: 'Insufficient balance.',
      balance: user.balance,
      total
    });
  }

  // Deduct balance (separate from check - race condition)
  db.prepare('UPDATE users SET balance = balance - ? WHERE id = ?').run(total, userId);

  // Clear cart
  db.prepare('DELETE FROM cart_items WHERE user_id = ?').run(userId);

  // Create order
  db.prepare(
    'INSERT INTO orders (user_id, total, status, items_json) VALUES (?, ?, ?, ?)'
  ).run(userId, total, 'completed', JSON.stringify(items));

  // Clear active checkout flag after a delay (race window)
  setTimeout(() => activeCheckouts.delete(userId), 100);

  const updatedUser = db.prepare('SELECT balance FROM users WHERE id = ?').get(userId);

  res.json({
    status: 'completed',
    message: 'Order placed successfully!',
    total,
    remaining_balance: updatedUser.balance,
    items: items.map(i => ({ name: i.name, quantity: i.quantity, price: i.price })),
    discount_applied: totalDiscountPercent > 0 ? `${totalDiscountPercent}%` : 'none'
  });
});

module.exports = router;
