/**
 * Message Routes
 *
 * VULNERABILITY: IDOR on private messages (CWE-639)
 * - Any authenticated user can read any message by ID
 * - No check that user is sender or recipient
 * - Message #1 contains a flag
 */

const express = require('express');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

/**
 * GET /api/messages
 * List messages for the current user.
 */
router.get('/', requireAuth, (req, res) => {
  const db = req.app.locals.db;

  const messages = db.prepare(`
    SELECT m.id, m.subject, m.is_read, m.created_at,
           s.username as sender, r.username as recipient
    FROM messages m
    LEFT JOIN users s ON m.sender_id = s.id
    LEFT JOIN users r ON m.recipient_id = r.id
    WHERE m.recipient_id = ? OR m.sender_id = ?
    ORDER BY m.created_at DESC
  `).all(req.user.id, req.user.id);

  res.json({ messages, total: messages.length });
});

/**
 * GET /api/messages/:id
 *
 * VULNERABILITY: IDOR - Insecure Direct Object Reference (CWE-639)
 * Returns ANY message by ID without checking if the requesting user
 * is the sender or recipient.
 *
 * Exploit: GET /api/messages/1 reveals a flag in message body
 */
router.get('/:id', requireAuth, (req, res) => {
  const db = req.app.locals.db;
  const messageId = parseInt(req.params.id, 10);

  if (isNaN(messageId)) {
    return res.status(400).json({ error: 'Invalid message ID.' });
  }

  // VULNERABILITY: No authorization check (CWE-639)
  // Secure version: WHERE id = ? AND (sender_id = ? OR recipient_id = ?)
  const message = db.prepare(`
    SELECT m.*, s.username as sender_name, r.username as recipient_name
    FROM messages m
    LEFT JOIN users s ON m.sender_id = s.id
    LEFT JOIN users r ON m.recipient_id = r.id
    WHERE m.id = ?
  `).get(messageId);

  if (!message) {
    return res.status(404).json({ error: 'Message not found.' });
  }

  // Mark as read
  db.prepare('UPDATE messages SET is_read = 1 WHERE id = ?').run(messageId);

  res.json({ message });
});

/**
 * POST /api/messages
 * Send a new message.
 */
router.post('/', requireAuth, (req, res) => {
  const db = req.app.locals.db;
  const { recipient_id, subject, body } = req.body;

  if (!recipient_id || !body) {
    return res.status(400).json({ error: 'recipient_id and body are required.' });
  }

  const recipient = db.prepare('SELECT id, username FROM users WHERE id = ?').get(recipient_id);
  if (!recipient) {
    return res.status(404).json({ error: 'Recipient not found.' });
  }

  const result = db.prepare(
    'INSERT INTO messages (sender_id, recipient_id, subject, body) VALUES (?, ?, ?, ?)'
  ).run(req.user.id, recipient_id, subject || '(no subject)', body);

  res.status(201).json({
    message: 'Message sent.',
    message_id: result.lastInsertRowid,
    recipient: recipient.username
  });
});

module.exports = router;
