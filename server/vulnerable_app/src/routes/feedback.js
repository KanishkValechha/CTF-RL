/**
 * Feedback Routes
 *
 * VULNERABILITY: Server-Side Template Injection (CWE-1336)
 * - User input passed directly to EJS template engine
 * - Template context contains the flag
 */

const express = require('express');
const ejs = require('ejs');
const { FLAGS } = require('../config');

const router = express.Router();

/**
 * POST /api/feedback
 *
 * VULNERABILITY: Server-Side Template Injection (CWE-1336)
 * The 'name' field is concatenated into an EJS template string
 * and rendered server-side. The template context includes the flag.
 *
 * Exploit: name = "<%= flag %>" extracts the flag from template context
 * Exploit: name = "<%- flag %>" also works (unescaped output)
 */
router.post('/', (req, res) => {
  const { name, message, email } = req.body;

  if (!name || !message) {
    return res.status(400).json({ error: 'name and message are required.' });
  }

  try {
    // VULNERABILITY: User input directly in template string (CWE-1336)
    // Secure version would: use parameterized templates, never concatenate user input
    const template = `Thank you for your feedback, ${name}! We received your message: "${message}"`;

    // Render the template with flag in context
    const rendered = ejs.render(template, {
      flag: FLAGS.ssti,
      secret: 'internal_secret_value',
      admin_password: 'admin123'
    });

    res.json({
      status: 'feedback_received',
      response: rendered,
      email_confirmation: email || 'no email provided'
    });
  } catch (err) {
    // VULNERABILITY: Template error details leaked
    res.status(500).json({
      error: 'Failed to process feedback.',
      details: err.message,
      template_error: true
    });
  }
});

module.exports = router;
