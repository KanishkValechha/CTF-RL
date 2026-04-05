/**
 * Import Routes
 *
 * VULNERABILITY: Insecure Deserialization / Code Execution (CWE-502)
 * - User-supplied data decoded and passed to eval()
 * - Allows arbitrary code execution on the server
 */

const express = require('express');
const { requireAuth } = require('../middleware/auth');
const { FLAGS } = require('../config');

const router = express.Router();

/**
 * POST /api/import
 *
 * VULNERABILITY: Insecure Deserialization via eval() (CWE-502)
 * Accepts base64-encoded data and evaluates it as JavaScript.
 * Intended for "data import" but allows arbitrary code execution.
 *
 * Exploit: Encode require('fs').readFileSync('flag.txt','utf8') as base64
 * Send: { "data": "<base64 encoded JS code>" }
 * Result is returned in the response.
 */
router.post('/', requireAuth, (req, res) => {
  const { data, format } = req.body;

  if (!data) {
    return res.status(400).json({
      error: 'data field is required.',
      usage: 'Send base64-encoded data in the "data" field.',
      supported_formats: ['json', 'csv', 'custom']
    });
  }

  try {
    // Decode base64 data
    const decoded = Buffer.from(data, 'base64').toString('utf8');

    let result;

    if (format === 'json') {
      // Try parsing as JSON first
      try {
        result = JSON.parse(decoded);
      } catch (e) {
        // VULNERABILITY: Fall through to eval if JSON parse fails
        result = eval(decoded); // eslint-disable-line no-eval
      }
    } else {
      // VULNERABILITY: Direct eval of user-supplied code (CWE-502)
      // Secure version would: parse data safely, use JSON.parse, validate schema
      result = eval(decoded); // eslint-disable-line no-eval
    }

    res.json({
      status: 'import_completed',
      format: format || 'auto',
      result: typeof result === 'object' ? result : String(result),
      records_processed: typeof result === 'object' && Array.isArray(result) ? result.length : 1
    });
  } catch (err) {
    res.status(500).json({
      error: 'Import failed.',
      details: err.message,
      // VULNERABILITY: Stack trace leaked
      stack: err.stack
    });
  }
});

module.exports = router;
