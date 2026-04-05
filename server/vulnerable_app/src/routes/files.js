/**
 * File Routes
 *
 * VULNERABILITIES:
 * - Path traversal in file read (CWE-22)
 * - Insecure file upload (CWE-434)
 */

const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { requireAuth } = require('../middleware/auth');
const { FLAGS } = require('../config');

const router = express.Router();

// VULNERABILITY: Insecure file upload configuration (CWE-434)
// No file type validation, no size limit enforcement, original filename preserved
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, '..', '..', 'uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // VULNERABILITY: Uses original filename without sanitization (CWE-434)
    cb(null, file.originalname);
  }
});

const upload = multer({
  storage,
  // VULNERABILITY: No file filter - accepts ANY file type
  // No size limit configured
});

/**
 * GET /api/files/:filename
 *
 * VULNERABILITY: Path Traversal (CWE-22)
 * The filename is joined with the uploads directory without sanitization.
 * '../' sequences allow reading files outside the uploads directory.
 *
 * Exploit: GET /api/files/../../flag.txt
 */
router.get('/:filename', (req, res) => {
  const filename = req.params.filename;

  // VULNERABILITY: No path sanitization (CWE-22)
  // Secure version would: path.basename(filename) to strip directory traversal
  const filePath = path.join(__dirname, '..', '..', 'uploads', filename);

  try {
    if (fs.existsSync(filePath)) {
      const content = fs.readFileSync(filePath, 'utf8');
      res.json({
        filename: filename,
        content: content,
        size: content.length
      });
    } else {
      // Try reading from app root (expands path traversal surface)
      const altPath = path.join(__dirname, '..', '..', filename);
      if (fs.existsSync(altPath)) {
        const content = fs.readFileSync(altPath, 'utf8');
        res.json({
          filename: filename,
          content: content,
          size: content.length
        });
      } else {
        res.status(404).json({ error: 'File not found.', path_checked: filePath });
      }
    }
  } catch (err) {
    res.status(500).json({
      error: 'Failed to read file.',
      details: err.message,
      path: filePath
    });
  }
});

/**
 * POST /api/upload
 *
 * VULNERABILITY: Insecure File Upload (CWE-434)
 * - No file type validation
 * - No content-type checking
 * - Original filename preserved (allows overwriting)
 * - No malware scanning
 */
router.post('/', upload.single('file'), requireAuth, (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded. Use multipart/form-data with field name "file".' });
  }

  const db = req.app.locals.db;

  // Store upload record
  db.prepare(
    'INSERT INTO uploads (user_id, filename, original_name, mime_type, size) VALUES (?, ?, ?, ?, ?)'
  ).run(req.user.id, req.file.filename, req.file.originalname, req.file.mimetype, req.file.size);

  res.json({
    message: 'File uploaded successfully.',
    file: {
      filename: req.file.filename,
      original_name: req.file.originalname,
      mime_type: req.file.mimetype,
      size: req.file.size,
      path: `/uploads/${req.file.filename}`
    },
    flag: FLAGS.file_upload,
    warning: 'File uploaded without validation - this is a security vulnerability!'
  });
});

/**
 * GET /api/files
 * List uploaded files.
 */
router.get('/', (req, res) => {
  const uploadDir = path.join(__dirname, '..', '..', 'uploads');

  try {
    if (!fs.existsSync(uploadDir)) {
      return res.json({ files: [], message: 'No uploads yet.' });
    }

    const files = fs.readdirSync(uploadDir).map(f => ({
      name: f,
      path: `/uploads/${f}`,
      // VULNERABILITY: Exposing full file path
      full_path: path.join(uploadDir, f)
    }));

    res.json({ files });
  } catch (err) {
    res.status(500).json({ error: 'Failed to list files.', details: err.message });
  }
});

module.exports = router;
