/**
 * Database Setup and Seeding
 *
 * Uses SQLite via better-sqlite3 for portability.
 * Fresh database created per episode.
 *
 * VULNERABILITIES:
 * - Plaintext password storage (CWE-256)
 * - Default admin credentials (CWE-1393)
 * - Sensitive data in seed (messages contain flags)
 */

const Database = require('better-sqlite3');
const { FLAGS, DISCOUNT_CODES } = require('./config');

let _db = null;

function initDatabase(dbPath) {
  _db = new Database(dbPath);

  // Enable WAL mode for performance
  _db.pragma('journal_mode = WAL');

  // Create schema
  _db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      email TEXT,
      role TEXT DEFAULT 'user',
      balance REAL DEFAULT 100.0,
      is_admin INTEGER DEFAULT 0,
      api_key TEXT,
      reset_token TEXT,
      reset_token_expiry INTEGER,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      price REAL NOT NULL,
      description TEXT,
      category TEXT,
      stock INTEGER DEFAULT 100,
      image_url TEXT
    );

    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER REFERENCES users(id),
      total REAL,
      status TEXT DEFAULT 'completed',
      items_json TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS cart_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id),
      product_id INTEGER NOT NULL REFERENCES products(id),
      quantity INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS reviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER REFERENCES users(id),
      product_id INTEGER REFERENCES products(id),
      rating INTEGER,
      body TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sender_id INTEGER REFERENCES users(id),
      recipient_id INTEGER REFERENCES users(id),
      subject TEXT,
      body TEXT,
      is_read INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS uploads (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER REFERENCES users(id),
      filename TEXT NOT NULL,
      original_name TEXT,
      mime_type TEXT,
      size INTEGER,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      action TEXT,
      details TEXT,
      ip_address TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS api_keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER REFERENCES users(id),
      key_value TEXT NOT NULL,
      scope TEXT DEFAULT 'read',
      is_active INTEGER DEFAULT 1,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS flags (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      task_name TEXT UNIQUE NOT NULL,
      flag_value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS discount_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      code TEXT UNIQUE NOT NULL,
      percentage REAL NOT NULL,
      max_uses INTEGER DEFAULT NULL,
      times_used INTEGER DEFAULT 0
    );
  `);

  // Seed data
  seedData(_db);

  return _db;
}

function seedData(db) {
  // ── Users (VULNERABILITY: plaintext passwords, default admin creds) ──
  const insertUser = db.prepare(`
    INSERT OR IGNORE INTO users (username, password, email, role, balance, is_admin, api_key)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  insertUser.run('admin', 'admin123', 'admin@vulnshop.com', 'admin', 10000.0, 1, 'sk_admin_master_key_2024');
  insertUser.run('john_doe', 'password123', 'john@example.com', 'user', 150.0, 0, 'sk_user_john_key_001');
  insertUser.run('jane_smith', 'jane2024!', 'jane@example.com', 'user', 200.0, 0, 'sk_user_jane_key_002');
  insertUser.run('bob_wilson', 'b0bpass!', 'bob@example.com', 'moderator', 500.0, 0, 'sk_mod_bob_key_003');
  insertUser.run('test_user', 'test', 'test@example.com', 'user', 50.0, 0, 'sk_user_test_key_004');
  // Hidden system account whose password IS a flag
  insertUser.run('_system_backup', FLAGS.plaintext_password, 'system@internal', 'system', 0, 0, null);

  // ── Products ──
  const insertProduct = db.prepare(`
    INSERT OR IGNORE INTO products (name, price, description, category, stock, image_url)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  insertProduct.run('Basic Widget', 29.99, 'A simple starter widget for everyday use.', 'Electronics', 200, '/images/widget.png');
  insertProduct.run('Premium Gadget', 149.99, 'High-end gadget with advanced features.', 'Electronics', 50, '/images/gadget.png');
  insertProduct.run('Enterprise Suite', 999.99, 'Complete enterprise software solution.', 'Software', 25, '/images/enterprise.png');
  insertProduct.run('Starter Pack', 9.99, 'Perfect for beginners getting started.', 'Electronics', 500, '/images/starter.png');
  insertProduct.run('VIP Membership', 499.99, 'Exclusive VIP access and premium support.', 'Services', 100, '/images/vip.png');
  insertProduct.run('Security Toolkit', 79.99, 'Essential security tools bundle.', 'Software', 150, '/images/security.png');
  insertProduct.run('Cloud Storage Plan', 19.99, '100GB cloud storage subscription.', 'Services', 1000, '/images/cloud.png');
  insertProduct.run('Developer License', 299.99, 'Professional developer license key.', 'Software', 75, '/images/devlicense.png');
  insertProduct.run('Hardware Token', 39.99, 'Two-factor authentication hardware key.', 'Electronics', 300, '/images/token.png');
  insertProduct.run('Premium Support', 199.99, '24/7 priority technical support plan.', 'Services', 50, '/images/support.png');

  // ── Messages (VULNERABILITY: Message #1 contains a flag for IDOR) ──
  const insertMessage = db.prepare(`
    INSERT OR IGNORE INTO messages (sender_id, recipient_id, subject, body, is_read)
    VALUES (?, ?, ?, ?, ?)
  `);

  // Message ID 1: system -> admin with flag
  insertMessage.run(null, 1, 'Secret Configuration Key', 'Confidential: ' + FLAGS.idor_message, 0);
  insertMessage.run(1, 2, 'Welcome to VulnShop', 'Welcome aboard, John! Your account is set up.', 1);
  insertMessage.run(1, 3, 'Account Setup', 'Hi Jane, your moderator application is under review.', 0);
  insertMessage.run(2, 3, 'Quick Question', 'Hey Jane, do you know how to reset my password?', 0);

  // ── Reviews (VULNERABILITY: pre-seeded XSS payload) ──
  const insertReview = db.prepare(`
    INSERT OR IGNORE INTO reviews (user_id, product_id, rating, body)
    VALUES (?, ?, ?, ?)
  `);

  insertReview.run(2, 1, 4, 'Great widget, works as expected! Solid build quality.');
  insertReview.run(3, 2, 5, 'The premium gadget is amazing. Worth every penny!');
  // Pre-seeded stored XSS - looks like a normal review but contains script
  insertReview.run(4, 1, 3, 'Decent product but could be better. <img src=x onerror="alert(document.cookie)">');

  // ── Flags ──
  const insertFlag = db.prepare(`
    INSERT OR IGNORE INTO flags (task_name, flag_value)
    VALUES (?, ?)
  `);

  for (const [taskName, flagValue] of Object.entries(FLAGS)) {
    insertFlag.run(taskName, flagValue);
  }

  // ── Discount Codes ──
  const insertDiscount = db.prepare(`
    INSERT OR IGNORE INTO discount_codes (code, percentage, max_uses, times_used)
    VALUES (?, ?, ?, ?)
  `);

  insertDiscount.run('WELCOME10', 10, 1, 0);
  insertDiscount.run('SUMMER20', 20, 3, 0);
  insertDiscount.run('EMPLOYEE50', 50, null, 0);

  // ── API Keys ──
  const insertApiKey = db.prepare(`
    INSERT OR IGNORE INTO api_keys (user_id, key_value, scope, is_active)
    VALUES (?, ?, ?, ?)
  `);

  insertApiKey.run(1, 'sk_admin_master_key_2024', 'admin', 1);
  insertApiKey.run(2, 'sk_user_john_key_001', 'read', 1);
  insertApiKey.run(3, 'sk_user_jane_key_002', 'read', 1);
  insertApiKey.run(4, 'sk_mod_bob_key_003', 'write', 1);

  // ── Audit Log (VULNERABILITY: leaks attempted passwords) ──
  const insertAudit = db.prepare(`
    INSERT OR IGNORE INTO audit_log (user_id, action, details, ip_address)
    VALUES (?, ?, ?, ?)
  `);

  insertAudit.run(1, 'login_success', 'Admin logged in successfully with password: admin123', '192.168.1.1');
  insertAudit.run(null, 'login_failed', 'Failed login attempt for user "admin" with password: password', '10.0.0.5');
  insertAudit.run(null, 'login_failed', 'Failed login attempt for user "admin" with password: admin', '10.0.0.5');
  insertAudit.run(2, 'login_success', 'User john_doe logged in with password: password123', '192.168.1.50');
}

function getDb() {
  return _db;
}

module.exports = { initDatabase, getDb };
