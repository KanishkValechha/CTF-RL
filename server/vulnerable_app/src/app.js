/**
 * Express Application Factory
 *
 * VULNERABILITIES in middleware configuration:
 * - CORS wildcard with credentials (CWE-942)
 * - No security headers (CWE-693)
 * - Debug mode enabled
 * - Verbose error handling
 */

const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const path = require('path');
const { errorHandler } = require('./middleware/errorHandler');
const { FLAGS } = require('./config');

function createApp(db, port) {
  const app = express();

  // Store db and port on app for access in routes
  app.locals.db = db;
  app.locals.port = port;

  // ── Middleware ──

  // VULNERABILITY: CORS wildcard with credentials (CWE-942)
  app.use(cors({
    origin: '*',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'X-Requested-With']
  }));

  // VULNERABILITY: No security headers (CWE-693)
  // Intentionally NOT setting: X-Frame-Options, X-Content-Type-Options,
  // Content-Security-Policy, Strict-Transport-Security, X-XSS-Protection

  // Parse JSON and URL-encoded bodies
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true }));
  app.use(cookieParser());

  // VULNERABILITY: Serve uploads directory without auth
  app.use('/uploads', express.static(path.join(__dirname, '..', 'uploads')));

  // ── Routes ──
  const authRoutes = require('./routes/auth');
  const userRoutes = require('./routes/users');
  const productRoutes = require('./routes/products');
  const cartRoutes = require('./routes/cart');
  const checkoutRoutes = require('./routes/checkout');
  const adminRoutes = require('./routes/admin');
  const fileRoutes = require('./routes/files');
  const messageRoutes = require('./routes/messages');
  const reviewRoutes = require('./routes/reviews');
  const searchRoutes = require('./routes/search');
  const feedbackRoutes = require('./routes/feedback');
  const importRoutes = require('./routes/import');
  const debugRoutes = require('./routes/debug');

  app.use('/api/auth', authRoutes);
  app.use('/api/users', userRoutes);
  app.use('/api/products', productRoutes);
  app.use('/api/cart', cartRoutes);
  app.use('/api/checkout', checkoutRoutes);
  app.use('/api/admin', adminRoutes);
  app.use('/api/files', fileRoutes);
  app.use('/api/messages', messageRoutes);
  app.use('/api/reviews', reviewRoutes);
  app.use('/api/search', searchRoutes);
  app.use('/api/feedback', feedbackRoutes);
  app.use('/api/import', importRoutes);
  app.use('/api/debug', debugRoutes);

  // VULNERABILITY: Exposed .env endpoint (CWE-16)
  app.get('/.env', (req, res) => {
    res.type('text/plain').send(
      `# VulnShop Environment Configuration\n` +
      `DATABASE_URL=sqlite:///tmp/vulnshop.db\n` +
      `JWT_SECRET=secret123\n` +
      `ADMIN_API_KEY=sk_admin_master_key_2024\n` +
      `STRIPE_SECRET_KEY=sk_live_fake_4eC39HqLyjWDarjtT1zdp7dc\n` +
      `DEBUG=true\n` +
      `FLAG=${FLAGS.exposed_env}\n` +
      `NODE_ENV=development\n`
    );
  });

  // VULNERABILITY: Exposed config endpoint
  app.get('/api/config', (req, res) => {
    res.json({
      app_name: 'VulnShop',
      version: '1.0.0',
      jwt_secret: 'secret123',
      admin_api_key: 'sk_admin_master_key_2024',
      debug: true,
      flag: FLAGS.exposed_env
    });
  });

  // Internal-only endpoint for SSRF exploitation
  app.get('/api/internal/secret', (req, res) => {
    // This endpoint is meant to be accessed only via SSRF
    // In a real scenario, it would check for internal IP
    // Here it's accessible but "hidden" - not in public docs
    res.json({
      status: 'internal_access_granted',
      secret: FLAGS.ssrf,
      message: 'This endpoint should only be accessible from internal network.'
    });
  });

  // Root endpoint
  app.get('/', (req, res) => {
    res.json({
      name: 'VulnShop E-Commerce API',
      version: '1.0.0',
      endpoints: {
        auth: ['POST /api/auth/register', 'POST /api/auth/login', 'POST /api/auth/logout', 'GET /api/auth/me', 'POST /api/auth/forgot-password', 'POST /api/auth/reset-password'],
        users: ['GET /api/users', 'GET /api/users/:id', 'PUT /api/users/:id', 'GET /api/users/lookup'],
        products: ['GET /api/products', 'GET /api/products/:id', 'GET /api/products/:id/reviews'],
        cart: ['GET /api/cart', 'POST /api/cart/add', 'POST /api/cart/remove', 'POST /api/cart/apply-discount'],
        checkout: ['POST /api/checkout'],
        admin: ['GET /api/admin/dashboard', 'GET /api/admin/flag', 'GET /api/admin/users', 'DELETE /api/admin/users/:id', 'POST /api/admin/export', 'POST /api/admin/fetch-url'],
        files: ['GET /api/files/:filename', 'POST /api/upload'],
        messages: ['GET /api/messages', 'GET /api/messages/:id', 'POST /api/messages'],
        reviews: ['POST /api/reviews', 'GET /api/reviews'],
        search: ['GET /api/search'],
        feedback: ['POST /api/feedback'],
        import: ['POST /api/import'],
        debug: ['GET /api/debug/info', 'GET /api/debug/headers']
      }
    });
  });

  // Serve React frontend static files (if built)
  const frontendPath = path.join(__dirname, '..', 'frontend', 'dist');
  app.use(express.static(frontendPath));

  // SPA fallback - serve index.html for non-API routes
  app.get(/^(?!\/api\/).*/, (req, res, next) => {
    const indexPath = path.join(frontendPath, 'index.html');
    try {
      res.sendFile(indexPath);
    } catch (e) {
      next();
    }
  });

  // VULNERABILITY: Verbose error handler (CWE-209)
  app.use(errorHandler);

  return app;
}

module.exports = { createApp };
