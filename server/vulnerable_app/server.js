/**
 * CTF Vulnerable Application - Entry Point
 *
 * Deliberately vulnerable e-commerce application for security research.
 * DO NOT deploy in production.
 *
 * Usage: node server.js --port PORT --db DB_PATH
 */

const { createApp } = require('./src/app');
const { initDatabase } = require('./src/database');

// Parse CLI arguments
function parseArgs() {
  const args = process.argv.slice(2);
  const config = {
    port: 5000,
    db: './vuln_app.db'
  };

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--port' && args[i + 1]) {
      config.port = parseInt(args[i + 1], 10);
      i++;
    } else if (args[i] === '--db' && args[i + 1]) {
      config.db = args[i + 1];
      i++;
    }
  }

  return config;
}

const config = parseArgs();

// Initialize database
const db = initDatabase(config.db);

// Create and start Express app
const app = createApp(db, config.port);

const server = app.listen(config.port, '127.0.0.1', () => {
  // Signal readiness to parent process (Python environment)
  console.log(`READY on port ${config.port}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  server.close(() => {
    if (db && db.open) {
      db.close();
    }
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  server.close(() => {
    if (db && db.open) {
      db.close();
    }
    process.exit(0);
  });
});
