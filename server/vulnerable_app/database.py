"""
Database setup and seeding for the vulnerable application.

Uses SQLite for lightweight, resettable storage.
"""

import sqlite3
import os

DB_PATH = None  # Set dynamically per-episode


def get_db_path() -> str:
    """Get the current database path."""
    global DB_PATH
    if DB_PATH is None:
        DB_PATH = os.path.join(os.path.dirname(__file__), "ctf_vuln.db")
    return DB_PATH


def set_db_path(path: str) -> None:
    """Set a custom database path (used per-episode)."""
    global DB_PATH
    DB_PATH = path


def get_db() -> sqlite3.Connection:
    """Get a database connection with row factory."""
    db = sqlite3.connect(get_db_path())
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    return db


def init_database(db_path: str | None = None) -> None:
    """
    Initialize the database: create tables and seed data.

    This is called on every episode reset to ensure clean state.
    """
    path = db_path or get_db_path()
    set_db_path(path)

    # Remove existing database for clean state
    if os.path.exists(path):
        os.remove(path)
    # Also remove WAL/SHM files
    for suffix in ["-wal", "-shm"]:
        wal_path = path + suffix
        if os.path.exists(wal_path):
            os.remove(wal_path)

    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")

    _create_tables(db)
    _seed_data(db)

    db.close()


def _create_tables(db: sqlite3.Connection) -> None:
    """Create all database tables."""
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user',
            balance REAL DEFAULT 100.0
        );

        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            price REAL NOT NULL,
            description TEXT,
            category TEXT,
            stock INTEGER DEFAULT 100
        );

        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            total REAL,
            status TEXT DEFAULT 'completed',
            items_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS flags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_name TEXT UNIQUE NOT NULL,
            flag_value TEXT NOT NULL
        );
    """)
    db.commit()


def _seed_data(db: sqlite3.Connection) -> None:
    """Insert initial data for CTF challenges."""

    # ── Users ──
    users = [
        ("admin", "super_secret_password_2024", "admin@vulnapp.local", "admin", 10000.0),
        ("john_doe", "password123", "john@example.com", "user", 150.0),
        ("jane_smith", "jane2024!", "jane@example.com", "user", 200.0),
        ("bob_wilson", "b0bpass!", "bob@example.com", "moderator", 500.0),
    ]
    db.executemany(
        "INSERT INTO users (username, password, email, role, balance) VALUES (?, ?, ?, ?, ?)",
        users,
    )

    # ── Products ──
    products = [
        ("Basic Widget", 29.99, "A simple everyday widget", "electronics", 100),
        ("Premium Gadget", 149.99, "Top-of-the-line gadget", "electronics", 50),
        ("Enterprise Solution", 999.99, "Enterprise-grade platform license", "software", 10),
        ("Starter Pack", 9.99, "Beginner-friendly bundle", "bundles", 200),
        ("VIP Membership", 499.99, "Exclusive VIP access", "membership", 5),
    ]
    db.executemany(
        "INSERT INTO products (name, price, description, category, stock) VALUES (?, ?, ?, ?, ?)",
        products,
    )

    # ── Flags ──
    flags = [
        ("sqli_login", "FLAG{sqli_bypass_auth_2024}"),
        ("idor_privesc", "FLAG{idor_privesc_chain_2024}"),
        ("payment_logic", "FLAG{payment_logic_negative_total_2024}"),
    ]
    db.executemany(
        "INSERT INTO flags (task_name, flag_value) VALUES (?, ?)",
        flags,
    )

    db.commit()
