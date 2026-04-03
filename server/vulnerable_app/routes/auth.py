"""
Authentication routes — INTENTIONALLY VULNERABLE.

Contains SQL injection vulnerability in the login endpoint.
This is the target for the 'sqli_login' (Easy) task.
"""

from flask import Blueprint, request, jsonify, session

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["POST"])
def register():
    """Register a new user account."""
    from ..database import get_db

    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    email = data.get("email", "")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, 'user')",
            (username, password, email),
        )
        db.commit()
        user = db.execute(
            "SELECT id, username, role FROM users WHERE username=?", (username,)
        ).fetchone()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]
        db.close()
        return jsonify(
            {
                "status": "registered",
                "user_id": user["id"],
                "username": user["username"],
                "role": user["role"],
            }
        ), 201
    except Exception as e:
        db.close()
        return jsonify({"error": f"Registration failed: {str(e)}"}), 400


@auth_bp.route("/login", methods=["POST"])
def login():
    """
    Login endpoint.

    ██████████████████████████████████████████████████
    ██  VULNERABILITY: SQL INJECTION                ██
    ██  User input is interpolated directly into    ██
    ██  the SQL query via f-string formatting.      ██
    ██  No parameterized queries are used.          ██
    ██████████████████████████████████████████████████
    """
    from ..database import get_db

    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    if not username:
        return jsonify({"error": "Username is required"}), 400

    db = get_db()

    # ❌ VULNERABLE: String formatting in SQL query
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

    try:
        user = db.execute(query).fetchone()
    except Exception as e:
        db.close()
        return jsonify({"error": f"Database error: {str(e)}"}), 500

    if user:
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]
        db.close()
        return jsonify(
            {
                "status": "success",
                "message": f"Welcome, {user['username']}!",
                "user_id": user["id"],
                "username": user["username"],
                "role": user["role"],
            }
        )

    db.close()
    return jsonify({"status": "failed", "error": "Invalid credentials"}), 401


@auth_bp.route("/logout", methods=["POST"])
def logout():
    """Log out the current user."""
    session.clear()
    return jsonify({"status": "logged_out"})


@auth_bp.route("/me", methods=["GET"])
def current_user():
    """Get the currently logged-in user's information."""
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    return jsonify(
        {
            "user_id": session.get("user_id"),
            "username": session.get("username"),
            "role": session.get("role"),
        }
    )
