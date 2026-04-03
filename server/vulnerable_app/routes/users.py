"""
User management routes — INTENTIONALLY VULNERABLE.

Contains IDOR (Insecure Direct Object Reference) and
mass assignment / privilege escalation vulnerabilities.
This is the target for the 'idor_privesc' (Medium) task.
"""

from flask import Blueprint, request, jsonify, session

users_bp = Blueprint("users", __name__)


@users_bp.route("/api/users", methods=["GET"])
def list_users():
    """List all users (public endpoint, shows limited info)."""
    from ..database import get_db

    db = get_db()
    users = db.execute("SELECT id, username, role FROM users").fetchall()
    db.close()
    return jsonify({"users": [dict(u) for u in users]})


@users_bp.route("/api/users/<int:user_id>", methods=["GET"])
def get_user(user_id: int):
    """
    Get user profile by ID.

    ██████████████████████████████████████████████████
    ██  VULNERABILITY: IDOR                         ██
    ██  No authorization check — any authenticated  ██
    ██  user can view ANY user's full profile,      ██
    ██  including email and role, by changing the    ██
    ██  user_id parameter.                          ██
    ██████████████████████████████████████████████████
    """
    from ..database import get_db

    # ❌ VULNERABLE: No check that the requesting user owns this profile
    db = get_db()
    user = db.execute(
        "SELECT id, username, email, role, balance FROM users WHERE id=?",
        (user_id,),
    ).fetchone()
    db.close()

    if user:
        return jsonify(dict(user))
    return jsonify({"error": "User not found"}), 404


@users_bp.route("/api/users/<int:user_id>", methods=["PUT"])
def update_user(user_id: int):
    """
    Update user profile.

    ██████████████████████████████████████████████████
    ██  VULNERABILITY: MASS ASSIGNMENT / PRIVESC    ██
    ██  The endpoint checks that you can only       ██
    ██  update YOUR OWN profile (user_id matches    ██
    ██  session), BUT it accepts ANY field —         ██
    ██  including 'role'. An attacker can set       ██
    ██  their own role to 'admin'.                  ██
    ██████████████████████████████████████████████████
    """
    from ..database import get_db

    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    # This check only ensures you modify YOUR OWN profile
    if session.get("user_id") != user_id:
        return jsonify({"error": "You can only update your own profile"}), 403

    data = request.get_json(silent=True) or {}
    if not data:
        return jsonify({"error": "No data provided"}), 400

    db = get_db()

    # ❌ VULNERABLE: Accepts ANY field, including 'role'
    set_clauses = []
    values = []
    for key, value in data.items():
        if key in ("id",):  # Only protect the primary key
            continue
        set_clauses.append(f"{key}=?")
        values.append(value)

    if not set_clauses:
        db.close()
        return jsonify({"error": "No valid fields to update"}), 400

    values.append(user_id)
    query = f"UPDATE users SET {', '.join(set_clauses)} WHERE id=?"

    try:
        db.execute(query, values)
        db.commit()
    except Exception as e:
        db.close()
        return jsonify({"error": f"Update failed: {str(e)}"}), 500

    # Refresh session if role was changed
    user = db.execute(
        "SELECT id, username, email, role FROM users WHERE id=?", (user_id,)
    ).fetchone()
    db.close()

    if user:
        session["role"] = user["role"]
        session["username"] = user["username"]
        return jsonify({"status": "updated", "user": dict(user)})

    return jsonify({"error": "User not found after update"}), 500
