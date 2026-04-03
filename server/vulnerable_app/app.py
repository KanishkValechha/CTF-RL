"""
Vulnerable Flask Application Factory.

Creates a Flask application with intentional security vulnerabilities
for the CTF environment. This app runs inside the Docker container
on port 5000I and is only accessible by the CTFEnvironment.
"""

from flask import Flask

from .config import SECRET_KEY


def create_vulnerable_app() -> Flask:
    """
    Create and configure the vulnerable Flask application.

    Returns:
        Configured Flask application with all vulnerable routes registered.
    """
    app = Flask(__name__)
    app.secret_key = SECRET_KEY

    # Register route blueprints
    from .routes.auth import auth_bp
    from .routes.users import users_bp
    from .routes.admin import admin_bp
    from .routes.payments import payments_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(payments_bp)

    # Root endpoint
    @app.route("/")
    def index():
        return {
            "name": "VulnApp",
            "version": "1.0.0",
            "description": "A web application with various features",
            "endpoints": [
                "POST /register",
                "POST /login",
                "POST /logout",
                "GET  /me",
                "GET  /api/users",
                "GET  /api/users/<id>",
                "PUT  /api/users/<id>",
                "GET  /api/products",
                "GET  /api/cart",
                "POST /api/cart/add",
                "POST /api/cart/remove",
                "POST /api/cart/apply-discount",
                "POST /api/checkout",
                "GET  /admin/dashboard",
                "GET  /admin/flag",
                "GET  /admin/users",
            ],
        }

    return app
