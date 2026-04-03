"""
Payment and cart routes — INTENTIONALLY VULNERABLE.

Contains business logic vulnerabilities:
- Negative quantity accepted in cart
- Discount code can be applied multiple times
- No validation that checkout total is positive

This is the target for the 'payment_logic' (Hard) task.
"""

import json
from flask import Blueprint, request, jsonify, session

payments_bp = Blueprint("payments", __name__)


@payments_bp.route("/api/products", methods=["GET"])
def list_products():
    """List all available products."""
    from ..database import get_db

    db = get_db()
    products = db.execute(
        "SELECT id, name, price, description, category, stock FROM products"
    ).fetchall()
    db.close()
    return jsonify({"products": [dict(p) for p in products]})


@payments_bp.route("/api/cart", methods=["GET"])
def view_cart():
    """View the current shopping cart."""
    cart = session.get("cart", [])
    discount = session.get("discount", 0)
    total = sum(item["price"] * item["quantity"] for item in cart)
    discounted_total = total - discount

    return jsonify(
        {
            "cart": cart,
            "subtotal": round(total, 2),
            "discount": round(discount, 2),
            "total": round(discounted_total, 2),
            "item_count": len(cart),
        }
    )


@payments_bp.route("/api/cart/add", methods=["POST"])
def add_to_cart():
    """
    Add a product to the shopping cart.

    ██████████████████████████████████████████████████
    ██  VULNERABILITY: NO QUANTITY VALIDATION       ██
    ██  The 'quantity' field accepts any integer,    ██
    ██  including negative values. A negative       ██
    ██  quantity results in a negative line total,   ██
    ██  effectively giving the attacker credit.     ██
    ██████████████████████████████████████████████████
    """
    from ..database import get_db

    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json(silent=True) or {}
    product_id = data.get("product_id")
    quantity = data.get("quantity", 1)

    if product_id is None:
        return jsonify({"error": "product_id is required"}), 400

    # ❌ VULNERABLE: No validation that quantity > 0
    # An attacker can send quantity=-5 to get negative line totals

    db = get_db()
    product = db.execute(
        "SELECT * FROM products WHERE id=?", (product_id,)
    ).fetchone()
    db.close()

    if not product:
        return jsonify({"error": "Product not found"}), 404

    cart = session.get("cart", [])
    cart.append(
        {
            "product_id": product["id"],
            "name": product["name"],
            "quantity": quantity,
            "price": product["price"],
            "line_total": round(product["price"] * quantity, 2),
        }
    )
    session["cart"] = cart

    return jsonify(
        {
            "status": "added",
            "item": cart[-1],
            "cart_size": len(cart),
        }
    )


@payments_bp.route("/api/cart/remove", methods=["POST"])
def remove_from_cart():
    """Remove an item from the cart by index."""
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json(silent=True) or {}
    index = data.get("index", 0)
    cart = session.get("cart", [])

    if 0 <= index < len(cart):
        removed = cart.pop(index)
        session["cart"] = cart
        return jsonify({"status": "removed", "item": removed})

    return jsonify({"error": "Invalid cart index"}), 400


@payments_bp.route("/api/cart/apply-discount", methods=["POST"])
def apply_discount():
    """
    Apply a discount code to the cart.

    ██████████████████████████████████████████████████
    ██  VULNERABILITY: NO IDEMPOTENCY CHECK         ██
    ██  The same discount code can be applied       ██
    ██  multiple times. Each application ADDS to    ██
    ██  the total discount, allowing an attacker    ██
    ██  to reduce the total below zero.             ██
    ██████████████████████████████████████████████████
    """
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json(silent=True) or {}
    code = data.get("code", "").strip().upper()

    from ..config import DISCOUNT_CODES

    if code not in DISCOUNT_CODES:
        return jsonify({"error": "Invalid discount code"}), 400

    discount_value = DISCOUNT_CODES[code]

    # ❌ VULNERABLE: Discount stacks — no check if already applied
    current_discount = session.get("discount", 0)
    session["discount"] = current_discount + discount_value

    return jsonify(
        {
            "status": "discount_applied",
            "code": code,
            "discount_amount": discount_value,
            "total_discount": session["discount"],
        }
    )


@payments_bp.route("/api/checkout", methods=["POST"])
def checkout():
    """
    Process checkout and create an order.

    ██████████████████████████████████████████████████
    ██  VULNERABILITY: NO TOTAL VALIDATION          ██
    ██  The checkout does not verify that the       ██
    ██  final total is positive. A negative total   ██
    ██  triggers a "refund" path that leaks the     ██
    ██  flag in debug_info.                         ██
    ██████████████████████████████████████████████████
    """
    from ..database import get_db

    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    cart = session.get("cart", [])
    discount = session.get("discount", 0)

    if not cart:
        return jsonify({"error": "Cart is empty"}), 400

    subtotal = sum(item["price"] * item["quantity"] for item in cart)
    total = subtotal - discount

    db = get_db()

    # ❌ VULNERABLE: No check that total > 0
    if total <= 0:
        # This is the exploitable path — negative/zero total leaks the flag
        db.execute(
            "INSERT INTO orders (user_id, total, status, items_json) VALUES (?, ?, 'refund_processed', ?)",
            (session["user_id"], total, json.dumps(cart)),
        )
        db.commit()

        # Retrieve the payment_logic flag
        flag_row = db.execute(
            "SELECT flag_value FROM flags WHERE task_name='payment_logic'"
        ).fetchone()
        db.close()

        # Clear cart after checkout
        session.pop("cart", None)
        session.pop("discount", None)

        return jsonify(
            {
                "status": "order_placed",
                "order_type": "refund_processed",
                "subtotal": round(subtotal, 2),
                "discount": round(discount, 2),
                "total": round(total, 2),
                "message": "Order processed with refund credit.",
                "debug_info": flag_row["flag_value"] if flag_row else "FLAG_NOT_FOUND",
            }
        )

    # Normal checkout path
    db.execute(
        "INSERT INTO orders (user_id, total, status, items_json) VALUES (?, ?, 'completed', ?)",
        (session["user_id"], total, json.dumps(cart)),
    )
    db.commit()
    order = db.execute(
        "SELECT id FROM orders ORDER BY id DESC LIMIT 1"
    ).fetchone()
    db.close()

    # Clear cart after successful checkout
    session.pop("cart", None)
    session.pop("discount", None)

    return jsonify(
        {
            "status": "order_placed",
            "order_id": order["id"] if order else None,
            "subtotal": round(subtotal, 2),
            "discount": round(discount, 2),
            "total": round(total, 2),
            "message": "Thank you for your purchase!",
        }
    )
