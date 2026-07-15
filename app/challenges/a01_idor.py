"""
A01:2021 - Broken Access Control (IDOR)

The /invoices/<id> endpoint checks that a user is authenticated, but never
checks that the invoice actually belongs to that user. Any logged-in user
can walk invoice IDs and read anyone else's data.
"""

from flask import Blueprint, jsonify, request, session
from werkzeug.security import check_password_hash

from app.extensions import db
from app.models import Invoice, User

bp = Blueprint("a01_idor", __name__, url_prefix="/a01")


@bp.post("/login")
def login():
    data = request.get_json(force=True)
    user = User.query.filter_by(username=data.get("username")).first()
    if not user or not check_password_hash(user.password_hash, data.get("password", "")):
        return jsonify({"error": "invalid credentials"}), 401
    session["a01_user_id"] = user.id
    return jsonify({"message": "logged in", "user_id": user.id})


@bp.get("/invoices/<int:invoice_id>")
def get_invoice(invoice_id):
    if "a01_user_id" not in session:
        return jsonify({"error": "login required"}), 401

    # VULNERABLE: no check that invoice.user_id == session["a01_user_id"]
    invoice = db.session.get(Invoice, invoice_id)
    if not invoice:
        return jsonify({"error": "not found"}), 404

    return jsonify(
        {"id": invoice.id, "user_id": invoice.user_id, "description": invoice.description, "amount": invoice.amount}
    )
