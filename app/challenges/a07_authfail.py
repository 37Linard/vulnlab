"""
A07:2021 - Identification and Authentication Failures

The token verifier trusts the `alg` field from the *attacker-controlled*
JWT header instead of pinning a single expected algorithm. Sending a token
with `"alg": "none"` skips signature verification entirely, so anyone can
forge a token claiming `role: admin`.

(Also note: /login has no rate limiting or lockout - a bonus finding
documented in the writeup, not separately flagged here.)
"""

import jwt
from flask import Blueprint, current_app, jsonify, request
from werkzeug.security import check_password_hash

from app.models import User

bp = Blueprint("a07_authfail", __name__, url_prefix="/a07")


@bp.post("/login")
def login():
    data = request.get_json(force=True)
    user = User.query.filter_by(username=data.get("username")).first()
    if not user or not check_password_hash(user.password_hash, data.get("password", "")):
        return jsonify({"error": "invalid credentials"}), 401

    token = jwt.encode(
        {"username": user.username, "role": "admin" if user.is_admin else "user"},
        current_app.config["SECRET_KEY"],
        algorithm="HS256",
    )
    return jsonify({"token": token})


@bp.get("/admin/flag")
def admin_flag():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "missing token"}), 401
    token = auth_header.removeprefix("Bearer ")

    try:
        header = jwt.get_unverified_header(token)
        alg = header.get("alg")

        # VULNERABLE: algorithm is picked from the token itself. "none"
        # bypasses signature verification altogether.
        if alg == "none":
            payload = jwt.decode(token, options={"verify_signature": False})
        else:
            payload = jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=[alg])
    except jwt.PyJWTError as exc:
        return jsonify({"error": f"invalid token: {exc}"}), 401

    if payload.get("role") != "admin":
        return jsonify({"error": "forbidden"}), 403

    return jsonify({"flag": "FLAG{jwt_alg_none_bypass}"})
