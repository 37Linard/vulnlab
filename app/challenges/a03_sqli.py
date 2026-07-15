"""
A03:2021 - Injection (SQL Injection)

Login builds a raw SQL string by directly interpolating user input instead
of using bound parameters. `username=admin' -- ` short-circuits the WHERE
clause and comments out the password check entirely.
"""

from flask import Blueprint, jsonify, request
from sqlalchemy import text

from app.extensions import db

bp = Blueprint("a03_sqli", __name__, url_prefix="/a03-sqli")


@bp.post("/login")
def login():
    data = request.get_json(force=True)
    username = data.get("username", "")
    password = data.get("password", "")

    # VULNERABLE: string-built SQL, no bound parameters.
    query = text(
        f"SELECT id, username, is_admin FROM user "
        f"WHERE username = '{username}' AND password_hash = '{password}'"
    )
    row = db.session.execute(query).first()

    if not row:
        return jsonify({"error": "invalid credentials"}), 401

    response = {"id": row.id, "username": row.username, "is_admin": bool(row.is_admin)}
    if row.username == "admin" and bool(row.is_admin):
        response["flag"] = "FLAG{sql_injection_login_bypass}"
    return jsonify(response)
