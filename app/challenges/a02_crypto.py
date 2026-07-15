"""
A02:2021 - Cryptographic Failures

Password-reset tokens are md5(username + LAUNCH_DATE). LAUNCH_DATE is a
hardcoded constant shipped in this public repo (see app/config.py) instead
of a per-request secret, so anyone can compute a valid reset token for any
username without ever seeing the "sent" email.
"""

import hashlib

from flask import Blueprint, current_app, jsonify, request

from app.extensions import db
from app.models import User

bp = Blueprint("a02_crypto", __name__, url_prefix="/a02")


def _make_token(username: str) -> str:
    launch_date = current_app.config["LAUNCH_DATE"]
    return hashlib.md5(f"{username}:{launch_date}".encode()).hexdigest()


@bp.post("/request-reset")
def request_reset():
    username = request.get_json(force=True).get("username", "")
    # Simulates "emailing" the token to the account's registered address.
    # The token itself is intentionally NOT returned here.
    return jsonify({"message": f"if {username} exists, a reset token was emailed"})


@bp.post("/reset")
def reset_password():
    data = request.get_json(force=True)
    username = data.get("username", "")
    token = data.get("token", "")
    new_password = data.get("new_password", "")

    user = User.query.filter_by(username=username).first()
    if not user or token != _make_token(username):
        return jsonify({"error": "invalid token"}), 400

    user.set_password(new_password)
    db.session.commit()

    response = {"message": f"password for {username} reset"}
    if username == "admin":
        response["flag"] = "FLAG{predictable_reset_token_pwned}"
    return jsonify(response)
