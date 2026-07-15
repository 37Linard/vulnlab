"""
A05:2021 - Security Misconfiguration

A debug/diagnostics endpoint meant only for local development
(DEBUG_ENDPOINTS_ENABLED) was left reachable with no authentication and no
environment check, dumping internal config - including secrets that have
no business being exposed over HTTP.
"""

from flask import Blueprint, current_app, jsonify

bp = Blueprint("a05_misconfig", __name__, url_prefix="/a05")


@bp.get("/internal/debug")
def debug_info():
    if not current_app.config.get("DEBUG_ENDPOINTS_ENABLED"):
        return jsonify({"error": "not found"}), 404

    # VULNERABLE: no auth check, dumps secrets meant to stay server-side.
    return jsonify(
        {
            "secret_key": current_app.config["SECRET_KEY"],
            "launch_date": current_app.config["LAUNCH_DATE"],
            "database_uri": current_app.config["SQLALCHEMY_DATABASE_URI"],
            "flag": "FLAG{debug_endpoint_leaks_secrets}",
        }
    )
