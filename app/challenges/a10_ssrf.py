"""
A10:2021 - Server-Side Request Forgery

/preview fetches ANY user-supplied URL from the server, with no allowlist
and no block on loopback/internal addresses. /internal/admin/flag trusts
`remote_addr == 127.0.0.1` as its only access control, assuming only the
server itself can reach it - but the preview feature lets an attacker make
the server issue that request on their behalf.
"""

import requests
from flask import Blueprint, jsonify, request

bp = Blueprint("a10_ssrf", __name__, url_prefix="/a10")


@bp.get("/internal/admin/flag")
def internal_admin_flag():
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return jsonify({"error": "forbidden - internal only"}), 403
    return jsonify({"flag": "FLAG{ssrf_internal_admin_hit}"})


@bp.get("/preview")
def preview():
    url = request.args.get("url", "")
    if not url:
        return jsonify({"error": "url required"}), 400

    try:
        # VULNERABLE: no allowlist, no block on internal/loopback targets.
        resp = requests.get(url, timeout=3)
        return jsonify({"status": resp.status_code, "preview": resp.text[:500]})
    except requests.RequestException as exc:
        return jsonify({"error": str(exc)}), 502
