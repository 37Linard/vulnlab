"""
A08:2021 - Software and Data Integrity Failures

"Import profile backup" unpickles attacker-supplied, base64-encoded data.
`pickle.loads` executes arbitrary code via `__reduce__` during
deserialization - there is no way to make this endpoint safe short of not
unpickling untrusted input at all.
"""

import base64
import pickle

from flask import Blueprint, jsonify, request

bp = Blueprint("a08_deserialize", __name__, url_prefix="/a08")


@bp.post("/profile/import")
def import_profile():
    data = request.get_json(force=True).get("data", "")

    try:
        raw = base64.b64decode(data)
        # VULNERABLE: unpickling untrusted, attacker-controlled bytes.
        restored = pickle.loads(raw)
    except Exception as exc:
        return jsonify({"error": f"could not restore profile: {exc}"}), 400

    return jsonify({"restored": str(restored)})
