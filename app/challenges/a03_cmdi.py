"""
A03:2021 - Injection (OS Command Injection)

The "server echo/diagnostic" endpoint shells out with the raw, unsanitized
`text` parameter and shell=True. Shell metacharacters (`;`, `|`, `&&`, ...)
let an attacker chain arbitrary commands.

NOTE: relies on POSIX `sh` (`;`, `cat`) - exploitable when run in the Docker
container (Linux), not on native Windows shells.
"""

import subprocess

from flask import Blueprint, jsonify, request

bp = Blueprint("a03_cmdi", __name__, url_prefix="/a03-cmdi")


@bp.get("/echo")
def echo():
    text = request.args.get("text", "")

    # VULNERABLE: unsanitized input passed to a shell.
    result = subprocess.run(
        f"echo {text}", shell=True, capture_output=True, text=True, timeout=5
    )

    return jsonify({"stdout": result.stdout, "stderr": result.stderr})
