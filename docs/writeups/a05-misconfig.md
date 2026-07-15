# A05:2021 - Security Misconfiguration

**Endpoint:** `GET /a05/internal/debug`
**Severity:** High

## Vulnerability

A diagnostics endpoint intended for local development was left reachable
in the deployed build, with no authentication and no environment gate
beyond a config flag (`DEBUG_ENDPOINTS_ENABLED`) that defaults to `True`:

```python
# app/challenges/a05_misconfig.py
@bp.get("/internal/debug")
def debug_info():
    if not current_app.config.get("DEBUG_ENDPOINTS_ENABLED"):
        return jsonify({"error": "not found"}), 404

    return jsonify({
        "secret_key": current_app.config["SECRET_KEY"],
        "launch_date": current_app.config["LAUNCH_DATE"],
        "database_uri": current_app.config["SQLALCHEMY_DATABASE_URI"],
        "flag": "FLAG{debug_endpoint_leaks_secrets}",
    })
```

## Reproduce

```bash
curl -s http://localhost:5000/a05/internal/debug
```

```json
{
  "secret_key": "vulnlab-static-secret-key",
  "launch_date": "2024-01-01",
  "database_uri": "sqlite:////tmp/vulnlab.db",
  "flag": "FLAG{debug_endpoint_leaks_secrets}"
}
```

No authentication, no IP restriction — just an unauthenticated GET.

## Impact

Leaks `SECRET_KEY` directly, which in this app also signs JWTs (see the
A07 writeup) — leaking it lets an attacker forge *validly signed* tokens,
not just abuse the alg=none bypass. It also confirms the exact
`LAUNCH_DATE` value the A02 exploit has to guess, and the database
connection string.

## Fix

- Debug/diagnostic endpoints should not exist in a deployed build at all;
  gate them behind a build-time flag that's physically absent from
  production images, not a runtime config value that can drift.
- If a diagnostics surface is genuinely needed, put it behind
  authentication + IP allowlisting, and never return secrets verbatim.
- Rotate `SECRET_KEY` outside of source control (env var / secrets
  manager), never hardcode it.

## Reference

[OWASP Top 10 2021 - A05 Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
