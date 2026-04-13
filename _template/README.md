# `<lab-name>` — `<one-line description>`

> ⚠️ **Intentionally vulnerable.** Educational use only. Do not deploy.

## Vulnerabilities

- **CWE-XXX `<name>`** — _brief description of where in the code it lives_.
- **CWE-YYY `<name>`** — _brief description_.

## Layout

```
<lab-name>/
├── docker-compose.yml
├── app/                # vulnerable app             (host :50XX)
├── attacker-server/    # payload host               (host :50XX+1)   [optional]
└── internal-service/   # SSRF / pivot target        (internal only)  [optional]
```

| Container         | Host port | Purpose                 |
|-------------------|-----------|-------------------------|
| `app`             | 50XX      | main vulnerable app     |
| `attacker-server` | 50XX+1    | XSS / exfil payloads    |
| `internal-service`| —         | pivot target            |

## Run

```bash
docker compose up --build
```

Open <http://localhost:50XX/>. Seeded users: `alice` / `bob` (password `password123`).

## Attack walkthrough

### 1. `<step name>`

```http
<exact HTTP request>
```

Expected response:

```json
{ ... }
```

### 2. `<next step>`

...

### N. Summary

```
<ascii diagram of the chain, e.g.>
attacker → POST /...  ─┬─ server-side fetch  → Collaborator   (CWE-918)
                       └─ stored verbatim    → unescaped sink (CWE-79)
victim   → GET /...    └─ JS executes in victim session
```

## How to fix

### CWE-XXX `<name>`

_Short remediation, code sketch preferred._

```python
# sketch
```

### CWE-YYY `<name>`

_Short remediation._

## References

- CWE-XXX: <https://cwe.mitre.org/data/definitions/XXX.html>
- OWASP `<relevant cheat sheet>`
- PortSwigger Web Security Academy — `<relevant topic>`

## Teardown

```bash
docker compose down -v
```
