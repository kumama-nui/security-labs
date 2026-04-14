# `cspt-to-xss` — Client-Side Path Traversal chained to DOM XSS

> ⚠️ **Intentionally vulnerable.** Educational use only. Do not deploy.

## Vulnerabilities

- **CWE-22 Path Traversal (client-side)** — `app/static/app.js` reads the
  username from `location.hash` and concatenates it into a `fetch()` URL
  template literal with zero validation. Injecting `../` segments
  redirects the request to a different endpoint on the same origin.
- **CWE-79 DOM-based XSS** — the same `app.js` assigns the JSON
  response's `bio` field directly to `element.innerHTML`. On its own this
  would be harmless (the legitimate `/api/users/<name>/profile` only
  returns hard-coded bios), but chained with CSPT the attacker fully
  controls what gets written there.

The two bugs are individually minor; the chain makes them exploitable.
This is the classic CSPT pattern described by Maxence Schmitt: a trusted
fetch path is rerouted to a less-trusted sibling endpoint, and whatever
structure that endpoint returns is treated as if it came from the real
one.

## Layout

```
cspt-to-xss/
├── docker-compose.yml
├── app/                # Flask + vanilla-JS SPA    (host :5083)
│   ├── Dockerfile
│   ├── app.py
│   ├── requirements.txt
│   └── static/
│       ├── index.html
│       ├── profile.html
│       └── app.js
└── attacker-server/    # phishing page host        (host :5084)
    ├── Dockerfile
    └── payloads/
        └── index.html
```

| Container         | Host port | Purpose                            |
|-------------------|-----------|------------------------------------|
| `app`             | 5083      | Main vulnerable SPA                |
| `attacker-server` | 5084      | Attacker-hosted phishing page      |

## Run

```bash
docker compose up --build
```

- Target app: <http://localhost:5083/>
- Attacker page: <http://localhost:5084/>

No authentication required — this lab is about the client-side sink, not
session handling.

## Attack walkthrough

### 1. Observe the normal flow

Open <http://localhost:5083/> and click **Alice's profile**.

The browser navigates to `/profile.html#alice`. `app.js` runs:

```js
const username = location.hash.slice(1) || "alice";
fetch(`/api/users/${username}/profile`)
  .then(r => r.json())
  .then(data => {
    document.getElementById("name").textContent = data.displayName;
    document.getElementById("bio").innerHTML = data.bio;
  });
```

In DevTools → Network you should see:

```
GET /api/users/alice/profile → 200 {"displayName":"Alice","bio":"..."}
```

The bio field is rendered with `innerHTML`, but since the server only
returns its hard-coded bio, nothing scary happens. **Yet.**

### 2. Find a sibling endpoint

Explore `/api/*`. Alongside `/api/users/<name>/profile` there is
`/api/echo?data=<whatever>`, which reflects `data` into a response shaped
like a user profile:

```
GET /api/echo?data=hello
→ {"displayName":"Echo","bio":"hello"}
```

This is the CSPT sink: it lives under `/api/`, it returns an object with
the same fields the SPA expects, and its `bio` value is attacker-chosen.

### 3. Build the path-traversal payload

The SPA's fetch template is:
```
/api/users/${username}/profile
```

If `username` contains `../echo?data=<payload>`, template-expansion gives:
```
/api/users/../echo?data=<payload>/profile
```

The URL parser performs RFC 3986 dot-segment removal on the path, and the
`?` begins the query string, so the request that actually goes out is:

```
GET /api/echo?data=<payload>/profile
```

— a totally different endpoint on the same origin, with an attacker-
controlled `data` parameter. The trailing `/profile` ends up inside the
query and is ignored.

### 4. Fire the XSS

Visit this URL in a browser:

```
http://localhost:5083/profile.html#../echo?data=%3Cimg%20src=x%20onerror=%22alert('XSS%20via%20CSPT')%22%3E
```

- `location.hash.slice(1)` →
  `../echo?data=<img src=x onerror="alert('XSS via CSPT')">`
- `fetch("/api/users/../echo?data=<img src=x onerror=...>/profile")`
- URL normalization →
  `fetch("/api/echo?data=<img src=x onerror=...>/profile")`
- Server responds:
  `{"displayName":"Echo","bio":"<img src=x onerror=\"alert('XSS via CSPT')\">/profile"}`
- SPA sets `innerHTML` to that string → `<img>` with a broken `src`
  fires `onerror` → `alert()` pops.

### 5. Deliver via the attacker page

Open <http://localhost:5084/>. The phishing page contains a link that
looks like a normal profile URL on the target site but carries the
payload in the fragment. Click it and the XSS fires in the target's
origin — exactly the real-world scenario (attacker emails a link to
`https://target.example/profile.html#...`, victim clicks, payload runs
under `target.example`'s origin).

### 6. Verify in Burp

Proxy the browser through Burp and reproduce. The interesting things to
notice in the HTTP history:

- The request goes to `/api/echo`, **not** `/api/users/.../profile` —
  proof that the fetch was hijacked client-side.
- The server logs show a request for `/api/echo` with `Referer:
  /profile.html#...` stripped (fragments are never sent).
- A server-side WAF that only looks at `/api/users/*` rules would miss
  this entirely. That's the defensive lesson.

### 7. Summary diagram

```
victim   → GET /profile.html#../echo?data=<payload>
            └── app.js: fetch(`/api/users/${hash}/profile`)
                        └── URL normalized → /api/echo?data=<payload>/profile
                                          └── {"bio": "<payload>"}
                                                           ↓
                                                       innerHTML sink
                                                           ↓
                                                    JS executes in
                                                    target's origin
```

## How to fix

### CWE-22 (client-side path traversal)

The fix is **validate or encode the fragment before using it in a fetch path**:

```js
// Option A: allowlist — reject anything that isn't a simple identifier.
const username = location.hash.slice(1) || "alice";
if (!/^[a-zA-Z0-9_-]{1,32}$/.test(username)) {
  throw new Error("invalid username");
}

// Option B: URL-encode each segment so '..' and '/' can't break out.
fetch(`/api/users/${encodeURIComponent(username)}/profile`);
```

Defence in depth:

- Use the URL constructor to build the request so you can inspect the
  resolved path before fetching:
  ```js
  const u = new URL(`/api/users/${encodeURIComponent(username)}/profile`,
                    location.origin);
  if (!u.pathname.startsWith("/api/users/") || !u.pathname.endsWith("/profile")) {
    throw new Error("unexpected path");
  }
  fetch(u);
  ```
- Server-side: make `/api/echo` (or any reflection endpoint) return a
  distinct shape, or require an `X-Requested-With` header, or apply a
  strict CORS / Sec-Fetch-* check so unexpected callers are rejected.
  This doesn't fix the traversal itself but breaks the chain.

### CWE-79 (DOM XSS sink)

Stop using `innerHTML` for attacker-influenceable data. Use
`textContent`:

```js
document.getElementById("bio").textContent = data.bio;
```

If rich text really is required, run the string through a vetted
sanitizer (DOMPurify) and set a strict Content-Security-Policy:

```
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'
```

A CSP like this would have neutralised the `alert()` in this lab even
with the CSPT still present — inline event handlers like `onerror=`
require `'unsafe-inline'` in `script-src`.

## References

- CWE-22: <https://cwe.mitre.org/data/definitions/22.html>
- CWE-79: <https://cwe.mitre.org/data/definitions/79.html>
- Maxence Schmitt — "Client-Side Path Traversal: the forgotten vulnerability"
- PortSwigger Web Security Academy — DOM XSS
- OWASP DOM-based XSS Prevention Cheat Sheet
- RFC 3986 §5.2.4 (Remove Dot Segments)

## Teardown

```bash
docker compose down -v
```
