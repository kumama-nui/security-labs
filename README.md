# security-labs

Intentionally vulnerable, self-contained Docker labs for offensive / defensive
security practice. Each lab is a directory under this repo and spins up with
`docker compose up --build`.

> ⚠️ **All labs here are intentionally vulnerable.** Do not expose any of them
> to the public internet, do not reuse the code in real applications, and do
> not run them on hosts with access to sensitive networks or cloud metadata
> endpoints.

## Labs

| Directory | Chain | CWE | Summary |
|-----------|-------|-----|---------|
| [`ssrf-to-stored-xss/`](./ssrf-to-stored-xss/) | SSRF → Stored XSS | 918 + 79 | Unvalidated profile-picture URL is fetched server-side, then rendered unescaped into `<img src>` |

## Layout

```
security-labs/
├── README.md            ← this file (index + conventions)
├── _template/           ← skeleton to copy when starting a new lab
└── <lab-name>/          ← one directory per lab
    ├── docker-compose.yml
    ├── README.md
    ├── app/             ← main vulnerable app
    ├── attacker-server/ ← optional: static payload host
    └── internal-service/← optional: SSRF pivot target / internal API mock
```

## Naming convention

- **Directory**: lowercase kebab-case describing the chain or primary bug.
  - Chain: `ssrf-to-stored-xss`, `xxe-to-rce`
  - Single bug: `sqli-blind-boolean`, `ssti-jinja2`, `path-traversal-lfi`
- **Do not** prefix with CWE numbers in the directory name (they go in the
  table above and in the lab README).
- Keep each lab **self-contained** — no shared code between labs. Copy from
  `_template/`, don't symlink.

## Port allocation

Every lab publishes on host ports in the **5000–5099** band so they don't
collide with Burp (8080), common dev servers (3000, 8000), etc. Reserve a
contiguous block per lab:

| Lab | Range |
|-----|-------|
| `ssrf-to-stored-xss` | 5080–5082 |
| _next lab_ | 5083–5085 |

Update this table when adding a lab.

## Procedure for adding a new lab

1. `cp -r _template/ <lab-name>/`
2. Edit `<lab-name>/README.md` — fill in the sections (see template).
3. Pick a port range from the table above, update `docker-compose.yml`.
4. Implement the vulnerability (`app/`), attacker server, internal service.
5. Verify: `cd <lab-name> && docker compose up --build` → exploit works →
   `docker compose down -v`.
6. Add the lab to the **Labs** table at the top of this README.
7. Update the **Port allocation** table.
8. Commit on a branch or straight to `main` (disposable labs — don't
   over-engineer the git flow).

## Required sections in each lab's `README.md`

Keep them in this order so readers know where to look:

1. **⚠ Warning** — intentionally vulnerable, do not deploy.
2. **Vulnerabilities** — bullet list with CWE IDs.
3. **Layout** — file tree.
4. **Run** — `docker compose up --build` and host URLs / seeded credentials.
5. **Attack walkthrough** — numbered steps, with exact HTTP requests.
6. **How to fix** — one subsection per CWE, code sketch preferred.
7. **References** — CWE links, OWASP cheat sheets, related writeups.
8. **Teardown** — `docker compose down -v`.

## Conventions

- Python Flask or Node Express for app containers — pick whichever fits the
  bug; don't abstract a "framework layer" across labs.
- SQLite if you need persistence. Avoid Postgres/MySQL unless the bug
  depends on it.
- Expose the vulnerable app on `:5080` + N (shift per lab).
- Attacker server and internal service use `python -m http.server` or a
  20-line `BaseHTTPRequestHandler`. Do not pull in heavyweight frameworks.
- Seed 2 users (`alice`, `bob`, password `password123`) when the bug needs
  authentication.
- Hardcode `SECRET_KEY = "lab-insecure-key-do-not-use"` — it's a feature,
  not a bug, that these are obviously insecure.
