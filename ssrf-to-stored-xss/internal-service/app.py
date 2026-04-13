"""
Mock internal service — only reachable from inside the lab network.

Simulates the kind of unauthenticated internal API that real-world SSRF
attacks pivot to (admin panels, metrics, cloud metadata, etc.).
"""
from http.server import BaseHTTPRequestHandler, HTTPServer

FAKE_SECRETS = {
    "admin_token": "INTERNAL-SECRET-TOKEN-do-not-leak",
    "db_dsn": "postgres://internal:hunter2@db.internal/prod",
    "flag": "FLAG{ssrf_pivoted_to_internal_api}",
}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/health"):
            self._send(200, b'{"status":"ok","service":"internal"}')
        elif self.path == "/admin":
            import json
            self._send(200, json.dumps(FAKE_SECRETS).encode())
        else:
            self._send(404, b'{"error":"not found"}')

    def log_message(self, fmt, *args):
        print("[internal] " + fmt % args, flush=True)


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 5000), Handler).serve_forever()
