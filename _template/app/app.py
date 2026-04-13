"""
<lab-name> — INTENTIONALLY VULNERABLE.

Vulnerabilities:
  - CWE-XXX: <describe>
  - CWE-YYY: <describe>
"""
from flask import Flask, request

app = Flask(__name__)
app.secret_key = "lab-insecure-key-do-not-use"


@app.route("/")
def index():
    return "replace me"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
