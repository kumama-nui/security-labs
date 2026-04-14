"""
cspt-to-xss — INTENTIONALLY VULNERABLE.

Vulnerabilities:
  - CWE-22  Path Traversal (client-side): front-end concatenates the
    username from location.hash into a fetch() URL without validation.
    An attacker can inject '../' segments to redirect the fetch to a
    different same-origin endpoint.
  - CWE-79  DOM-based XSS: the JSON response's 'bio' field is assigned
    to element.innerHTML. When combined with the CSPT, the attacker
    fully controls the value written there (via /api/echo).
"""
from flask import Flask, jsonify, request, send_from_directory

app = Flask(__name__, static_folder="static", static_url_path="")

USERS = {
    "alice": {
        "displayName": "Alice",
        "bio": "Hi, I'm Alice. I like tea and weird URL parsers.",
    },
    "bob": {
        "displayName": "Bob",
        "bio": "Bob here. Coffee enthusiast, amateur ROP author.",
    },
}


@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.route("/profile.html")
def profile_page():
    return send_from_directory("static", "profile.html")


@app.route("/api/users/<username>/profile")
def api_user_profile(username):
    """Legitimate endpoint: returns the user's public profile JSON."""
    user = USERS.get(username)
    if user is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(user)


@app.route("/api/echo")
def api_echo():
    """
    Innocuous-looking debugging endpoint. Returns whatever 'data' is
    supplied, wrapped in a profile-shaped object.

    This is the 'sink' the CSPT aims at: since it shares the /api/ path
    prefix with the real endpoint and the SPA doesn't validate the fetch
    target, `../echo?data=<payload>` reaches it from the profile page's
    fetch call.
    """
    data = request.args.get("data", "")
    return jsonify({"displayName": "Echo", "bio": data})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
