"""
SSRF -> Stored XSS lab application.

INTENTIONALLY VULNERABLE. DO NOT DEPLOY.

Vulnerabilities:
  - CWE-918 Server-Side Request Forgery:
      /api/profile fetches the user-supplied profilePicture URL with no
      validation (no scheme allowlist, no host allowlist, no DNS pinning).
  - CWE-79 Stored Cross-Site Scripting:
      The stored profilePicture value is rendered into an <img src="...">
      attribute using Jinja's |safe filter, so attacker-controlled content
      (e.g. "x" onerror="alert(1)") breaks out of the attribute.
"""

import os
import sqlite3
from functools import wraps

import requests
from flask import (
    Flask, g, redirect, render_template, request, session, url_for, jsonify, flash
)
from werkzeug.security import check_password_hash, generate_password_hash

DB_PATH = os.environ.get("DB_PATH", "/app/data/lab.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "lab-insecure-key")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            display_name TEXT,
            bio TEXT DEFAULT '',
            profile_picture TEXT DEFAULT ''
        );
        """
    )
    cur = conn.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        conn.execute(
            "INSERT INTO users (username, password_hash, display_name, bio, profile_picture) VALUES (?, ?, ?, ?, ?)",
            (
                "alice",
                generate_password_hash("password123"),
                "Alice",
                "Hello, I am Alice.",
                "https://via.placeholder.com/150",
            ),
        )
        conn.execute(
            "INSERT INTO users (username, password_hash, display_name, bio, profile_picture) VALUES (?, ?, ?, ?, ?)",
            (
                "bob",
                generate_password_hash("password123"),
                "Bob",
                "Hello, I am Bob.",
                "https://via.placeholder.com/150",
            ),
        )
    conn.commit()
    conn.close()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def current_user():
    uid = session.get("user_id")
    if uid is None:
        return None
    return get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()


@app.route("/")
def index():
    users = get_db().execute("SELECT id, username, display_name FROM users").fetchall()
    return render_template("index.html", users=users, me=current_user())


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        display_name = request.form.get("display_name", "").strip() or username
        if not username or not password:
            flash("username and password required")
            return redirect(url_for("register"))
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password_hash, display_name) VALUES (?, ?, ?)",
                (username, generate_password_hash(password), display_name),
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("username already taken")
            return redirect(url_for("register"))
        flash("registered — please log in")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        row = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if row and check_password_hash(row["password_hash"], password):
            session["user_id"] = row["id"]
            return redirect(url_for("profile", user_id=row["id"]))
        flash("invalid credentials")
        return redirect(url_for("login"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/profile/<int:user_id>")
def profile(user_id):
    row = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        return "not found", 404
    # VULN (CWE-79): profile_picture is rendered into an img src attribute
    # with |safe in the template — no escaping, no attribute quoting guarantee.
    return render_template("profile.html", user=row, me=current_user())


@app.route("/edit", methods=["GET"])
@login_required
def edit():
    return render_template("edit.html", user=current_user())


def _fetch_url_server_side(url: str) -> dict:
    """
    VULN (CWE-918): fetches an arbitrary user-supplied URL from the server.

    The stated purpose is "verify the image exists and record its
    Content-Type / size for thumbnail generation". In reality there is no
    scheme allowlist, no host allowlist, and no DNS resolution pinning, so
    the caller can aim this at:
      - Burp Collaborator (DNS/HTTP interaction oracle)
      - http://internal-service:5000/admin (lab internal service)
      - http://169.254.169.254/ (cloud metadata — not present in this lab,
        but the same class of target)
    """
    result = {"ok": False, "status": None, "content_type": None, "bytes": 0, "error": None}
    try:
        r = requests.get(url, timeout=4, allow_redirects=True, stream=True)
        result["ok"] = True
        result["status"] = r.status_code
        result["content_type"] = r.headers.get("Content-Type")
        # read a small chunk so the request actually completes on the wire
        chunk = next(r.iter_content(chunk_size=2048), b"")
        result["bytes"] = len(chunk)
        r.close()
    except Exception as e:  # noqa: BLE001
        result["error"] = f"{type(e).__name__}: {e}"
    return result


@app.route("/api/profile", methods=["PATCH"])
@login_required
def api_profile_patch():
    data = request.get_json(silent=True) or {}
    updates = {}
    if "displayName" in data:
        updates["display_name"] = str(data["displayName"])
    if "bio" in data:
        updates["bio"] = str(data["bio"])

    fetch_result = None
    if "profilePicture" in data:
        picture = str(data["profilePicture"])
        # VULN (CWE-918): server fetches the URL with no validation.
        fetch_result = _fetch_url_server_side(picture)
        # VULN (CWE-79): stored verbatim; rendered with |safe later.
        updates["profile_picture"] = picture

    if updates:
        cols = ", ".join(f"{k} = ?" for k in updates)
        params = list(updates.values()) + [session["user_id"]]
        db = get_db()
        db.execute(f"UPDATE users SET {cols} WHERE id = ?", params)
        db.commit()

    return jsonify({"ok": True, "updated": list(updates.keys()), "fetch": fetch_result})


@app.route("/edit", methods=["POST"])
@login_required
def edit_post():
    updates = {
        "display_name": request.form.get("display_name", ""),
        "bio": request.form.get("bio", ""),
    }
    picture = request.form.get("profile_picture", "")
    fetch_result = None
    if picture:
        fetch_result = _fetch_url_server_side(picture)
        updates["profile_picture"] = picture
    cols = ", ".join(f"{k} = ?" for k in updates)
    params = list(updates.values()) + [session["user_id"]]
    db = get_db()
    db.execute(f"UPDATE users SET {cols} WHERE id = ?", params)
    db.commit()
    if fetch_result is not None:
        flash(f"server fetched URL: {fetch_result}")
    return redirect(url_for("profile", user_id=session["user_id"]))


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
