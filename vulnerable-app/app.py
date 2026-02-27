"""
Deliberately Vulnerable Web Application — Cyber Range Target
=============================================================
This Flask app exposes endpoints that mimic real-world vulnerability
patterns, centred on CVE-2014-6271 (Shellshock).

WARNING: This application is INTENTIONALLY INSECURE.
         Run it ONLY inside the provided Docker container.
"""

import os
import sqlite3
import subprocess

from flask import Flask, request, jsonify

app = Flask(__name__)

DB_PATH = "/tmp/cyberrange.db"


def _init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            role     TEXT
        );
        INSERT OR IGNORE INTO users VALUES (1, 'admin',    'superuser');
        INSERT OR IGNORE INTO users VALUES (2, 'operator', 'user');
        INSERT OR IGNORE INTO users VALUES (3, 'guest',    'readonly');

        CREATE TABLE IF NOT EXISTS secrets (
            id   INTEGER PRIMARY KEY,
            flag TEXT
        );
        INSERT OR IGNORE INTO secrets VALUES
            (1, 'FLAG{sh3llsh0ck_CVE-2014-6271_pwned}');
        """
    )
    conn.commit()
    conn.close()


# ── Landing page ────────────────────────────────────────────────────
@app.route("/")
def index():
    return (
        "<html><head><title>System Dashboard</title></head>"
        "<body>"
        "<h1>System Health Dashboard v1.2.3</h1>"
        "<p>Server: Apache/2.2.22 (Ubuntu)</p>"
        "<ul>"
        '<li><a href="/cgi-bin/status">/cgi-bin/status</a> — server health check</li>'
        '<li><a href="/api/ping?host=127.0.0.1">/api/ping</a> — network diagnostic</li>'
        '<li><a href="/api/users?username=admin">/api/users</a> — user directory</li>'
        "</ul>"
        "</body></html>"
    )


# ── CVE-2014-6271  Shellshock-style CGI endpoint ───────────────────
@app.route("/cgi-bin/status")
def cgi_status():
    """
    Simulates a Bash CGI script that inherits HTTP headers as env vars.
    The User-Agent value is injected straight into a bash -c invocation,
    mirroring the root cause of Shellshock: unsanitised environment
    variable content interpreted by Bash.
    """
    user_agent = request.headers.get("User-Agent", "Unknown")

    try:
        result = subprocess.run(
            [
                "bash",
                "-c",
                (
                    f'echo "Content-Type: text/plain";'
                    f'echo "Server: Apache/2.2.22";'
                    f'echo "X-Powered-By: Bash/4.2";'
                    f'echo;'
                    f'echo "System Status: OK";'
                    f'echo "Uptime: $(uptime -p 2>/dev/null || echo unknown)";'
                    f'echo "User-Agent: {user_agent}"'
                ),
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout + result.stderr, 200, {"Content-Type": "text/plain"}
    except subprocess.TimeoutExpired:
        return "Request timed out\n", 504, {"Content-Type": "text/plain"}


# ── Command-injection via ping ──────────────────────────────────────
@app.route("/api/ping")
def api_ping():
    """
    Passes `host` query-param directly into a shell command —
    classic OS command injection.
    """
    host = request.args.get("host", "127.0.0.1")
    try:
        result = subprocess.run(
            f"ping -c 1 -W 2 {host}",
            shell=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return jsonify({"stdout": result.stdout, "stderr": result.stderr})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "timeout"}), 504


# ── SQL-injection via user lookup ───────────────────────────────────
@app.route("/api/users")
def api_users():
    """
    Builds a SQL query via string concatenation — textbook SQLi.
    """
    username = request.args.get("username", "")
    if not username:
        return jsonify({"error": "username parameter required"}), 400

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    query = f"SELECT id, username, role FROM users WHERE username = '{username}'"
    try:
        cur.execute(query)
        rows = cur.fetchall()
        users = [{"id": r[0], "username": r[1], "role": r[2]} for r in rows]
        return jsonify({"query": query, "results": users})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    finally:
        conn.close()


# ── robots.txt — mild information disclosure ────────────────────────
@app.route("/robots.txt")
def robots():
    return (
        "User-agent: *\n"
        "Disallow: /cgi-bin/\n"
        "Disallow: /api/\n"
        "Disallow: /admin/\n"
        "Disallow: /backup/\n"
    ), 200, {"Content-Type": "text/plain"}


# ── Server header leak on every response ────────────────────────────
@app.after_request
def add_headers(response):
    response.headers["Server"] = "Apache/2.2.22 (Ubuntu)"
    response.headers["X-Powered-By"] = "Bash/4.2"
    return response


if __name__ == "__main__":
    _init_db()
    app.run(host="0.0.0.0", port=8080, debug=False)
