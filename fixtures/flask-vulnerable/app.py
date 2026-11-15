"""Deliberately vulnerable Flask fixture for Vibe Killer's test suite.

NOT A REAL APPLICATION. DO NOT DEPLOY. Every weakness here is intentional and
paired with a check in Vibe Killer; ../flask-patched/app.py is the same
application with each one fixed, so the suite can prove each check both fires
and stays silent.

It exists in a second stack on purpose: the stack adapters and auto-detection
are part of what is under test, not just the checks.
"""

import hashlib
import os
import random
import sqlite3
import subprocess

import jwt
import requests
from flask import Flask, g, jsonify, request

app = Flask(__name__)

# VULN: the signing secret is in the source, so anyone with the repository can
# mint a token for any user.
JWT_SECRET = "supersecret"

# Seeded throwaway data. The 9000x records are the canaries Vibe Killer reads
# to prove a boundary failed; each carries a distinctive marker.
USERS = {
    "userA-token": {"id": "userA", "name": "Ada Example", "role": "member"},
    "userB-token": {"id": "userB", "name": "Grace Example", "role": "member"},
    "admin-token": {"id": "admin", "name": "Root Example", "role": "admin"},
}

ORDERS = [
    {"id": 90001, "user_id": "userB", "item": "Decoy order", "total": 4242, "note": "VK-CANARY-USERB"},
    {"id": 90002, "user_id": "userA", "item": "Decoy order", "total": 1111, "note": "VK-CANARY-USERA"},
]

PROFILES = [
    {"id": 90001, "user_id": "userB", "email": "grace@example.invalid", "note": "VK-CANARY-USERB-PROFILE"},
    {"id": 90002, "user_id": "userA", "email": "ada@example.invalid", "note": "VK-CANARY-USERA-PROFILE"},
]


def current_user():
    """Authentication. This part is fine; the authorization is what is missing."""
    header = request.headers.get("Authorization", "")
    token = header[7:] if header.lower().startswith("bearer ") else ""
    return USERS.get(token)


def require_auth(fn):
    """Authentication decorator, applied per route by hand."""
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if user is None:
            return jsonify({"error": "authentication required"}), 401
        g.user = user
        return fn(*args, **kwargs)

    return wrapper


# VULN: the origin is reflected and credentials are allowed, so any site a
# logged-in user visits can call this API as them.
@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "*")
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response


@app.route("/health")
def health():
    return jsonify({"ok": True})


# VULN (idor.sequential-id-access): authenticated, then looks the order up by
# the id in the URL with no ownership check.
@app.route("/api/orders/<int:order_id>", methods=["GET"])
@require_auth
def get_order(order_id):
    for order in ORDERS:
        if order["id"] == order_id:
            return jsonify(order)
    return jsonify({"error": "not found"}), 404


# VULN (authz.unprotected-endpoint): no authentication at all, and it returns
# another user's profile.
@app.route("/api/profiles/<int:profile_id>", methods=["GET"])
def get_profile(profile_id):
    for profile in PROFILES:
        if profile["id"] == profile_id:
            return jsonify(profile)
    return jsonify({"error": "not found"}), 404


# VULN (authz.mass-assignment): the whole JSON body becomes the record.
@app.route("/api/orders", methods=["POST"])
@require_auth
def create_order():
    payload = request.json or {}
    order = {"id": random.randint(1, 100000)}
    order.update(payload)
    ORDERS.append(order)
    return jsonify(order), 201


# VULN (injection.sql-string-built-from-input): the search term is formatted
# into the statement, so it becomes part of the query's syntax.
@app.route("/api/search", methods=["GET"])
@require_auth
def search():
    term = request.args.get("q", "")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(f"SELECT id, item FROM orders WHERE item LIKE '%{term}%'")
    return jsonify([{"id": r[0], "item": r[1]} for r in cursor.fetchall()])


# VULN (traversal.path-built-from-input): the filename is joined without being
# resolved and checked, so ../ escapes the directory.
@app.route("/api/files/<path:name>", methods=["GET"])
@require_auth
def read_file(name):
    path = os.path.join(os.path.dirname(__file__), "uploads", name)
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


# VULN (ssrf.user-supplied-url-fetched): the server fetches a caller-supplied
# URL, lending it the server's network position.
@app.route("/api/import", methods=["POST"])
@require_auth
def import_feed():
    url = (request.json or {}).get("url")
    response = requests.get(url, timeout=10)
    return jsonify({"bytes": len(response.content)})


# VULN (injection.command-built-from-input): shell=True hands the assembled
# string to a shell, which parses the request value as syntax.
@app.route("/api/convert", methods=["POST"])
@require_auth
def convert():
    name = (request.json or {}).get("filename", "")
    output = subprocess.run(f"convert {name} /tmp/out.png", shell=True, capture_output=True)
    return jsonify({"output": output.stdout.decode("utf-8", "replace")})


# VULN (auth.jwt-not-verified): decodes without verifying the signature, so
# the claims are client-controlled.
@app.route("/api/session", methods=["GET"])
def session_info():
    token = request.headers.get("X-Session-JWT", "")
    if not token:
        return jsonify({"user": None})
    claims = jwt.decode(token, verify=False)
    return jsonify({"user": claims.get("sub")})


# VULN (crypto.predictable-token): a reset token from a non-cryptographic
# generator can be reproduced.
@app.route("/api/reset", methods=["POST"])
def reset_password():
    reset_token = "".join(random.choice("abcdef0123456789") for _ in range(32))
    return jsonify({"reset_token": reset_token})


# VULN (crypto.password-fast-digest): a general-purpose digest, no work factor,
# no salt.
def hash_password(password):
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(":memory:")
        g.db.execute("CREATE TABLE orders (id INTEGER, item TEXT, user_id TEXT)")
        for order in ORDERS:
            g.db.execute(
                "INSERT INTO orders VALUES (?, ?, ?)",
                (order["id"], order["item"], order["user_id"]),
            )
        g.db.commit()
    return g.db


if __name__ == "__main__":
    # VULN (misconfig.debug-mode-enabled): the interactive debugger allows
    # code execution on anyone who can load an error page.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=True)
