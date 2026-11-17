"""The flask-vulnerable fixture with every weakness fixed.

This proves the other half of each check: that it stays silent on correct code.
A scanner that fires on both files is not detecting anything.
"""

import os
import secrets
import sqlite3
import subprocess
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse

import jwt
import requests
from flask import Flask, g, jsonify, request

app = Flask(__name__)

# FIX: the signing key comes from the environment, so it is not in the
# repository and can be rotated without a code change.
JWT_SECRET = os.environ["JWT_SIGNING_KEY"]

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

# FIX: an explicit allowlist instead of reflecting whatever origin asked.
ALLOWED_ORIGINS = {"http://localhost:5173", "https://app.example.invalid"}

UPLOAD_ROOT = (Path(__file__).parent / "uploads").resolve()

IMPORT_ALLOWED_HOSTS = {"feeds.example.invalid"}


def current_user():
    header = request.headers.get("Authorization", "")
    token = header[7:] if header.lower().startswith("bearer ") else ""
    return USERS.get(token)


def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if user is None:
            return jsonify({"error": "authentication required"}), 401
        g.user = user
        return fn(*args, **kwargs)

    return wrapper


@app.after_request
def add_headers(response):
    origin = request.headers.get("Origin")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Vary"] = "Origin"

    # FIX: response hardening headers, set once for every route.
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


# FIX: one error handler, so no route can leak a traceback by forgetting to
# catch something.
@app.errorhandler(Exception)
def handle_error(err):
    correlation_id = secrets.token_hex(8)
    app.logger.exception("[%s] unhandled error", correlation_id)
    return jsonify({"error": "internal error", "correlation_id": correlation_id}), 500


@app.route("/health")
def health():
    return jsonify({"ok": True})

# The same "who am I" endpoint as its vulnerable twin, and the reason it exists
# is the same: exposure.shared-trust-domain needs an endpoint on a neighbour
# that refuses an anonymous request before it can ask whether the other
# component's token is accepted.
@app.route("/api/me", methods=["GET"])
@require_auth
def whoami():
    return jsonify({"id": g.user["id"], "name": g.user["name"], "role": g.user["role"]})


# FIX: the authenticated principal is part of the lookup, so a record
# belonging to someone else is never loaded. A miss returns 404 rather than
# 403, so the endpoint does not confirm another user's record exists.
@app.route("/api/orders/<int:order_id>", methods=["GET"])
@require_auth
def get_order(order_id):
    for order in ORDERS:
        if order["id"] == order_id and order["user_id"] == g.user["id"]:
            return jsonify(order)
    return jsonify({"error": "not found"}), 404


# FIX: authentication is required, and the lookup is scoped to the caller.
@app.route("/api/profiles/<int:profile_id>", methods=["GET"])
@require_auth
def get_profile(profile_id):
    for profile in PROFILES:
        if profile["id"] == profile_id and profile["user_id"] == g.user["id"]:
            return jsonify(profile)
    return jsonify({"error": "not found"}), 404


# FIX: the accepted fields are named explicitly, and the owner comes from the
# session rather than from the request.
@app.route("/api/orders", methods=["POST"])
@require_auth
def create_order():
    payload = request.get_json(silent=True) or {}
    item = payload.get("item")
    total = payload.get("total")
    if not isinstance(item, str) or not isinstance(total, (int, float)):
        return jsonify({"error": "item and total are required"}), 400

    order = {
        "id": secrets.randbelow(100000),
        "user_id": g.user["id"],
        "item": item,
        "total": total,
    }
    ORDERS.append(order)
    return jsonify(order), 201


# FIX: the search term is a bound parameter, so it is data and never syntax.
@app.route("/api/search", methods=["GET"])
@require_auth
def search():
    term = request.args.get("q", "")
    cursor = get_db().cursor()
    cursor.execute(
        "SELECT id, item FROM orders WHERE item LIKE ? AND user_id = ?",
        (f"%{term}%", g.user["id"]),
    )
    return jsonify([{"id": r[0], "item": r[1]} for r in cursor.fetchall()])


# FIX: the resolved path is checked against the directory it must stay inside,
# which holds even when the input carries encoded traversal sequences.
@app.route("/api/files/<path:name>", methods=["GET"])
@require_auth
def read_file(name):
    resolved = (UPLOAD_ROOT / name).resolve()
    if not resolved.is_relative_to(UPLOAD_ROOT):
        return jsonify({"error": "invalid filename"}), 400
    if not resolved.is_file():
        return jsonify({"error": "not found"}), 404
    return resolved.read_text(encoding="utf-8")


# FIX: only an allowlisted host is fetched, over HTTPS, with redirects off so
# the destination cannot be changed after the check.
@app.route("/api/import", methods=["POST"])
@require_auth
def import_feed():
    url = (request.get_json(silent=True) or {}).get("url", "")
    parsed = urlparse(str(url))
    if parsed.scheme != "https" or parsed.hostname not in IMPORT_ALLOWED_HOSTS:
        return jsonify({"error": "host not allowed"}), 400

    response = requests.get(url, timeout=10, allow_redirects=False)
    return jsonify({"bytes": len(response.content)})


# FIX: an argument list and no shell, plus a check that the filename is one we
# expect.
@app.route("/api/convert", methods=["POST"])
@require_auth
def convert():
    name = str((request.get_json(silent=True) or {}).get("filename", ""))
    if not name or not all(c.isalnum() or c in "._-" for c in name):
        return jsonify({"error": "invalid filename"}), 400

    source = (UPLOAD_ROOT / name).resolve()
    if not source.is_relative_to(UPLOAD_ROOT):
        return jsonify({"error": "invalid filename"}), 400

    output = subprocess.run(
        ["convert", str(source), str(UPLOAD_ROOT / "out.png")],
        capture_output=True,
        check=False,
    )
    return jsonify({"output": output.stdout.decode("utf-8", "replace")})


# FIX: the signature is verified and the algorithm list is pinned.
@app.route("/api/session", methods=["GET"])
def session_info():
    token = request.headers.get("X-Session-JWT", "")
    if not token:
        return jsonify({"user": None})
    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        return jsonify({"user": None}), 401
    return jsonify({"user": claims.get("sub")})


# FIX: a cryptographic source, so the token cannot be reproduced.
@app.route("/api/reset", methods=["POST"])
def reset_password():
    return jsonify({"reset_token": secrets.token_urlsafe(32)})


# FIX: a password hash with a work factor and a per-password salt.
def hash_password(password):
    from argon2 import PasswordHasher

    return PasswordHasher().hash(password)


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
    # FIX: debug comes from the environment and defaults to off, so the
    # interactive debugger is never reachable by accident.
    app.run(
        host="127.0.0.1",
        port=int(os.environ.get("PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG") == "1",
    )
