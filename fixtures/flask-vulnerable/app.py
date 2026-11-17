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

# The runtime agent's three call sites.
#
# Vibe Killer does not instrument anything: it prints an agent for an operator
# to add to their own application and delete afterwards. This fixture keeps the
# call sites so that the runtime layer can be exercised against a real server
# rather than against a recorder, which is the only way to find out whether the
# shipped agent works. The module itself is not committed here -- a run copies
# it in -- so the stub below is what makes the fixture still runnable on its
# own, and the agent does nothing anyway unless VIBEKILLER_SINK is set.
try:
    import vibekiller_agent
except ImportError:

    class _NoAgent:
        @staticmethod
        def attach(_app):
            pass

        @staticmethod
        def note_auth(_name):
            pass

        @staticmethod
        def observe_cursor(cursor):
            return cursor

    vibekiller_agent = _NoAgent()

vibekiller_agent.attach(app)

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
        vibekiller_agent.note_auth("require_auth")
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

# An ordinary "who am I" endpoint, which every API of this shape has and these
# fixtures did not. It carries no weakness: it requires authentication and
# returns the caller's own record.
#
# It is here because exposure.shared-trust-domain needs one. That check asks
# whether a token minted for one declared component is accepted by another,
# and it establishes that by finding an endpoint on the neighbour that refuses
# an anonymous request -- deliberately from a short fixed list rather than by
# discovery. With no such endpoint anywhere in the fixtures, the check could
# run and could never find anything, which is how it sat for as long as it
# existed.
@app.route("/api/me", methods=["GET"])
@require_auth
def whoami():
    return jsonify({"id": g.user["id"], "name": g.user["name"], "role": g.user["role"]})


# VULN (idor.sequential-id-access): authenticated, then looks the order up by
# the id in the URL with no ownership check.
#
# VULN (runtime.query-missing-owner-filter): the statement is parameterised, so
# there is no injection here, and it constrains the id and nothing else. That
# is the weakness only the runtime layer can see: from outside, a response
# carrying someone else's record looks the same whether the query filtered on
# the owner and the application leaked it afterwards, or the query never
# mentioned the owner at all. The agent reports the statement's shape, which
# settles it.
@app.route("/api/orders/<int:order_id>", methods=["GET"])
@require_auth
def get_order(order_id):
    cursor = vibekiller_agent.observe_cursor(get_db().cursor())
    cursor.execute("SELECT id, item, user_id, note FROM orders WHERE id = ?", (order_id,))
    row = cursor.fetchone()
    if row is None:
        return jsonify({"error": "not found"}), 404
    return jsonify({"id": row[0], "item": row[1], "user_id": row[2], "note": row[3]})


# VULN (runtime.auth-check-not-fired): this decorator was added to protect the
# route and never checks anything -- the body was lost in a refactor, or it was
# a stub nobody finished. Static analysis sees a route with authorization on it
# and is satisfied; a caller with no credentials is served. Only an observation
# of what actually ran during the request can tell the difference, which is the
# whole reason the runtime layer exists.
def require_admin(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        return fn(*args, **kwargs)

    return wrapper


@app.route("/api/admin/stats", methods=["GET"])
@require_admin
def admin_stats():
    return jsonify({"orders": len(ORDERS), "profiles": len(PROFILES)})


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
    cursor = vibekiller_agent.observe_cursor(conn.cursor())
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
        g.db.execute("CREATE TABLE orders (id INTEGER, item TEXT, user_id TEXT, note TEXT)")
        for order in ORDERS:
            g.db.execute(
                "INSERT INTO orders VALUES (?, ?, ?, ?)",
                (order["id"], order["item"], order["user_id"], order.get("note", "")),
            )
        g.db.commit()
    return g.db


if __name__ == "__main__":
    # VULN (misconfig.debug-mode-enabled): the interactive debugger allows
    # code execution on anyone who can load an error page.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=True)
