"""Deliberately vulnerable FastAPI fixture for Vibe Killer's test suite.

NOT A REAL APPLICATION. DO NOT DEPLOY. Every weakness here is intentional and
paired with a rule in the pack; ../fastapi-patched/main.py is the same
application with each one fixed, so the suite can prove each rule both fires
and stays silent.

This is the third stack, and it exists for a specific reason rather than for
breadth. The Python adapter has always claimed FastAPI support -- it detects
the framework and extracts routes through APIRouter and include_router -- but
nothing proved it, so "implemented" and "working" were the same word for it.
The routes below are deliberately declared with a prefixed APIRouter mounted
through include_router, which is the extraction path under test.

Writing it also showed what did not carry across, and keeping the weaknesses
here rather than trimming them is what let that be measured instead of
assumed. Four rules were silent on this file when it was written, for reasons
that had nothing to do with the fixture:

  idor-missing-ownership-check-python was anchored on @$APP.route(...), which
  @router.get(...) does not match, so the pack's flagship access-control rule
  could not fire on FastAPI at all.

  The taint rules took their sources from request.args, request.form and
  request.json, and FastAPI has none of those: it parses the query string,
  path and body into the handler's parameters, so the taint never started.

  jwt-accepts-unsigned-algorithm only matched "none" as the first entry in the
  algorithms list, and the list here is ["HS256", "none"] -- which is the
  shape it takes in practice, since "none" gets appended rather than
  substituted.

  tls-verification-disabled matched nothing on Python whatsoever. This
  docstring used to claim that one did fire; it did not, and no test
  contradicted the claim because nothing asserted that any rule fires
  anywhere.

All four report here now. rules/testdata pins each of them to a line, and
rules/coverage_test.go refuses a rule that nothing pins, which is the part
that keeps this from happening again.

What is still missing is not FastAPI-specific and is not in this file. Counted
across the pack, eight of its twenty-five contract rule ids have no Python
spelling at all, in any framework: authz.endpoint-missing-auth,
authz.client-supplied-role, authz.mass-assignment,
auth.session-cookie-unprotected, auth.token-without-expiry,
injection.nosql-operator-injection, misconfig.error-detail-disclosed and
misconfig.static-exposure are matched only against Express idioms. Two run the
other way -- misconfig.debug-mode-enabled and misconfig.wildcard-allowed-hosts
are Python-only.

None of those weaknesses are present in this file, so there is nothing here to
annotate. The gap is tracked as issue #5 rather than as a comment pretending
to be one.
"""

import hashlib
import os
import random
import sqlite3

import jwt
import requests
from fastapi import APIRouter, FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Vibe Killer FastAPI fixture")

# VULN (auth.jwt-weak-secret): the signing secret is in the source, so anyone
# with the repository can mint a token for any user.
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

# The prefix and the mount below are what the adapter has to follow to produce
# "/api/orders/{order_id}" rather than "/orders/{order_id}".
router = APIRouter(prefix="/api")


def current_user(authorization):
    """Authentication. This part is fine; the authorization is what is missing."""
    token = authorization[7:] if (authorization or "").lower().startswith("bearer ") else ""
    return USERS.get(token)


def require_auth(authorization):
    user = current_user(authorization)
    if user is None:
        raise HTTPException(status_code=401, detail="authentication required")
    return user


class OrderIn(BaseModel):
    # VULN (authz.mass-assignment): the model accepts whatever the caller
    # sends, including fields the caller should not control.
    model_config = {"extra": "allow"}

    item: str = "unnamed"


@app.get("/health")
def health():
    return {"ok": True}


# VULN (idor.sequential-id-access): authenticated, then looks the order up by
# the id in the path with no ownership check.
#
# This is the route that recorded the gap, and now records the fix: the rule's
# patterns were anchored on @$APP.route(...) and this decorator is
# @router.get(...), so it could not match. The decorator is matched generically
# now and the finding is reported statically as well as over HTTP.
@router.get("/orders/{order_id}")
def get_order(order_id: int, authorization: str = Header(default="")):
    require_auth(authorization)
    for order in ORDERS:
        if order["id"] == order_id:
            return order
    raise HTTPException(status_code=404, detail="not found")


# VULN (authz.unprotected-endpoint): no authentication at all, and it returns
# another user's profile.
@router.get("/profiles/{profile_id}")
def get_profile(profile_id: int):
    for profile in PROFILES:
        if profile["id"] == profile_id:
            return profile
    raise HTTPException(status_code=404, detail="not found")


@router.post("/orders", status_code=201)
def create_order(payload: OrderIn, authorization: str = Header(default="")):
    require_auth(authorization)
    # VULN: the whole validated-but-permissive body becomes the record.
    order = {"id": random.randint(1, 100000)}
    order.update(payload.model_dump())
    ORDERS.append(order)
    return order


# VULN (injection.sql-string-built-from-input): the search term is formatted
# into the statement, so it becomes part of the query's syntax.
@router.get("/search")
def search(q: str = "", authorization: str = Header(default="")):
    require_auth(authorization)
    cursor = get_db().cursor()
    cursor.execute(f"SELECT id, item FROM orders WHERE item LIKE '%{q}%'")
    return [{"id": row[0], "item": row[1]} for row in cursor.fetchall()]


# VULN (traversal.path-built-from-input): the filename is joined without being
# resolved and checked, so ../ escapes the directory.
@router.get("/files/{name}")
def read_file(name: str, authorization: str = Header(default="")):
    require_auth(authorization)
    path = os.path.join(os.path.dirname(__file__), "uploads", name)
    with open(path, "r", encoding="utf-8") as handle:
        return {"content": handle.read()}


# VULN (ssrf.user-supplied-url-fetched) and (misconfig.tls-verification-disabled):
# the server fetches a caller-supplied URL, and does it without verifying the
# certificate.
#
# Two findings on one line, and neither of them used to report.
#
# unsafe-fetch-of-user-supplied-url-python is a taint rule, and its sources
# were a Flask request object that FastAPI does not have: the url arrives as a
# handler parameter, so the taint never started. The rule now takes a route
# handler's parameters as sources, which is the shape FastAPI actually uses.
#
# tls-verification-disabled was the other one. It declared python among its
# languages and matched nothing on Python, silently, with errors: 0.
@router.post("/import")
def import_feed(url: str, authorization: str = Header(default="")):
    require_auth(authorization)
    response = requests.get(url, timeout=10, verify=False)
    return {"bytes": len(response.content)}


# VULN (auth.jwt-not-verified): decodes without verifying the signature, so
# the claims are client-controlled.
@router.get("/session")
def session_info(x_session_jwt: str = Header(default="")):
    if not x_session_jwt:
        return {"user": None}
    claims = jwt.decode(x_session_jwt, options={"verify_signature": False})
    return {"user": claims.get("sub")}


# VULN (auth.jwt-unsigned-accepted): "none" is accepted as an algorithm, so an
# unsigned token is treated as valid.
@router.get("/session/strict")
def session_strict(x_session_jwt: str = Header(default="")):
    claims = jwt.decode(x_session_jwt, JWT_SECRET, algorithms=["HS256", "none"])
    return {"user": claims.get("sub")}


# VULN (crypto.predictable-token): a reset token from a non-cryptographic
# generator can be reproduced.
@router.post("/reset")
def reset_password():
    reset_token = "".join(random.choice("abcdef0123456789") for _ in range(32))
    return {"reset_token": reset_token}


# VULN (auth.api-key-timing): comparing a secret with == leaks its length and
# its matching prefix through timing.
@router.post("/admin/rotate")
def rotate(x_api_key: str = Header(default="")):
    expected_api_key = os.environ.get("ADMIN_API_KEY", "")
    if x_api_key == expected_api_key:
        return {"rotated": True}
    raise HTTPException(status_code=403, detail="forbidden")


# VULN (crypto.password-fast-digest): a general-purpose digest, no work factor,
# no salt.
def hash_password(password):
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def get_db():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE orders (id INTEGER, item TEXT, user_id TEXT)")
    for order in ORDERS:
        conn.execute(
            "INSERT INTO orders VALUES (?, ?, ?)",
            (order["id"], order["item"], order["user_id"]),
        )
    conn.commit()
    return conn


# This is the line the adapter has to follow to resolve the prefix.
app.include_router(router)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("PORT", "5001")))
