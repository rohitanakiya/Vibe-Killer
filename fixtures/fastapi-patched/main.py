"""The fastapi-vulnerable fixture with every weakness fixed.

NOT A REAL APPLICATION, but it is the half of the pair that matters most: the
suite asserts the rule pack is *completely silent* here. A rule that fires on
both versions is not detecting anything, it is pattern-matching on the domain,
and that assertion is the only thing that catches it.

Each fix is the one a reviewer would actually make, not the smallest edit that
quiets a rule. That distinction is load-bearing. open() on a non-literal path
inside a route body is reported wherever it appears, and the rule's only
exemption is Flask's send_from_directory -- so the file route here uses
FileResponse over a path that has been resolved and confirmed to be under the
intended root, which is both the idiomatic FastAPI answer and genuinely safe,
rather than moving the same unsafe open() into a helper where the rule happens
not to look.
"""

import hmac
import os
import secrets
import sqlite3
from pathlib import Path

import jwt
import requests
from argon2 import PasswordHasher
from fastapi import APIRouter, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

app = FastAPI(title="Vibe Killer FastAPI fixture (patched)")

# FIXED: the signing secret comes from the environment, so the repository does
# not contain it and rotating it does not need a deploy of new code.
JWT_SECRET = os.environ["FIXTURE_JWT_SECRET"]

UPLOAD_ROOT = (Path(__file__).parent / "uploads").resolve()

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

router = APIRouter(prefix="/api")

password_hasher = PasswordHasher()


def current_user(authorization):
    token = authorization[7:] if (authorization or "").lower().startswith("bearer ") else ""
    return USERS.get(token)


def require_auth(authorization):
    user = current_user(authorization)
    if user is None:
        raise HTTPException(status_code=401, detail="authentication required")
    return user


class OrderIn(BaseModel):
    # FIXED: unknown fields are rejected, so the caller cannot set columns the
    # endpoint never meant to expose.
    model_config = {"extra": "forbid"}

    item: str = "unnamed"


@app.get("/health")
def health():
    return {"ok": True}


# FIXED: the lookup is scoped to the caller, so another user's order is simply
# not found rather than being returned.
@router.get("/orders/{order_id}")
def get_order(order_id: int, authorization: str = Header(default="")):
    user = require_auth(authorization)
    for order in ORDERS:
        if order["id"] == order_id and order["user_id"] == user["id"]:
            return order
    raise HTTPException(status_code=404, detail="not found")


# FIXED: authentication is required, and a profile is only readable by its
# owner.
@router.get("/profiles/{profile_id}")
def get_profile(profile_id: int, authorization: str = Header(default="")):
    user = require_auth(authorization)
    for profile in PROFILES:
        if profile["id"] == profile_id and profile["user_id"] == user["id"]:
            return profile
    raise HTTPException(status_code=404, detail="not found")


@router.post("/orders", status_code=201)
def create_order(payload: OrderIn, authorization: str = Header(default="")):
    user = require_auth(authorization)
    # FIXED: the record is assembled field by field, and the owner comes from
    # the session rather than from the body.
    order = {
        "id": secrets.randbelow(100000) + 1,
        "item": payload.item,
        "user_id": user["id"],
        "total": 0,
    }
    ORDERS.append(order)
    return order


# FIXED: the term is bound as a parameter, so it is data to the database rather
# than syntax.
@router.get("/search")
def search(q: str = "", authorization: str = Header(default="")):
    require_auth(authorization)
    cursor = get_db().cursor()
    cursor.execute("SELECT id, item FROM orders WHERE item LIKE ?", (f"%{q}%",))
    return [{"id": row[0], "item": row[1]} for row in cursor.fetchall()]


# FIXED: the path is resolved and confirmed to be inside the intended root
# before anything is read, so ../ cannot escape it. FileResponse streams the
# file without the route ever opening a caller-influenced path itself.
@router.get("/files/{name}")
def read_file(name: str, authorization: str = Header(default="")):
    require_auth(authorization)
    candidate = (UPLOAD_ROOT / name).resolve()
    if not candidate.is_relative_to(UPLOAD_ROOT) or not candidate.is_file():
        raise HTTPException(status_code=404, detail="not found")
    return FileResponse(candidate)


# FIXED: only an allowlisted host is fetched, and the certificate is verified.
ALLOWED_FEED_HOSTS = frozenset({"feeds.example.invalid"})


@router.post("/import")
def import_feed(url: str, authorization: str = Header(default="")):
    require_auth(authorization)

    from urllib.parse import urlparse

    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_FEED_HOSTS:
        raise HTTPException(status_code=400, detail="that host is not allowed")

    response = requests.get(url, timeout=10)
    return {"bytes": len(response.content)}


# FIXED: the signature is verified, with the algorithm pinned, so the claims
# are the issuer's rather than the caller's.
@router.get("/session")
def session_info(x_session_jwt: str = Header(default="")):
    if not x_session_jwt:
        return {"user": None}
    try:
        claims = jwt.decode(x_session_jwt, JWT_SECRET, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="invalid token")
    return {"user": claims.get("sub")}


@router.get("/session/strict")
def session_strict(x_session_jwt: str = Header(default="")):
    try:
        claims = jwt.decode(x_session_jwt, JWT_SECRET, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="invalid token")
    return {"user": claims.get("sub")}


# FIXED: a cryptographic source, so the token cannot be reproduced by guessing
# the generator's state.
@router.post("/reset")
def reset_password():
    return {"reset_token": secrets.token_urlsafe(32)}


# FIXED: a constant-time comparison, so neither the length nor a matching
# prefix leaks through timing.
@router.post("/admin/rotate")
def rotate(x_api_key: str = Header(default="")):
    expected = os.environ.get("ADMIN_API_KEY", "")
    if not expected or not hmac.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=403, detail="forbidden")
    return {"rotated": True}


# FIXED: a password hashing function with a work factor, salted per password by
# the library.
def hash_password(password):
    return password_hasher.hash(password)


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


app.include_router(router)


if __name__ == "__main__":
    import uvicorn

    # FIXED: debug and reload are driven from the environment and default off.
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=int(os.environ.get("PORT", "5001")),
        reload=os.environ.get("FIXTURE_RELOAD") == "1",
    )
