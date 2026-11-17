"""Behaviour fixture for the Python rules in access-control.yaml.

NOT AN APPLICATION. See the header of misconfiguration.py.

The match range for these rules is the whole handler, deliberately: the
ownership exclusions are evaluated against the range, so narrowing it would
switch them off silently. That is why each annotation sits above the decorator
or the `def` rather than above the lookup.
"""

from functools import lru_cache
from fastapi import APIRouter, Depends, Header, HTTPException
from flask import Flask, g, jsonify, request
from pydantic import BaseModel

app = Flask(__name__)
router = APIRouter(prefix="/api")

ORDERS = [{"id": 1, "user_id": "userA", "item": "Decoy order"}]
NOTES = []


class NoteIn(BaseModel):
    text: str = ""


class OrderIn(BaseModel):
    item: str = ""


class PromoteIn(BaseModel):
    role: str = "member"


def get_current_user():
    raise NotImplementedError("fixture only")


def require_auth(fn):
    return fn


class Order:
    query = None
    objects = None


def get_object_or_404(model, **kwargs):
    raise NotImplementedError("fixture only")


def JsonResponse(payload):
    raise NotImplementedError("fixture only")


# --- idor-missing-ownership-check-python (Flask) --------------------------

# ruleid: idor-missing-ownership-check-python
@app.route("/flask/orders/<int:order_id>")
def flask_order(order_id):
    order = Order.query.get_or_404(order_id)
    return jsonify({"id": order.id})


# ok: idor-missing-ownership-check-python
@app.route("/flask/orders-scoped/<int:order_id>")
def flask_order_scoped(order_id):
    order = Order.query.filter_by(id=order_id, user_id=current_user.id).first_or_404()
    return jsonify({"id": order.id})


# --- idor-missing-ownership-check-python (FastAPI) -----------------------
#
# FastAPI writes @router.get, not @app.route. Every alternative in this rule
# was anchored on `.route`, so the pack's flagship access-control finding
# could not fire on a FastAPI application at all.

# ruleid: idor-missing-ownership-check-python
@router.get("/orders/{order_id}")
def fastapi_order(order_id: int):
    for order in ORDERS:
        if order["id"] == order_id:
            return order
    raise HTTPException(status_code=404, detail="not found")


# ok: idor-missing-ownership-check-python
@router.get("/orders-scoped/{order_id}")
def fastapi_order_scoped(order_id: int, user_id: str = Header(default="")):
    for order in ORDERS:
        if order["id"] == order_id and order["user_id"] == user_id:
            return order
    raise HTTPException(status_code=404, detail="not found")


# --- idor-missing-ownership-check-django ---------------------------------
#
# A Django function-based view has no decorator to anchor on: the URL is bound
# in urls.py and the first parameter is the request.

# ruleid: idor-missing-ownership-check-django
def order_detail(request, order_id):
    order = Order.objects.get(pk=order_id)
    return JsonResponse({"id": order.pk})


# ruleid: idor-missing-ownership-check-django
def order_detail_shortcut(request, order_id):
    order = get_object_or_404(Order, pk=order_id)
    return JsonResponse({"id": order.pk})


# ok: idor-missing-ownership-check-django
def order_detail_scoped(request, order_id):
    order = Order.objects.get(pk=order_id, user=request.user)
    return JsonResponse({"id": order.pk})


# The first parameter has to be the request, or any two-argument helper that
# queries by id would be a finding.
# ok: idor-missing-ownership-check-django
def fetch_order(session, order_id):
    return Order.objects.get(pk=order_id)


# --- route-without-auth-decorator-python ---------------------------------
#
# Mutating methods only, as in the Express rule: a GET with no authentication
# is very often public by design, and the endpoint layer settles that case by
# requesting the route without credentials.


# ruleid: route-without-auth-decorator-python
@router.post("/notes")
def create_note(body: NoteIn):
    NOTES.append({"text": body.text})
    return {"ok": True}


# ok: route-without-auth-decorator-python
@router.post("/notes-guarded")
def create_note_guarded(body: NoteIn, user=Depends(get_current_user)):
    NOTES.append({"text": body.text, "owner": user})
    return {"ok": True}


# Flask writes the method in the decorator's arguments rather than its name,
# which is why the rule constrains the list as a metavariable.
# ruleid: route-without-auth-decorator-python
@app.route("/flask/notes", methods=["POST"])
def flask_create_note():
    NOTES.append({"text": "fixture"})
    return jsonify({"ok": True})


# ok: route-without-auth-decorator-python
@app.route("/flask/notes-guarded", methods=["POST"])
@require_auth
def flask_create_note_guarded():
    NOTES.append({"text": "fixture"})
    return jsonify({"ok": True})


# ok: route-without-auth-decorator-python
@router.get("/notes")
def list_notes():
    return NOTES


# A route that is public by design is a decision, not an oversight.
# ok: route-without-auth-decorator-python
@app.route("/flask/login", methods=["POST"])
def flask_login():
    return jsonify({"ok": True})


# --- authorization-decided-client-side-python ----------------------------

def is_admin_from_body():
    # ruleid: authorization-decided-client-side-python
    if request.json["role"] == "admin":
        return True
    return False


def is_admin_from_form():
    # ruleid: authorization-decided-client-side-python
    if request.form.get("is_admin", False):
        return True
    return False


# The FastAPI shape, and the reason this rule is worth more than a regex: the
# body arrives as a typed parameter, so payload.role reads like attribute
# access on something trusted.
@router.post("/promote")
def promote(payload: PromoteIn, user=Depends(get_current_user)):
    # ruleid: authorization-decided-client-side-python
    if payload.role == "admin":
        return {"promoted": True}
    raise HTTPException(status_code=403, detail="forbidden")


def is_admin_from_session():
    # ok: authorization-decided-client-side-python
    if g.user["role"] == "admin":
        return True
    return False


# --- mass-assignment-request-body-python ---------------------------------

@app.route("/flask/orders-bulk", methods=["POST"])
@require_auth
def flask_create_order_bulk():
    payload = request.json or {}
    order = {"id": 1}
    # ruleid: mass-assignment-request-body-python
    order.update(payload)
    return jsonify(order)


@router.post("/orders-bulk")
def fastapi_create_order_bulk(payload: OrderIn, user=Depends(get_current_user)):
    order = {"id": 1}
    # ruleid: mass-assignment-request-body-python
    order.update(payload.model_dump())
    return order


@router.post("/orders-picked")
def fastapi_create_order_picked(payload: dict, user=Depends(get_current_user)):
    order = {"id": 1}
    # Naming the field is the fix, so the same sink is clean.
    # ok: mass-assignment-request-body-python
    order.update({"item": payload["item"]})
    return order


# --- a decorator is not a route ------------------------------------------
#
# See the note in injection.py: any imported decorator used to satisfy the
# route anchor these rules hang their FastAPI sources on.

@lru_cache(maxsize=8)
def cached_bulk_update(payload: OrderIn):
    order = {"id": 1}
    # ok: mass-assignment-request-body-python
    order.update(payload.model_dump())
    return order


@lru_cache(maxsize=8)
def cached_is_admin(payload: PromoteIn):
    # ok: authorization-decided-client-side-python
    if payload.role == "admin":
        return True
    return False
