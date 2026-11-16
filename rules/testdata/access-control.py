"""Behaviour fixture for the Python rules in access-control.yaml.

NOT AN APPLICATION. See the header of misconfiguration.py.

The match range for these rules is the whole handler, deliberately: the
ownership exclusions are evaluated against the range, so narrowing it would
switch them off silently. That is why each annotation sits above the decorator
or the `def` rather than above the lookup.
"""

from fastapi import APIRouter, Header, HTTPException
from flask import Flask, jsonify

app = Flask(__name__)
router = APIRouter(prefix="/api")

ORDERS = [{"id": 1, "user_id": "userA", "item": "Decoy order"}]


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
