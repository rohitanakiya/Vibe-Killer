"""The django-vulnerable fixture's views with every weakness fixed.

NOT A REAL APPLICATION, but it is the half of the pair that matters most: the
suite asserts the rule pack is completely silent here and that no finding is
confirmed against it. A rule or a check that fires on both versions is not
detecting anything.

Each fix is the one a reviewer would make rather than the smallest edit that
quiets a rule.
"""

import json
import os
from pathlib import Path

from django.db import connection
from django.http import FileResponse, JsonResponse

from .auth import require_auth
from .models import Order, Profile

UPLOAD_ROOT = (Path(__file__).parent / "uploads").resolve()


def health(request):
    """Unauthenticated on purpose: the dynamic check script waits on it to know
    the application is serving."""
    return JsonResponse({"ok": True})


@require_auth
def whoami(request):
    return JsonResponse(request.vk_user)


# FIXED: the queryset is filtered by the caller as well as the id, so another
# user's order is simply not found rather than being returned. 404 rather than
# 403, so the response does not confirm that someone else's record exists.
@require_auth
def order_detail(request, order_id):
    order = Order.objects.filter(pk=order_id, user_id=request.vk_user["id"]).first()
    if order is None:
        return JsonResponse({"error": "not found"}, status=404)
    return JsonResponse(
        {"id": order.pk, "item": order.item, "user_id": order.user_id, "note": order.note}
    )


# FIXED: the record is assembled field by field, and the owner comes from the
# authenticated caller rather than from the body.
@require_auth
def create_order(request):
    payload = json.loads(request.body or b"{}")
    order = Order(
        user_id=request.vk_user["id"],
        item=str(payload.get("item", "unnamed")),
        total=0,
    )
    order.save()
    return JsonResponse({"id": order.pk}, status=201)


# FIXED: authentication is required, and a profile is only readable by its
# owner.
@require_auth
def profile_detail(request, profile_id):
    profile = Profile.objects.filter(pk=profile_id, user_id=request.vk_user["id"]).first()
    if profile is None:
        return JsonResponse({"error": "not found"}, status=404)
    return JsonResponse(
        {"id": profile.pk, "email": profile.email, "user_id": profile.user_id, "note": profile.note}
    )


# FIXED: the term is bound as a parameter, so it is data to the database rather
# than syntax, and the search is scoped to the caller's own orders.
@require_auth
def search(request):
    term = request.GET.get("q", "")
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT id, item FROM shop_order WHERE user_id = %s AND item LIKE %s",
            [request.vk_user["id"], f"%{term}%"],
        )
        rows = cursor.fetchall()
    return JsonResponse([{"id": r[0], "item": r[1]} for r in rows], safe=False)


# FIXED: the path is resolved and confirmed to be inside the intended root
# before anything is read, so ../ cannot escape it. FileResponse streams the
# file without the view ever opening a caller-influenced path itself.
#
# traversal.path-escape still reports this handler at `likely`, and that is
# the check being accurate rather than wrong. It compares a plain request for
# a missing file against the same name behind ../ segments; this handler
# answers both 404, so from outside there is nothing to tell "I resolved the
# path and rejected it" apart from "I looked and found nothing". The check
# says exactly that in its evidence and declines to call it confirmed.
#
# The 404 stays. Answering 400 for a rejected path would separate the two
# cases and silence the finding, but it would also tell a caller which paths
# resolve outside the root, and that is a worse handler. A fixture edited to
# quiet a check measures the edit.
@require_auth
def read_file(request, name):
    candidate = (UPLOAD_ROOT / name).resolve()
    if not candidate.is_relative_to(UPLOAD_ROOT) or not candidate.is_file():
        return JsonResponse({"error": "not found"}, status=404)
    return FileResponse(open(candidate, "rb"), content_type="application/octet-stream")
