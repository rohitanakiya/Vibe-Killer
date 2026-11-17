"""Deliberately vulnerable views. NOT A REAL APPLICATION. DO NOT DEPLOY.

Each weakness is paired with a rule or a check, and ../django-patched is the
same application with every one of them fixed.

This fixture exists because the dynamic layer had never run against Django.
It does now: ten findings are reproduced against a live server here,
including the access-control proof that reads userB's canary order as userA.

Writing it also measured how much of the *static* pack reaches Django, and
the answer is four rules -- cors-origin-reflected, debug-mode-enabled,
sql-built-by-string-formatting and wildcard-allowed-hosts. Three weaknesses
below are reported by nothing static, for reasons that are about the rules
rather than about this file:

  traversal.path-built-from-input and authz.mass-assignment are both anchored
  on a route decorator, `@$APP.$ROUTE(...)`. A Django view carries no route
  decorator at all -- the URL is bound in urls.py -- so neither rule can
  match one. Both weaknesses are real here, and the endpoint layer proves the
  traversal.

  idor.missing-ownership-check has a Django variant, and it is excluded by
  its own ownership-column filter: order_detail returns "user_id" in its
  response, and the filter looks for that column name anywhere in the
  handler rather than in the query. Serialising a record's owner id is
  entirely ordinary, so the filter is defeated by correct code next to the
  bug. The weakness is proven dynamically instead.

Nothing here is written to make a rule fire or stay quiet. A fixture tuned
to the rules measures the tuning.
"""

import json
import os

from django.db import connection
from django.http import HttpResponse, JsonResponse

from .auth import require_auth
from .models import Order, Profile

UPLOAD_ROOT = os.path.join(os.path.dirname(__file__), "uploads")


def health(request):
    """Unauthenticated on purpose: the dynamic check script waits on it to know
    the application is serving."""
    return JsonResponse({"ok": True})


@require_auth
def whoami(request):
    """An ordinary "who am I" endpoint, which carries no weakness: it requires
    authentication and returns the caller's own record. It is here because
    exposure.shared-trust-domain needs an endpoint on a component that refuses
    an anonymous request before it can ask whether another component's token is
    accepted."""
    return JsonResponse(request.vk_user)


# VULN (idor.sequential-id-access): authenticated, then looks the order up by
# the id in the URL with no ownership check. Any authenticated caller can read
# another user's order by changing the number.
#
# VULN (runtime.query-missing-owner-filter): the ORM issues a statement keyed
# on the primary key and nothing else, which is the same weakness seen from
# the inside -- though no Django agent ships yet, so nothing observes it here.
@require_auth
def order_detail(request, order_id):
    order = Order.objects.get(pk=order_id)
    return JsonResponse(
        {"id": order.pk, "item": order.item, "user_id": order.user_id, "note": order.note}
    )


# VULN (authz.mass-assignment): the whole JSON body becomes the record, so a
# caller can set user_id and own someone else's order.
@require_auth
def create_order(request):
    payload = json.loads(request.body or b"{}")
    order = Order(**payload)
    order.save()
    return JsonResponse({"id": order.pk}, status=201)


# VULN (authz.unprotected-endpoint): no authentication at all, and it returns
# another user's profile.
def profile_detail(request, profile_id):
    profile = Profile.objects.get(pk=profile_id)
    return JsonResponse(
        {"id": profile.pk, "email": profile.email, "user_id": profile.user_id, "note": profile.note}
    )


# VULN (injection.sql-string-built-from-input): the search term is formatted
# into the statement, so it becomes part of the query's syntax.
@require_auth
def search(request):
    term = request.GET.get("q", "")
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT id, item FROM shop_order WHERE item LIKE '%{term}%'")
        rows = cursor.fetchall()
    return JsonResponse([{"id": r[0], "item": r[1]} for r in rows], safe=False)


# VULN (traversal.path-built-from-input): the name is joined without being
# resolved and checked, so ../ escapes the directory.
@require_auth
def read_file(request, name):
    with open(os.path.join(UPLOAD_ROOT, name), "rb") as fh:
        return HttpResponse(fh.read(), content_type="application/octet-stream")
