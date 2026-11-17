"""Deliberately vulnerable views. NOT A REAL APPLICATION. DO NOT DEPLOY.

Each weakness is paired with a rule or a check, and ../django-patched is the
same application with every one of them fixed.

This fixture exists because the dynamic layer had never run against Django.
It does now: ten findings are reproduced against a live server here,
including the access-control proof that reads userB's canary order as userA.

It earned its keep twice, though, and the second time was the surprise.
Running it also measured the *static* pack against Django, and the first
answer was four rules out of the seven that fire today. The three it was
missing were missing because of defects in the rules -- each one invisible
until a fixture asked, because a silent rule and a satisfied rule produce
exactly the same output:

  idor.missing-ownership-check, the rule this project leads with, suppressed
  itself whenever a handler serialised the record's owner into its response.
  order_detail below returns "user_id", the exclusion looked for that name
  anywhere in the view rather than in the query, and the flagship
  access-control finding went quiet. One line of entirely ordinary correct
  code, next to the bug, hid the bug -- and the more completely a handler
  serialises its record, the likelier it was hidden. The defect was in all
  three language variants, not just Django's.

  authz.mass-assignment had every part of this flow except where it starts.
  request.data is Django REST Framework; create_order below reads
  request.body, which was not in the source list, so the taint never began
  and a sink the rule already had was never reached.

  traversal.path-built-from-input was anchored on a route decorator. A Django
  view carries none -- urls.py binds the URL, sometimes several include()
  levels away -- so the rule could not match a Django handler at all.

All three are fixed, each pinned in rules/testdata/ with the Django shape
beside the Flask and FastAPI ones, and all three weaknesses below are now
reported statically as well as dynamically.

Nothing here is written to make a rule fire or stay quiet. A fixture tuned
to the rules measures the tuning -- which is the whole reason these three
were findable.
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
