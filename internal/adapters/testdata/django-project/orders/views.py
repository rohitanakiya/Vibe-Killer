"""Views for the URLconf fixture.

The method a view accepts is declared here, not in the URLconf, which is why
the extractor has to read this file to describe the routes correctly.
"""

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views import View
from django.views.decorators.http import require_POST, require_http_methods
from rest_framework import viewsets

ORDERS = [{"id": 1, "item": "Decoy order"}]


def order_list(request):
    """No decorator, so Django dispatches every method to it. The extractor
    records GET alone rather than inventing the rest."""
    return JsonResponse({"orders": ORDERS})


@login_required
def order_detail(request, order_id):
    for order in ORDERS:
        if order["id"] == order_id:
            return JsonResponse(order)
    return JsonResponse({"error": "not found"}, status=404)


@require_POST
def create_order(request):
    ORDERS.append({"id": len(ORDERS) + 1, "item": "created"})
    return JsonResponse({"ok": True}, status=201)


@require_http_methods(["GET", "DELETE"])
def purge_orders(request):
    """Declared but never routed. It must not appear in the surface: a route
    that no URLconf reaches is not an endpoint."""
    ORDERS.clear()
    return JsonResponse({"ok": True})


class BoardList(View):
    """A class-based view states its methods by defining them."""

    def get(self, request):
        return JsonResponse({"boards": []})

    def post(self, request):
        return JsonResponse({"ok": True}, status=201)


class TicketViewSet(viewsets.ModelViewSet):
    """ModelViewSet promises all six actions, so the router generates all six
    routes from it."""

    queryset = None
    serializer_class = None


class ReportViewSet(viewsets.ReadOnlyModelViewSet):
    """Read-only, so the router generates the two read routes and no more.
    Getting this wrong in the other direction would have the endpoint checks
    send a DELETE to something that does not accept one."""

    queryset = None
    serializer_class = None
