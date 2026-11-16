"""An app URLconf, mounted at /api/ by the root one.

Nothing here states its own prefix, which is the point: the extractor has to
walk down from the root to know that "orders/" is served at "/api/orders".
"""

from django.urls import include, path
from rest_framework.routers import DefaultRouter

from . import views
from .views import BoardList

router = DefaultRouter()
router.register("tickets", views.TicketViewSet)
router.register("reports", views.ReportViewSet, basename="report")

urlpatterns = [
    path("orders/", views.order_list, name="order-list"),
    path("orders/<int:order_id>/", views.order_detail, name="order-detail"),
    path("orders/create/", views.create_order, name="order-create"),
    path("boards/", BoardList.as_view(), name="board-list"),
    path("", include(router.urls)),
]
