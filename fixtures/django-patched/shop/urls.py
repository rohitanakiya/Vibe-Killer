"""The app URLconf, mounted at /api/ by the root one.

Nothing here states that prefix, which is the point: a reader of this file
alone would report every route one segment short.
"""

from django.urls import path

from . import views

urlpatterns = [
    path("me", views.whoami, name="whoami"),
    path("orders/<int:order_id>", views.order_detail, name="order-detail"),
    path("orders", views.create_order, name="order-create"),
    path("profiles/<int:profile_id>", views.profile_detail, name="profile-detail"),
    path("search", views.search, name="search"),
    path("files/<path:name>", views.read_file, name="read-file"),
]
