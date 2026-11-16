"""The root URLconf. Every route below reaches its real path through here."""

from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", include("orders.urls")),
    # The namespacing form of include, which is a different shape to parse.
    path("legacy/", include(("legacy.urls", "legacy"), namespace="legacy")),
]
