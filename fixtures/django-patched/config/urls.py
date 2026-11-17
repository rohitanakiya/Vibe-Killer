"""The root URLconf.

Every route below reaches its real path through here, which is the thing a
line-by-line reader of shop/urls.py cannot know.
"""

from django.urls import include, path

from shop import views

urlpatterns = [
    path("health", views.health, name="health"),
    path("api/", include("shop.urls")),
]
