"""re_path patterns, which are regexes rather than templates.

Normalizing one as though it were a path() template produces a path the server
does not serve, so the extractor strips the regex syntax first.
"""

from django.urls import re_path

from . import views

urlpatterns = [
    re_path(r"^profiles/(?P<profile_id>[0-9]+)/$", views.profile_detail),
    re_path(r"^reports/([0-9]{4})/$", views.report_by_year),
]
