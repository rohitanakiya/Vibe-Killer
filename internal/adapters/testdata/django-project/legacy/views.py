"""Views for the legacy app."""

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse


@login_required
def profile_detail(request, profile_id):
    return JsonResponse({"id": profile_id})


def report_by_year(request, year):
    return JsonResponse({"year": year})
