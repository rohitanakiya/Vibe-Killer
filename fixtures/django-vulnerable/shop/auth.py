"""The fixture's seeded users and its authorization decorator.

Bearer tokens over a dict rather than django.contrib.auth, because what is
under test is the scanner and not Django's login flow. The tokens are the ones
the other fixtures hand out, so one config declares the seeded users for all
of them.
"""

from functools import wraps

from django.http import JsonResponse

USERS = {
    "userA-token": {"id": "userA", "name": "Ada Example", "role": "member"},
    "userB-token": {"id": "userB", "name": "Grace Example", "role": "member"},
    "admin-token": {"id": "admin", "name": "Root Example", "role": "admin"},
}


def current_user(request):
    header = request.headers.get("Authorization", "")
    token = header[7:] if header.lower().startswith("bearer ") else ""
    return USERS.get(token)


def require_auth(view):
    """Authentication, which this fixture does enforce. The weaknesses here
    are all about what happens *after* the caller is identified."""

    @wraps(view)
    def wrapper(request, *args, **kwargs):
        user = current_user(request)
        if user is None:
            return JsonResponse({"error": "authentication required"}, status=401)
        request.vk_user = user
        return view(request, *args, **kwargs)

    return wrapper
