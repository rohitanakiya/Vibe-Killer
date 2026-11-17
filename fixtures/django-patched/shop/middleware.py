"""Response middleware for the patched fixture."""

ALLOWED_ORIGINS = frozenset({"https://app.example.invalid"})


class SecurityHeadersMiddleware:
    """FIXED: credentials are allowed only for an allowlisted origin, never
    for whatever Origin arrived, and the hardening headers are set once for
    every route."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        origin = request.headers.get("Origin", "")
        if origin in ALLOWED_ORIGINS:
            response["Access-Control-Allow-Origin"] = origin
            response["Access-Control-Allow-Credentials"] = "true"

        response["X-Content-Type-Options"] = "nosniff"
        response["X-Frame-Options"] = "DENY"
        response["Content-Security-Policy"] = "default-src 'self'"
        response["Referrer-Policy"] = "no-referrer"
        return response
