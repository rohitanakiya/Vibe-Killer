"""Response middleware for the vulnerable fixture."""


class ReflectOriginMiddleware:
    """VULN: reflects whatever Origin arrives and allows credentials with it,
    and sets none of the response hardening headers."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response["Access-Control-Allow-Origin"] = request.headers.get("Origin", "*")
        response["Access-Control-Allow-Credentials"] = "true"
        return response
