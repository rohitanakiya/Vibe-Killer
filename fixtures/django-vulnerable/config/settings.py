"""Settings for the deliberately vulnerable Django fixture.

NOT A REAL APPLICATION. DO NOT DEPLOY.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# VULN: the signing secret is in the source, so anyone with the repository can
# mint a session cookie.
SECRET_KEY = "django-insecure-fixture-secret-do-not-use"

# VULN (misconfig.debug-mode-enabled): the debugger returns settings, query
# contents and a full traceback in error responses.
DEBUG = True

# VULN (misconfig.wildcard-allowed-hosts): every Host header is accepted, so
# an attacker's domain ends up in any absolute URL this application builds.
ALLOWED_HOSTS = ["*"]

ROOT_URLCONF = "config.urls"

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "shop",
]

MIDDLEWARE = [
    "django.middleware.common.CommonMiddleware",
    # VULN (misconfig.cors-credentialed-wildcard): the origin is reflected and
    # credentials are allowed, so any site a logged-in user visits can call
    # this API as them. No security headers are set either.
    "shop.middleware.ReflectOriginMiddleware",
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.environ.get("FIXTURE_DB", str(BASE_DIR / "fixture.sqlite3")),
    }
}

USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.AutoField"
