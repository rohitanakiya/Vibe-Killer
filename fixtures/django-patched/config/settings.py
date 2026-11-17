"""Settings for the patched Django fixture.

NOT A REAL APPLICATION, but every weakness of its vulnerable twin is fixed
here, and the suite asserts that the rule pack is completely silent on it and
that nothing is confirmed against it.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# FIXED: the signing key comes from the environment, so the repository does not
# contain it and rotating it does not need a deploy of new code.
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]

# FIXED: the debugger is off and driven from the environment, so an error
# response carries no settings, no query contents and no traceback.
DEBUG = os.environ.get("DJANGO_DEBUG") == "1"

# FIXED: only the hostnames this instance serves, so a forged Host header
# cannot end up in an absolute URL the application builds.
ALLOWED_HOSTS = ["127.0.0.1", "localhost", "testserver"]

ROOT_URLCONF = "config.urls"

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "shop",
]

MIDDLEWARE = [
    "django.middleware.common.CommonMiddleware",
    # FIXED: an allowlisted origin only, and the response hardening headers
    # set once for every route.
    "shop.middleware.SecurityHeadersMiddleware",
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.environ.get("FIXTURE_DB", str(BASE_DIR / "fixture.sqlite3")),
    }
}

USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.AutoField"
