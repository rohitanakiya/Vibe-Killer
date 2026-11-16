"""Settings for the URLconf fixture. ROOT_URLCONF is what the extractor reads."""

SECRET_KEY = "fixture-only-not-a-secret"
ALLOWED_HOSTS = ["testserver"]
ROOT_URLCONF = "config.urls"

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "rest_framework",
    "orders",
    "legacy",
]
