"""Behaviour fixture for the Python rules in misconfiguration.yaml.

NOT AN APPLICATION. Every line here exists to pin one rule to one verdict,
and `semgrep --test` enforces both halves: a `ruleid:` line must match and an
`ok:` line must not. The `ok:` lines are the point. A rule that matches
nothing and a rule that matches everything both look fine in a scan of
vulnerable code; only a negative case tells them apart.

Each rule in the pack is required to appear here by
TestEveryRuleHasABehaviourFixture, so a new rule cannot ship unexercised.
"""

from functools import lru_cache
import os
import secrets
import ssl
import traceback
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse

import httpx
import requests
import uvicorn
from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

app = Flask(__name__)
router = APIRouter()

ALLOWED_FEED_HOSTS = frozenset({"feeds.example.invalid"})
UPLOAD_ROOT = os.path.join(os.path.dirname(__file__), "uploads")


class ApplicationRequestHandler:
    pass


# --- cors-origin-reflected-python -----------------------------------------

def cors_credentialed_wildcard(flask_app):
    # ruleid: cors-origin-reflected-python
    CORS(flask_app, origins="*", supports_credentials=True)


def cors_scoped(flask_app):
    # ok: cors-origin-reflected-python
    CORS(flask_app, origins=["https://app.example.invalid"])


@app.after_request
def reflect_origin(response):
    # ruleid: cors-origin-reflected-python
    response.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "")
    return response


@app.after_request
def fixed_origin(response):
    # ok: cors-origin-reflected-python
    response.headers["Access-Control-Allow-Origin"] = "https://app.example.invalid"
    return response


# FastAPI has no CORS() helper; the same policy is middleware, and the rule
# used to say nothing about an application configured exactly this wrongly.
def cors_middleware_wildcard(fastapi_app):
    # ruleid: cors-origin-reflected-python
    fastapi_app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)


def cors_middleware_scoped(fastapi_app):
    # ok: cors-origin-reflected-python
    fastapi_app.add_middleware(
        CORSMiddleware,
        allow_origins=["https://app.example.invalid"],
        allow_credentials=True,
    )


# --- debug-mode-enabled ---------------------------------------------------

# ruleid: debug-mode-enabled
DEBUG = True


def serve_with_debugger(flask_app):
    # ruleid: debug-mode-enabled
    flask_app.run(debug=True)


def enable_debug_attribute(flask_app):
    # ruleid: debug-mode-enabled
    flask_app.debug = True


def serve_without_debugger(flask_app):
    # ok: debug-mode-enabled
    flask_app.run(debug=False)


def build_app_in_debug():
    # ruleid: debug-mode-enabled
    return FastAPI(debug=True)


def serve_with_the_reloader(fastapi_app):
    # ruleid: debug-mode-enabled
    uvicorn.run(fastapi_app, host="127.0.0.1", port=5001, reload=True)


def serve_without_the_reloader(fastapi_app):
    # ok: debug-mode-enabled
    uvicorn.run(fastapi_app, host="127.0.0.1", port=5001, reload=False)


# --- wildcard-allowed-hosts -----------------------------------------------

# A wildcard on its own, which is the shape the rule used to require.
# ruleid: wildcard-allowed-hosts
ALLOWED_HOSTS = ["*"]

# The shape it actually takes in practice: the wildcard added beside the real
# hostnames, so an exact match on the single-element list never sees it.
# ruleid: wildcard-allowed-hosts
ALLOWED_HOSTS = ["app.example.invalid", "*"]

# ok: wildcard-allowed-hosts
ALLOWED_HOSTS = ["app.example.invalid", ".internal.example.invalid"]


def trust_any_host(fastapi_app):
    # ruleid: wildcard-allowed-hosts
    fastapi_app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])


def trust_named_hosts(fastapi_app):
    # ok: wildcard-allowed-hosts
    fastapi_app.add_middleware(TrustedHostMiddleware, allowed_hosts=["app.example.invalid"])


# --- unsafe-fetch-of-user-supplied-url-python -----------------------------

@app.route("/flask/import", methods=["POST"])
def flask_import():
    url = request.args.get("url", "")
    # ruleid: unsafe-fetch-of-user-supplied-url-python
    return requests.get(url, timeout=10).text


@router.post("/fastapi/import")
def fastapi_import(url: str):
    # FastAPI hands the query value in as a parameter, so there is no request
    # object for the taint to start from. This is the case the rule was blind
    # to while claiming to cover Python.
    # ruleid: unsafe-fetch-of-user-supplied-url-python
    return requests.get(url, timeout=10).text


@router.post("/fastapi/import-checked")
def fastapi_import_checked(url: str):
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_FEED_HOSTS:
        raise HTTPException(status_code=400, detail="that host is not allowed")
    # ok: unsafe-fetch-of-user-supplied-url-python
    return requests.get(url, timeout=10).text


@router.get("/fastapi/feed")
def fastapi_fixed_feed(name: str):
    # ok: unsafe-fetch-of-user-supplied-url-python
    return requests.get("https://feeds.example.invalid/latest", timeout=10).text


# --- tls-verification-disabled-python -------------------------------------
#
# None of these are route handlers, so no parameter is tainted and the fetch
# rules stay out of it. What is under test here is only the TLS switch.

def requests_unverified(feed_url):
    # ruleid: tls-verification-disabled-python
    return requests.get(feed_url, timeout=10, verify=False)


def httpx_unverified(feed_url):
    # ruleid: tls-verification-disabled-python
    return httpx.get(feed_url, timeout=10, verify=False)


def legacy_unverified_context():
    # ruleid: tls-verification-disabled-python
    return ssl._create_unverified_context()


def weaken_context(ctx):
    # The receiver is a local, which is the only way this is ever written.
    # ruleid: tls-verification-disabled-python
    ctx.verify_mode = ssl.CERT_NONE


def requests_verified(feed_url):
    # ok: tls-verification-disabled-python
    return requests.get(feed_url, timeout=10)


def context_left_alone():
    # ok: tls-verification-disabled-python
    return ssl.create_default_context()


# --- error-detail-returned-to-caller-python ------------------------------
#
# The exception text only counts when it is tied to the exception the handler
# caught. str(anything) is far too common to match on its own, and a rule that
# did would fire on every stringified value in a response.

def read_order(order_id):
    try:
        return {"id": int(order_id)}
    except ValueError as exc:
        # ruleid: error-detail-returned-to-caller-python
        return jsonify({"error": str(exc)}), 400


def read_order_generically(order_id):
    try:
        return {"id": int(order_id)}
    except ValueError:
        # ok: error-detail-returned-to-caller-python
        return jsonify({"error": "that id is not a number"}), 400


def count_items(items):
    # Not an exception, and the rule has to stay off it.
    # ok: error-detail-returned-to-caller-python
    return jsonify({"error": str(len(items))})


@app.errorhandler(Exception)
def handle_error_verbosely(err):
    # ruleid: error-detail-returned-to-caller-python
    return jsonify({"error": str(err)}), 500


@app.errorhandler(ValueError)
def handle_error_quietly(err):
    correlation_id = secrets.token_hex(8)
    app.logger.exception("[%s] unhandled error", correlation_id)
    # ok: error-detail-returned-to-caller-python
    return jsonify({"error": "internal error", "correlation_id": correlation_id}), 500


def read_order_with_traceback(order_id):
    try:
        return {"id": int(order_id)}
    except ValueError:
        # A traceback in a response has no innocent reading, so this needs no
        # tie to the caught exception.
        # ruleid: error-detail-returned-to-caller-python
        return jsonify({"error": traceback.format_exc()}), 500


def read_order_logging_the_traceback(order_id):
    try:
        return {"id": int(order_id)}
    except ValueError:
        # Logging it server-side is the correct thing to do.
        # ok: error-detail-returned-to-caller-python
        app.logger.error("%s", traceback.format_exc())
        return jsonify({"error": "internal error"}), 500


# --- directory-listing-or-whole-tree-served-python -----------------------

def mount_static_at_the_project_root(fastapi_app):
    # ruleid: directory-listing-or-whole-tree-served-python
    fastapi_app.mount("/files", StaticFiles(directory="."), name="files")


def mount_static_at_a_public_directory(fastapi_app):
    # ok: directory-listing-or-whole-tree-served-python
    fastapi_app.mount("/assets", StaticFiles(directory="static"), name="assets")


def serve_the_source_tree():
    # ruleid: directory-listing-or-whole-tree-served-python
    return send_from_directory(os.path.dirname(__file__), "app.py")


def serve_an_upload():
    # ok: directory-listing-or-whole-tree-served-python
    return send_from_directory(UPLOAD_ROOT, "banner.png")


def serve_a_listing():
    # The stdlib handler lists whatever directory it is rooted at.
    # ruleid: directory-listing-or-whole-tree-served-python
    return HTTPServer(("127.0.0.1", 8000), SimpleHTTPRequestHandler)


def serve_an_application():
    # ok: directory-listing-or-whole-tree-served-python
    return HTTPServer(("127.0.0.1", 8000), ApplicationRequestHandler)


# --- a decorator is not a route ------------------------------------------
#
# See the note in injection.py. This rule's FastAPI sources hung off the same
# anchor, so a cached helper's argument was a taint source.

@lru_cache(maxsize=8)
def cached_fetch(url):
    # ok: unsafe-fetch-of-user-supplied-url-python
    return requests.get(url, timeout=10).text
