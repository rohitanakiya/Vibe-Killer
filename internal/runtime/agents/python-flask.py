"""Vibe Killer runtime agent for Flask.

THIS IS YOUR CODE. Vibe Killer prints it; you add it, you read it, and you
delete it when you are finished. Nothing is injected into your process and
nothing is left behind, because the tool never put anything there.

What it does: for each request, it reports the route, the status, which
authorization decorators actually ran, and the shape of the database
statements that were issued.

What it deliberately does not do: send parameter values. Statements are
reported with their placeholders intact and only a count of bound parameters,
so none of your data reaches the scanner. The sink refuses an observation that
looks like it carries values.

Install:

    1. Save this file next to your app, as vibekiller_agent.py
    2. After creating your app:

           import vibekiller_agent
           vibekiller_agent.attach(app)

    3. Mark your auth decorators so the agent can see them fire. Inside the
       decorator, after the check passes:

           vibekiller_agent.note_auth("require_auth")

    4. To report queries, wrap your cursor or engine once:

           cursor = vibekiller_agent.observe_cursor(cursor)

       or, for SQLAlchemy, call attach_sqlalchemy(engine).

    5. Run the scan, then remove the two lines from step 2.

The sink URL comes from the VIBEKILLER_SINK environment variable, which the
scan prints. With it unset the agent does nothing at all, so leaving the code
in place on a machine that is not being scanned has no effect.
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.parse
import urllib.request
from typing import Any

SCHEMA_VERSION = "1.0"
CORRELATION_HEADER = "X-Vibekiller-Probe"

_SINK = os.environ.get("VIBEKILLER_SINK", "")

# Per-request state. Flask's own `g` would work for the request itself, but a
# query issued from a background thread during the request would not find it,
# so the agent keeps its own thread-local.
_local = threading.local()


def _state() -> dict[str, Any] | None:
    return getattr(_local, "vk", None)


def note_auth(name: str) -> None:
    """Record that a named authorization check ran for this request."""
    state = _state()
    if state is not None and name:
        state["auth_checks"].append(name)


def note_query(sql: str, param_count: int = 0, duration_ms: int = 0) -> None:
    """Record a statement.

    `sql` must keep its placeholders: never pass a string with values already
    substituted into it.
    """
    state = _state()
    if state is None or not sql:
        return
    state["queries"].append(
        {"sql": str(sql), "param_count": int(param_count or 0), "duration_ms": int(duration_ms or 0)}
    )


def observe_cursor(cursor: Any) -> Any:
    """Wrap a DB-API cursor so its execute methods report statement shapes."""

    class _ObservingCursor:
        def __init__(self, inner: Any) -> None:
            self._inner = inner

        def execute(self, sql: str, params: Any = None, *args: Any, **kwargs: Any) -> Any:
            started = time.monotonic()
            try:
                if params is None:
                    return self._inner.execute(sql, *args, **kwargs)
                return self._inner.execute(sql, params, *args, **kwargs)
            finally:
                count = len(params) if hasattr(params, "__len__") else (0 if params is None else 1)
                note_query(sql, count, int((time.monotonic() - started) * 1000))

        def executemany(self, sql: str, seq: Any, *args: Any, **kwargs: Any) -> Any:
            started = time.monotonic()
            try:
                return self._inner.executemany(sql, seq, *args, **kwargs)
            finally:
                note_query(sql, 0, int((time.monotonic() - started) * 1000))

        def __getattr__(self, name: str) -> Any:
            return getattr(self._inner, name)

        def __iter__(self):
            return iter(self._inner)

    return _ObservingCursor(cursor)


def attach_sqlalchemy(engine: Any) -> None:
    """Report statement shapes from a SQLAlchemy engine."""
    try:
        from sqlalchemy import event
    except ImportError:
        return

    @event.listens_for(engine, "before_cursor_execute")
    def _before(conn, cursor, statement, parameters, context, executemany):  # noqa: ANN001
        count = len(parameters) if hasattr(parameters, "__len__") else 0
        note_query(statement, count, 0)


def _post(observation: dict[str, Any]) -> None:
    if not _SINK:
        return

    parsed = urllib.parse.urlparse(_SINK)
    # Loopback only. The sink is always local, and refusing anything else means
    # a stray environment variable cannot turn this into an exfiltration path.
    if parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
        return

    body = json.dumps(observation).encode("utf-8")
    request = urllib.request.Request(
        _SINK, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        # Reporting is best effort: it must never affect the application.
        with urllib.request.urlopen(request, timeout=2):
            pass
    except Exception:
        pass


def attach(app: Any) -> None:
    """Attach the agent to a Flask app."""
    if not _SINK:
        return

    from flask import g, request

    @app.before_request
    def _vk_before() -> None:  # noqa: ANN202
        _local.vk = {"auth_checks": [], "queries": [], "started": time.monotonic()}
        g._vk_correlation = request.headers.get(CORRELATION_HEADER, "")

    @app.after_request
    def _vk_after(response: Any) -> Any:
        state = _state()
        if state is None:
            return response

        rule = request.url_rule
        _post(
            {
                "schema_version": SCHEMA_VERSION,
                "correlation_id": getattr(g, "_vk_correlation", ""),
                "method": request.method,
                "path": request.path,
                "route": str(rule.rule) if rule is not None else "",
                "status": response.status_code,
                "handler": (rule.endpoint if rule is not None else ""),
                "auth_checks": state["auth_checks"],
                "principal": str(getattr(getattr(g, "user", None), "get", lambda _k, _d=None: "")("id", "") or ""),
                "queries": state["queries"],
                "duration_ms": int((time.monotonic() - state["started"]) * 1000),
            }
        )
        _local.vk = None
        return response

    @app.teardown_request
    def _vk_teardown(_exc: Any) -> None:  # noqa: ANN202
        _local.vk = None
