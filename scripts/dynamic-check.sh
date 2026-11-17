#!/usr/bin/env bash
#
# Run Vibe Killer's dynamic layer against a fixture that is actually running.
#
# Everything else in this repository tests the endpoint checks against
# httptest handlers written in Go -- closures that answer the way a vulnerable
# app is expected to answer. That proves the check's logic against our own idea
# of the application, and nothing more. It is the same gap the Django extractor
# had: the code looked right, the tests agreed with it, and nothing had asked a
# real server.
#
# So this boots the fixture, points a real scan at it with --target, and
# asserts on what came back:
#
#   vulnerable   the endpoint checks reproduce the findings listed for that
#                stack, every reproduction carries its steps, and the
#                access-control proof names the seeded canary it read
#   patched      nothing is confirmed at all
#
# Confirmed is the assertion that matters on both sides. The README reserves
# `confidence: confirmed` for a finding that was re-run against the instance,
# so zero confirmed findings on corrected code is the claim worth pinning --
# while still allowing an honest heuristic finding at `likely`, which the
# patched fixtures do produce for endpoints that really are anonymous.
#
# Running all three stacks rather than one is not repetition. The endpoint
# checks are stack-agnostic by design: they probe HTTP. What differs per stack
# is the adapter that hands them the routes, so this is the only thing that
# tests Express's and FastAPI's route extraction against a server rather than
# against a parser.
#
# Usage:  scripts/dynamic-check.sh <flask|express|fastapi> <vulnerable|patched>
#
# Needs: go, curl, and python3 or node depending on the stack. Writes to a
# temporary directory and removes it, and stops the fixture on any exit path.

set -euo pipefail

STACK="${1:-}"
MODE="${2:-}"

case "$STACK" in
flask | express | fastapi | django) ;;
*)
    echo "usage: $0 <flask|express|fastapi|django> <vulnerable|patched|runtime|exposure>" >&2
    exit 2
    ;;
esac
case "$MODE" in
vulnerable | patched) ;;
runtime)
    # The runtime mode scans the vulnerable fixture with an agent attached.
    # Only Flask has one wired up: internal/runtime/agents ships agents for
    # Flask and Express, and the Flask fixture is where the call sites are.
    if [ "$STACK" != "flask" ]; then
        echo "runtime mode is only wired up for flask" >&2
        exit 2
    fi
    ;;
exposure)
    # Two components, which is what the exposure layer needs and what no
    # earlier run gave it: in every scan so far it probed a declared
    # neighbour with nothing listening, timed out, and reported nothing.
    if [ "$STACK" != "flask" ]; then
        echo "exposure mode is only wired up for flask" >&2
        exit 2
    fi
    ;;
*)
    echo "usage: $0 <flask|express|fastapi> <vulnerable|patched|runtime>" >&2
    exit 2
    ;;
esac

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# runtime scans the vulnerable fixture; the mode names what is being proven,
# not a separate application.
FIXTURE_MODE="$MODE"
case "$MODE" in
runtime | exposure) FIXTURE_MODE="vulnerable" ;;
esac
FIXTURE="fixtures/$STACK-$FIXTURE_MODE"
if [ ! -d "$FIXTURE" ]; then
    echo "no such fixture: $FIXTURE" >&2
    exit 2
fi

# One port for every stack, and it has to be one the committed config declares
# under authorized_targets -- that list is what the scope guard enforces, and a
# port outside it is refused rather than scanned. 3000 and 5000 are both
# declared; the fixtures' own defaults differ, so the port is passed in.
PORT="${PORT:-5000}"
TARGET="http://127.0.0.1:$PORT"

# The sink port the agent posts to. It has to match runtime.proxy_port in the
# config, because the agent is started before the scan and so before the sink
# exists -- the operator's app is told where to post, then the scan binds it.
SINK_PORT="${SINK_PORT:-18080}"

WORK="$(mktemp -d)"
APP_PID=""
NEIGHBOUR_PID=""

# Where the application is served from, and what the scan is pointed at. Both
# are the fixture itself except in runtime mode, which works on a copy: the
# agent is a file the operator adds beside their app and deletes afterwards, so
# it has no business being committed to a fixture, and attachRuntime writes it
# into whatever directory it is scanning.
APP_DIR="$FIXTURE"
SCAN_REPO="$FIXTURE"

cleanup() {
    for pid in "$APP_PID" "$NEIGHBOUR_PID"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    rm -rf "$WORK"
}
trap cleanup EXIT

# Secrets for the patched fixtures, which read their signing keys from the
# environment rather than carrying one in the source -- that being the fix
# their vulnerable twins are missing. Each stack names them differently, so all
# of them are set.
if [ "$MODE" = "runtime" ]; then
    APP_DIR="$WORK/app"
    SCAN_REPO="$WORK/app"
    cp -r "$FIXTURE" "$APP_DIR"
    rm -rf "$APP_DIR/__pycache__"

    # The agent as shipped, not a copy kept in the fixture: if the two could
    # drift, this would be testing the copy.
    cp internal/runtime/agents/python-flask.py "$APP_DIR/vibekiller_agent.py"

    # With this unset the agent does nothing at all, which is how the fixture
    # stays an ordinary application the rest of the time.
    export VIBEKILLER_SINK="http://127.0.0.1:$SINK_PORT/observe"
    echo "==> runtime mode: agent installed, sink at $VIBEKILLER_SINK"
fi

export JWT_SIGNING_KEY="dynamic-check-only-not-a-secret"
export FIXTURE_JWT_SECRET="dynamic-check-only-not-a-secret"
export ADMIN_API_KEY="dynamic-check-only-not-a-secret"
export PORT

# --- install and start ------------------------------------------------------

# make_python_venv creates a virtualenv for $APP_DIR and installs its pinned
# requirements, leaving the interpreter path in PY.
make_python_venv() {

    # PYTHON overrides the interpreter, and the vulnerable Flask fixture is why
    # it exists. Its pins are deliberately old so the dependency check finds
    # advisories for them, and Werkzeug 2.0.1 calls ast.Str, which Python
    # removed after 3.12 -- so that fixture cannot be served by an arbitrary
    # interpreter. CI pins 3.12 for this job; locally, pass
    # PYTHON=/path/to/python3.12.
    bootstrap="${PYTHON:-python3}"
    BOOTSTRAP_PY_USED="$bootstrap"

    echo "==> creating a virtualenv for $FIXTURE ($("$bootstrap" --version 2>&1))"

    # A venv per fixture rather than one shared one: flask-vulnerable pins
    # Flask 2.0.1 and flask-patched pins 3.1.0, and installing both into one
    # environment would mean testing neither.
    "$bootstrap" -m venv "$WORK/venv"
    py="$WORK/venv/bin/python"
    [ -x "$py" ] || py="$WORK/venv/Scripts/python.exe"

    "$py" -m pip install --quiet --disable-pip-version-check --upgrade pip
    "$py" -m pip install --quiet --disable-pip-version-check -r "$APP_DIR/requirements.txt"
    PY="$py"
}

# start_python_fixture serves the app with a python expression.
start_python_fixture() {
    local entry="$1"
    make_python_venv

    echo "==> starting $APP_DIR on $TARGET"
    (
        cd "$APP_DIR"
        exec "$PY" -c "$entry"
    ) >"$WORK/app.log" 2>&1 &
    APP_PID=$!
}

case "$STACK" in
flask)
    # debug follows each fixture's own configuration rather than being forced.
    # misconfig.verbose-error reproduces by asking for a stack trace, so
    # running the vulnerable app with the debugger off would quietly disarm a
    # check under test -- and the patched fixture's fix *is* that the debugger
    # is off.
    if [ "$FIXTURE_MODE" = "vulnerable" ]; then FLASK_DEBUG_FLAG="True"; else FLASK_DEBUG_FLAG="False"; fi
    # use_reloader=False in both cases. The reloader forks, and a fixture that
    # outlives the script is a port left bound for whatever runs next.
    start_python_fixture "from app import app; app.run(host='127.0.0.1', port=$PORT, debug=$FLASK_DEBUG_FLAG, use_reloader=False)"
    ;;
fastapi)
    start_python_fixture "import uvicorn; from main import app; uvicorn.run(app, host='127.0.0.1', port=$PORT, log_level='warning')"
    ;;
django)
    # Django needs its schema before it can serve anything, and the canary
    # records the access-control checks read have to be in it. A management
    # command seeds them rather than a fixture file, which is how a Django
    # project would do it, and --run-syncdb creates the tables for an app with
    # no migrations directory.
    make_python_venv

    export DJANGO_SECRET_KEY="dynamic-check-only-not-a-secret"
    export FIXTURE_DB="$WORK/fixture.sqlite3"

    echo "==> migrating and seeding $APP_DIR"
    (cd "$APP_DIR" && "$PY" manage.py migrate --run-syncdb --no-input >"$WORK/migrate.log" 2>&1) || {
        echo "migrate failed:" >&2
        tail -20 "$WORK/migrate.log" >&2
        exit 1
    }
    (cd "$APP_DIR" && "$PY" manage.py seed_fixtures >>"$WORK/migrate.log" 2>&1) || {
        echo "seeding failed:" >&2
        tail -20 "$WORK/migrate.log" >&2
        exit 1
    }
    tail -1 "$WORK/migrate.log"

    # --noreload because the autoreloader forks, and a fixture that outlives
    # the script is a port left bound for whatever runs next.
    echo "==> starting $APP_DIR on $TARGET"
    (
        cd "$APP_DIR"
        exec "$PY" manage.py runserver "127.0.0.1:$PORT" --noreload
    ) >"$WORK/app.log" 2>&1 &
    APP_PID=$!
    ;;
express)
    echo "==> installing $APP_DIR (node $(node --version))"
    # npm ci, which needs a committed lockfile and both express fixtures now
    # have one. That matters beyond reproducible installs: osv-scanner reads
    # the lockfile and cannot read a package.json, so the fixture without one
    # contributed nothing at all to the dependency layer -- the pair was not
    # being compared on the same basis.
    (cd "$APP_DIR" && npm ci --no-audit --no-fund >/dev/null)

    echo "==> starting $APP_DIR on $TARGET"
    (
        cd "$APP_DIR"
        exec node server.js
    ) >"$WORK/app.log" 2>&1 &
    APP_PID=$!
    ;;
esac

# The sleep is the whole point of this loop, and leaving it out is what broke
# the FastAPI leg in CI while every local run passed.
#
# curl returns immediately when nothing is listening, so an attempt costs
# microseconds rather than the --max-time it looks like it costs. Without a
# delay, 150 attempts burn through in well under a second: Flask binds fast
# enough to be caught anyway, uvicorn has fastapi and pydantic to import
# first, and the loop was finishing before the server existed. The budget has
# to be wall-clock time, not a number of attempts.
ready=""
WAITED=0
for _ in $(seq 1 120); do
    if [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "$TARGET/health" || true)" = "200" ]; then
        ready="yes"
        break
    fi
    if ! kill -0 "$APP_PID" 2>/dev/null; then
        echo "the fixture exited before it served anything:" >&2
        cat "$WORK/app.log" >&2
        exit 1
    fi
    sleep 0.5
    WAITED=$((WAITED + 1))
done
if [ -z "$ready" ]; then
    echo "the fixture never answered $TARGET/health after $((WAITED / 2))s:" >&2
    cat "$WORK/app.log" >&2
    exit 1
fi
echo "    up after $((WAITED / 2))s"

# --- the second component, for the exposure layer --------------------------
#
# exposure.shared-trust-domain asks whether a credential minted for one
# declared component is accepted by another, and it needs two to ask. Every
# earlier run declared a neighbour on 3000, found nothing listening, timed out
# and reported nothing -- the layer ran and could not have found anything.
#
# The neighbour here is flask-patched beside flask-vulnerable: two builds of
# one service, both validating the same bearer tokens, which is the shape the
# weakness actually takes. It is not a contrived pair -- a token minted for the
# public API working against the internal one is the finding.
if [ "$MODE" = "exposure" ]; then
    NEIGHBOUR_FIXTURE="fixtures/$STACK-patched"
    NEIGHBOUR_PORT="${NEIGHBOUR_PORT:-3000}"

    echo "==> starting $NEIGHBOUR_FIXTURE on 127.0.0.1:$NEIGHBOUR_PORT as the neighbour"
    "$BOOTSTRAP_PY_USED" -m venv "$WORK/venv-neighbour"
    NPY="$WORK/venv-neighbour/bin/python"
    [ -x "$NPY" ] || NPY="$WORK/venv-neighbour/Scripts/python.exe"
    "$NPY" -m pip install --quiet --disable-pip-version-check --upgrade pip
    "$NPY" -m pip install --quiet --disable-pip-version-check -r "$NEIGHBOUR_FIXTURE/requirements.txt"

    (
        cd "$NEIGHBOUR_FIXTURE"
        exec "$NPY" -c "from app import app; app.run(host='127.0.0.1', port=$NEIGHBOUR_PORT, debug=False, use_reloader=False)"
    ) >"$WORK/neighbour.log" 2>&1 &
    NEIGHBOUR_PID=$!

    nready=""
    for _ in $(seq 1 120); do
        if [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "http://127.0.0.1:$NEIGHBOUR_PORT/health" || true)" = "200" ]; then
            nready="yes"
            break
        fi
        if ! kill -0 "$NEIGHBOUR_PID" 2>/dev/null; then
            echo "the neighbour exited before it served anything:" >&2
            cat "$WORK/neighbour.log" >&2
            exit 1
        fi
        sleep 0.5
    done
    if [ -z "$nready" ]; then
        echo "the neighbour never answered:" >&2
        cat "$WORK/neighbour.log" >&2
        exit 1
    fi
    echo "    neighbour up"
fi

# --- scan it ----------------------------------------------------------------
#
# The seeded user tokens come from the environment, never from the config
# file, which is what lets the committed config declare them by name. These
# are the tokens the fixtures hand out.

echo "==> scanning with --target"
set +e
RUNTIME_FLAG=""
if [ "$MODE" = "runtime" ]; then
    RUNTIME_FLAG="--with-runtime"
fi

VK_USERA_TOKEN="userA-token" VK_USERB_TOKEN="userB-token" \
    go run ./cmd/vibekiller scan \
    --repo "$SCAN_REPO" \
    --config vibekiller.config.yaml \
    --target "$TARGET" \
    --i-own-this-target \
    $RUNTIME_FLAG \
    --runs-dir "$WORK/runs" >"$WORK/scan.log" 2>&1
SCAN_STATUS=$?
set -e

# A non-zero exit is expected on a vulnerable fixture: severity_threshold is
# high and it has findings above it. What must not happen is a crash, so the
# run directory is what gets checked rather than the status.
RUN_DIR="$(find "$WORK/runs" -mindepth 1 -maxdepth 1 -type d | sort | tail -1)"
if [ -z "$RUN_DIR" ] || [ ! -f "$RUN_DIR/findings.json" ]; then
    echo "the scan produced no findings.json (exit $SCAN_STATUS):" >&2
    tail -40 "$WORK/scan.log" >&2
    exit 1
fi

grep -E "^ +(ok|--|[0-9]+) +[a-z]" "$WORK/scan.log" || true
grep -E "confirmed by a non-destructive check|route\(s\) mapped" "$WORK/scan.log" || true

# --- assert -----------------------------------------------------------------

python3 - "$RUN_DIR/findings.json" "$STACK" "$MODE" <<'PY'
import json
import sys

path, stack, mode = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, encoding="utf-8") as fh:
    doc = json.load(fh)

findings = doc["findings"]
confirmed = [f for f in findings if f.get("confidence") == "confirmed"]
dast = [f for f in findings if f.get("source") == "dast"]
failed = doc.get("failed") or []

print("stack=%s mode=%s  findings=%d  dast=%d  confirmed=%d  failed_checks=%d"
      % (stack, mode, len(findings), len(dast), len(confirmed), len(failed)))
for rule in sorted({f["rule_id"] for f in confirmed}):
    print("    confirmed: " + rule)

# What each stack's vulnerable fixture must prove against a running instance.
# These lists are measured rather than assumed, and they differ because the
# fixtures differ -- FastAPI's returns no stack traces, so there is nothing
# for misconfig.verbose-error to reproduce there, and saying so is better than
# a shared list that quietly expects less of everything.
# traversal.path-escape is deliberately absent from all three. It reproduces
# on Linux and not on Windows -- the probe reads ../../etc/passwd, and path
# semantics differ -- so requiring it would make the script platform-specific
# while it is meant to be runnable by hand anywhere.
EXPECTED = {
    "flask": {
        "authz.unprotected-endpoint",
        "idor.sequential-id-access",
        "injection.sql-differential",
        "misconfig.cors-reflection",
        "misconfig.missing-security-headers",
        "misconfig.verbose-error",
    },
    "express": {
        "authz.unprotected-endpoint",
        "idor.sequential-id-access",
        "injection.sql-differential",
        "misconfig.cors-reflection",
        "misconfig.missing-security-headers",
    },
    # Thinner than the others, and that is the fixture rather than the stack.
    # fastapi-vulnerable has no CORS handling to reflect, returns clean JSON
    # errors with no stack trace, and its SQL injection produces no
    # differential response. Listing what it actually proves is better than a
    # shared list that quietly expects less of everything.
    "fastapi": {
        "authz.unprotected-endpoint",
        "idor.sequential-id-access",
        "misconfig.missing-security-headers",
    },
    # The widest of the four, because the fixture was written last and carries
    # every weakness the endpoint layer can prove.
    #
    # Three of these are the only thing that reaches their weakness at all.
    # A Django view carries no route decorator, so the traversal and mass
    # assignment rules -- both anchored on one -- cannot match a Django
    # handler, and the IDOR rule's ownership-column filter is defeated by a
    # response that serialises the owner id. The fixture's docstring records
    # each one. Static coverage of this stack is four rules; this list is what
    # makes the rest of it provable.
    "django": {
        "authz.unprotected-endpoint",
        "idor.sequential-id-access",
        "injection.sql-differential",
        "misconfig.cors-reflection",
        "misconfig.missing-security-headers",
        "misconfig.verbose-error",
        "traversal.path-escape",
    },
}

problems = []

# A check that broke makes every assertion below meaningless, whichever
# fixture this is.
for f in failed:
    problems.append("check %s failed: %s" % (f.get("check_id"), f.get("error")))

if mode == "exposure":
    # The exposure layer, which needed two components and had never been given
    # them: every earlier run declared a neighbour with nothing listening,
    # timed out against it and reported nothing.
    skipped_ids = {s.get("check_id") for s in (doc.get("skipped") or [])}
    if "exposure.shared-trust-domain" in skipped_ids:
        problems.append("exposure.shared-trust-domain was skipped")

    exposure = [f for f in findings if f["rule_id"] == "exposure.shared-trust-domain"]
    if not exposure:
        problems.append("exposure.shared-trust-domain produced no finding against two components")

    # The finding has to name the neighbour it reached, and must not have
    # reached anything else: the scope is fixed from authorized_targets before
    # a single request is sent, and the whole layer is only defensible because
    # of that.
    for f in exposure:
        blob = json.dumps(f)
        if "3000" not in blob:
            problems.append("the exposure finding does not name the neighbour it probed")
        for stranger in ("example.com", "169.254.169.254", "metadata"):
            if stranger in blob:
                problems.append("the exposure finding mentions %s, which nothing declared" % stranger)

elif mode == "runtime":
    # The runtime layer, which until this existed had never run against an
    # application at all. Its two checks are what an outside observer cannot
    # determine: whether the authorization a route declares actually executed,
    # and whether the statement behind a record read constrained its owner.
    skipped_ids = {s.get("check_id") for s in (doc.get("skipped") or [])}
    runtime_rules = {"runtime.auth-check-not-fired", "runtime.query-missing-owner-filter"}

    # Reachability first, because that was the defect. Eligibility is decided
    # before any check runs and the gate asks whether an observation has
    # arrived; an agent only reports when the app serves a request, so on an
    # idle instance the checks were skipped every single time, however
    # correctly the agent was installed.
    for rule in sorted(runtime_rules & skipped_ids):
        problems.append("%s was skipped, so the runtime layer is unreachable again" % rule)

    got = {f["rule_id"] for f in findings}
    for rule in sorted(runtime_rules - got):
        problems.append("%s produced no finding against the instrumented fixture" % rule)

    # Two things must not travel, and both are checked on the value rather
    # than on a string that resembles it. The `auth` field is a constructed
    # label -- evidenceRequest appends "-token" to the seeded user's id -- so
    # looking for "userA-token" anywhere in the finding proves nothing; this
    # fixture's token value happens to be that exact string.
    for f in findings:
        if f["rule_id"] not in runtime_rules:
            continue
        headers = ((f.get("evidence") or {}).get("request") or {}).get("headers") or {}
        for name, value in headers.items():
            if name.lower() in ("authorization", "cookie") and value != "<redacted>":
                problems.append("%s carries an unredacted %s header" % (f["rule_id"], name))

    # The statement's shape is what an observation carries. Parameter values
    # are what it must never carry, and the sink refuses an observation that
    # looks like it holds them, so a bound value appearing here would mean
    # that refusal had stopped working.
    for f in findings:
        if f["rule_id"] != "runtime.query-missing-owner-filter":
            continue
        observed = (f.get("evidence") or {}).get("observed", "")
        if "?" not in observed:
            problems.append("the query evidence shows no placeholder, so it may carry values: %s"
                            % observed[:120])

elif mode == "vulnerable":
    got = {f["rule_id"] for f in confirmed}
    for rule in sorted(EXPECTED[stack] - got):
        problems.append("%s did not reproduce against the running fixture" % rule)

    # Confirmed means re-run, so a confirmed finding without the record of the
    # re-run is the claim without the evidence.
    for f in confirmed:
        if not (f.get("reproduction") or {}).get("steps"):
            problems.append("%s claims confirmed with no reproduction steps" % f["rule_id"])

    # The access-control proof has to name the seeded record it read. That is
    # what makes it a proof rather than a status code, and what keeps it off
    # real data.
    idor = [f for f in confirmed if f["rule_id"] == "idor.sequential-id-access"]
    if idor and not any("VK-CANARY" in json.dumps(f) for f in idor):
        problems.append("no idor finding names the canary marker it read")

else:
    # Nothing may be confirmed against corrected code. A heuristic finding at
    # `likely` is allowed and expected: some patched endpoints really do answer
    # anonymous callers, by design.
    for f in confirmed:
        problems.append("%s was confirmed against the patched fixture: %s"
                        % (f["rule_id"], f.get("evidence", {}).get("summary", "")[:120]))

for p in problems:
    print("FAIL: " + p)
if problems:
    sys.exit(1)
print("ok")
PY

echo "==> $STACK/$MODE: as expected"
