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
flask | express | fastapi) ;;
*)
    echo "usage: $0 <flask|express|fastapi> <vulnerable|patched>" >&2
    exit 2
    ;;
esac
case "$MODE" in
vulnerable | patched) ;;
*)
    echo "usage: $0 <flask|express|fastapi> <vulnerable|patched>" >&2
    exit 2
    ;;
esac

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

FIXTURE="fixtures/$STACK-$MODE"
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

WORK="$(mktemp -d)"
APP_PID=""

cleanup() {
    if [ -n "$APP_PID" ] && kill -0 "$APP_PID" 2>/dev/null; then
        kill "$APP_PID" 2>/dev/null || true
        wait "$APP_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

# Secrets for the patched fixtures, which read their signing keys from the
# environment rather than carrying one in the source -- that being the fix
# their vulnerable twins are missing. Each stack names them differently, so all
# of them are set.
export JWT_SIGNING_KEY="dynamic-check-only-not-a-secret"
export FIXTURE_JWT_SECRET="dynamic-check-only-not-a-secret"
export ADMIN_API_KEY="dynamic-check-only-not-a-secret"
export PORT

# --- install and start ------------------------------------------------------

start_python_fixture() {
    local entry="$1" # the python expression that serves the app

    # PYTHON overrides the interpreter, and the vulnerable Flask fixture is why
    # it exists. Its pins are deliberately old so the dependency check finds
    # advisories for them, and Werkzeug 2.0.1 calls ast.Str, which Python
    # removed after 3.12 -- so that fixture cannot be served by an arbitrary
    # interpreter. CI pins 3.12 for this job; locally, pass
    # PYTHON=/path/to/python3.12.
    local bootstrap="${PYTHON:-python3}"

    echo "==> creating a virtualenv for $FIXTURE ($("$bootstrap" --version 2>&1))"

    # A venv per fixture rather than one shared one: flask-vulnerable pins
    # Flask 2.0.1 and flask-patched pins 3.1.0, and installing both into one
    # environment would mean testing neither.
    "$bootstrap" -m venv "$WORK/venv"
    local py="$WORK/venv/bin/python"
    [ -x "$py" ] || py="$WORK/venv/Scripts/python.exe"

    "$py" -m pip install --quiet --disable-pip-version-check --upgrade pip
    "$py" -m pip install --quiet --disable-pip-version-check -r "$FIXTURE/requirements.txt"

    echo "==> starting $FIXTURE on $TARGET"
    (
        cd "$FIXTURE"
        exec "$py" -c "$entry"
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
    if [ "$MODE" = "vulnerable" ]; then FLASK_DEBUG_FLAG="True"; else FLASK_DEBUG_FLAG="False"; fi
    # use_reloader=False in both cases. The reloader forks, and a fixture that
    # outlives the script is a port left bound for whatever runs next.
    start_python_fixture "from app import app; app.run(host='127.0.0.1', port=$PORT, debug=$FLASK_DEBUG_FLAG, use_reloader=False)"
    ;;
fastapi)
    start_python_fixture "import uvicorn; from main import app; uvicorn.run(app, host='127.0.0.1', port=$PORT, log_level='warning')"
    ;;
express)
    echo "==> installing $FIXTURE (node $(node --version))"
    # npm ci where a lockfile is committed, because then the transitive pins
    # are fixed and are what the dependency check reads. express-vulnerable
    # has one; express-patched does not, so its transitive versions resolve
    # fresh and npm ci refuses to run at all.
    if [ -f "$FIXTURE/package-lock.json" ]; then
        (cd "$FIXTURE" && npm ci --no-audit --no-fund >/dev/null)
    else
        (cd "$FIXTURE" && npm install --no-audit --no-fund >/dev/null)
    fi

    echo "==> starting $FIXTURE on $TARGET"
    (
        cd "$FIXTURE"
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

# --- scan it ----------------------------------------------------------------
#
# The seeded user tokens come from the environment, never from the config
# file, which is what lets the committed config declare them by name. These
# are the tokens the fixtures hand out.

echo "==> scanning with --target"
set +e
VK_USERA_TOKEN="userA-token" VK_USERB_TOKEN="userB-token" \
    go run ./cmd/vibekiller scan \
    --repo "$FIXTURE" \
    --config vibekiller.config.yaml \
    --target "$TARGET" \
    --i-own-this-target \
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
}

problems = []

# A check that broke makes every assertion below meaningless, whichever
# fixture this is.
for f in failed:
    problems.append("check %s failed: %s" % (f.get("check_id"), f.get("error")))

if mode == "vulnerable":
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
