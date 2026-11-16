#!/usr/bin/env bash
#
# Run Vibe Killer's dynamic layer against a fixture that is actually running.
#
# Everything else in this repository tests the endpoint checks against
# httptest handlers written in Go -- closures that answer the way a vulnerable
# Flask app is expected to answer. That proves the check's logic against our
# own idea of the application, and nothing more. It is the same gap the Django
# extractor had: the code looked right, the tests agreed with it, and nothing
# had asked a real server.
#
# So this boots the fixture, points a real scan at it with --target, and
# asserts on what came back:
#
#   vulnerable   the endpoint checks reproduce specific findings, every
#                reproduction carries its steps, and the access-control proof
#                names the seeded canary it read
#   patched      nothing is confirmed at all
#
# Confirmed is the assertion that matters on both sides. The README reserves
# `confidence: confirmed` for a finding that was re-run against the instance,
# so zero confirmed findings on corrected code is the claim worth pinning --
# while still allowing an honest heuristic finding at `likely`, which the
# patched fixture does produce for an endpoint that really is anonymous.
#
# Usage:  scripts/dynamic-check.sh vulnerable|patched
#
# Needs: go, python3 (3.12 or newer), curl. Writes to a temporary directory and
# removes it, and stops the fixture on any exit path.

set -euo pipefail

MODE="${1:-}"
case "$MODE" in
vulnerable | patched) ;;
*)
    echo "usage: $0 vulnerable|patched" >&2
    exit 2
    ;;
esac

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

FIXTURE="fixtures/flask-$MODE"
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

# --- the fixture's own dependencies, in their own environment ---------------
#
# A venv per fixture rather than one shared one: flask-vulnerable pins Flask
# 2.0.1 because the dependency check is supposed to find advisories for it, and
# flask-patched pins 3.1.0. Installing both into one environment would mean
# testing neither.

# PYTHON overrides the interpreter, and the vulnerable fixture is why it
# exists. Its pins are deliberately old so the dependency check finds
# advisories for them, and Werkzeug 2.0.1 calls ast.Str, which Python removed
# after 3.12 -- so the fixture cannot be served by an arbitrary interpreter.
# CI pins 3.12 for this job; locally, pass PYTHON=/path/to/python3.12.
BOOTSTRAP_PY="${PYTHON:-python3}"

echo "==> creating a virtualenv for $FIXTURE ($("$BOOTSTRAP_PY" --version 2>&1))"
"$BOOTSTRAP_PY" -m venv "$WORK/venv"

# Windows puts the interpreter somewhere else, and this script is run by hand
# there as well as by CI.
if [ -x "$WORK/venv/bin/python" ]; then
    PY="$WORK/venv/bin/python"
else
    PY="$WORK/venv/Scripts/python.exe"
fi

"$PY" -m pip install --quiet --disable-pip-version-check --upgrade pip
"$PY" -m pip install --quiet --disable-pip-version-check -r "$FIXTURE/requirements.txt"

# --- start it ---------------------------------------------------------------
#
# debug is on for the vulnerable fixture and off for the patched one, which is
# each one's own configuration: misconfig.verbose-error reproduces by asking
# for a stack trace, so running the vulnerable app with the debugger off would
# quietly disarm one of the checks under test.
#
# use_reloader=False in both cases. The reloader forks, and a fixture that
# outlives the script is a port left bound for the next job on the runner.

if [ "$MODE" = "vulnerable" ]; then
    DEBUG="True"
else
    DEBUG="False"
fi

echo "==> starting $FIXTURE on $TARGET (debug=$DEBUG)"
(
    cd "$FIXTURE"
    JWT_SIGNING_KEY="dynamic-check-only-not-a-secret" \
        ADMIN_API_KEY="dynamic-check-only-not-a-secret" \
        FIXTURE_JWT_SECRET="dynamic-check-only-not-a-secret" \
        exec "$PY" -c "from app import app; app.run(host='127.0.0.1', port=$PORT, debug=$DEBUG, use_reloader=False)"
) >"$WORK/app.log" 2>&1 &
APP_PID=$!

ready=""
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
done
if [ -z "$ready" ]; then
    echo "the fixture never answered $TARGET/health:" >&2
    cat "$WORK/app.log" >&2
    exit 1
fi
echo "    up"

# --- scan it ----------------------------------------------------------------
#
# The seeded user tokens come from the environment, never from the config
# file, which is what lets the committed config declare them by name. The
# tokens here are the ones the fixtures hand out.

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

# A non-zero exit is expected on the vulnerable fixture: severity_threshold is
# high and it has findings above it. What must not happen is a crash, so the
# run directory is the thing to check for rather than the status.
RUN_DIR="$(find "$WORK/runs" -mindepth 1 -maxdepth 1 -type d | sort | tail -1)"
if [ -z "$RUN_DIR" ] || [ ! -f "$RUN_DIR/findings.json" ]; then
    echo "the scan produced no findings.json (exit $SCAN_STATUS):" >&2
    tail -40 "$WORK/scan.log" >&2
    exit 1
fi

sed -n '1,25p' "$WORK/scan.log"
echo "    ..."
grep -E "confirmed by a non-destructive check|route\(s\) mapped" "$WORK/scan.log" || true

# --- assert -----------------------------------------------------------------

python3 - "$RUN_DIR/findings.json" "$MODE" <<'PY'
import json
import sys

path, mode = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as fh:
    doc = json.load(fh)

findings = doc["findings"]
confirmed = [f for f in findings if f.get("confidence") == "confirmed"]
dast = [f for f in findings if f.get("source") == "dast"]
failed = doc.get("failed") or []

print("findings=%d  dast=%d  confirmed=%d  failed_checks=%d"
      % (len(findings), len(dast), len(confirmed), len(failed)))

problems = []

# A check that broke makes every assertion below meaningless, whichever
# fixture this is.
for f in failed:
    problems.append("check %s failed: %s" % (f.get("check_id"), f.get("error")))

if mode == "vulnerable":
    want = {
        "authz.unprotected-endpoint",
        "idor.sequential-id-access",
        "injection.sql-differential",
        "misconfig.cors-reflection",
        "misconfig.verbose-error",
    }
    got = {f["rule_id"] for f in confirmed}
    for rule in sorted(want - got):
        problems.append("%s did not reproduce against the running fixture" % rule)

    # Confirmed means re-run, so a confirmed finding without the record of
    # the re-run is the claim without the evidence.
    for f in confirmed:
        rep = f.get("reproduction") or {}
        if not rep.get("steps"):
            problems.append("%s claims confirmed with no reproduction steps" % f["rule_id"])

    # The access-control proof has to name the seeded record it read. That is
    # what makes it a proof rather than a status code, and what keeps it off
    # real data.
    idor = [f for f in confirmed if f["rule_id"] == "idor.sequential-id-access"]
    if not any("VK-CANARY" in json.dumps(f) for f in idor):
        problems.append("no idor finding names the canary marker it read")

    if len(confirmed) < 5:
        problems.append("only %d findings were confirmed" % len(confirmed))

else:
    # Nothing may be confirmed against corrected code. A heuristic finding at
    # `likely` is allowed and expected: /api/session really does answer
    # anonymous callers in the patched fixture, by design.
    for f in confirmed:
        problems.append("%s was confirmed against the patched fixture: %s"
                        % (f["rule_id"], f.get("evidence", {}).get("summary", "")[:120]))

for p in problems:
    print("FAIL: " + p)
if problems:
    sys.exit(1)
print("ok")
PY

echo "==> $MODE: as expected"
