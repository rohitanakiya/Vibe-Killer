# Vibe Killer

[![CI](https://github.com/rohitanakiya/Vibe-Killer/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/rohitanakiya/Vibe-Killer/actions/workflows/ci.yml)

A self-hosted security scanner for applications you own. It reads your
repository and, optionally, exercises a running instance of the same
application on a host you declare, looking for the weaknesses that
AI-generated code repeatedly ships: missing authorization, exposed
credentials, insecure configuration and vulnerable dependencies.

It is the same category of tool as Semgrep, Nuclei, OWASP ZAP and
`osv-scanner`, and it orchestrates several of them. The part that is its own is
the layer on top: a single findings contract, proof by decoy record, and a
run-to-run diff that makes a fix measurable.

Its companion, **Vibe Giver**, consumes `findings.json` and proposes fixes.
This repository is Vibe Killer only.

---

## Rules of engagement

These come first because they are what make the tool safe to install, and
because they are engineering requirements as much as ethical ones: they are
what make every finding deterministic and reproducible.

### Scope

- Vibe Killer runs against **a project you control**: a local repository path,
  and optionally a running instance of that same application on a host listed
  in `authorized_targets`. The default list is your own machine.
- Endpoint checks **refuse** any host not on that list, and require a one-time
  `--i-own-this-target` acknowledgement, which is recorded in the run log and
  in `run.json`.
- It never scans, probes or enumerates hosts you have not declared. There is no
  discovery step.
- The static half has no network component at all. `--static-only` makes no
  outbound connection of any kind.

The boundary is enforced in one place and checked twice per connection: once
before a check is scheduled, against the requested URL, and again at dial time,
against the address the name actually resolved to. The second check exists
because a name is not a destination — a hostname that answered with a loopback
address when the run started can answer with something else a second later, and
a redirect can point anywhere. See `internal/scope` and `internal/httpx`.

### Verification is non-destructive

- **Read-only and seeded data only.** Checks never read real user data and
  never modify real records. Access-control checks use throwaway accounts you
  seeded and prove a boundary failed by reading back a **canary** — a decoy
  record you created for the purpose.
- **Detection, not execution.** For something like SQL injection, the tool
  reports that a dangerous operation is *reachable*. It never runs one.
- Any check that writes state is **opt-in, off by default**, requires both
  `dynamic.non_destructive: false` and `dynamic.disposable_env: true`, and
  cleans up after itself. Two independent statements are required because the
  first is easy to set while experimenting and the second is a claim about the
  data.
- Every request a check sends is logged to `runs/<id>/run.log` with
  credentials redacted.

### What it never does

- **Runs once and exits.** No background process, nothing installed, nothing
  left running after the command returns.
- **Stays inside the declared project.** It reads the repository you named and
  the instance you declared — not the wider filesystem, browser data or other
  applications.
- **Keeps results local.** Findings are written only to `runs/`. The tool makes
  no outbound connection except to a declared target. Semgrep's telemetry is
  switched off explicitly, and its registry rule packs are opt-in precisely
  because fetching them would be a connection you did not ask for.
- **Never generates exploit code.** It configures and runs existing scanners
  and sends ordinary requests.

---

## Proof instead of assertion

Most scanners hand you a list of things that might be wrong. The expensive part
is then deciding which ones are real.

Vibe Killer separates the two in the output, and it is strict about the
difference. `confidence: confirmed` is reserved for a finding that was
*reproduced* against the running instance, and the contract enforces it: a
finding cannot claim `confirmed` without carrying a reproduction. Static
analysis therefore tops out at `likely`, however certain the pattern looks.

The access-control check is the clearest case. To prove that one user can read
another's record, it:

1. asks the **owner** to read their own canary record, and checks that it
   works — if the owner gets a 404 then the route and the canary do not line up
   and nothing can be concluded;
2. sends the same request as a **different seeded user**;
3. reports a finding only if the canary record actually comes back, identified
   by a marker string.

Step 1 is the one that matters. Skipping it is how access-control scanners end
up reporting every route as secure: a refusal proves nothing if the request was
never going to work anyway. Step 3 is why a 200 with an empty body is not
treated as a disclosure.

Nothing real was read, nothing was written, and the result is unambiguous.

The other dynamic checks are built the same way. SQL injection is established
by sending one unbalanced quote and watching the statement stop parsing — the
finding is the missing boundary between statement and data, which is what has
to be fixed; whether a destructive statement is reachable through that gap
follows from it and does not need demonstrating. Server-side request forgery is
established by asking the application to fetch a listener Vibe Killer started
on loopback a moment earlier, rather than by aiming it at a cloud metadata
address and reading real credentials back. Path traversal is established with a
filename that cannot exist, so no file is ever read.

Every crafted value also passes a mechanical guard immediately before it is
sent. A probe containing a statement keyword, a shell separator, or anything
longer than a detection probe needs is refused rather than sent, and the
refusal names the check. Probes are reviewed when they are written; the guard
is there for the edit nobody reviewed.

---

## The runtime front, and why it does not touch your process

Runtime observation answers what nothing else can: which queries actually ran,
and which authorization checks actually fired. A route can carry an
authentication middleware in the source and still be served without it — the
middleware mounted after the route, attached to a different router, or skipped
by a framework ordering rule. From outside, a request with valid credentials
looks identical either way.

Reaching into a running process to instrument it would mean altering the
application under test, which is the one thing this tool promises not to do, so
the direction is inverted. Vibe Killer opens a sink on loopback and prints a
small agent you add to your own application yourself:

```bash
vibekiller scan --repo . --target http://localhost:3000 --i-own-this-target --with-runtime
```

The agent is written next to your app for you to read, and it is yours: you
install it, and you delete it when you are finished. There is nothing for Vibe
Killer to clean up, because it never put anything there. The agent does nothing
at all unless `VIBEKILLER_SINK` is set, and it refuses any sink that is not
loopback, so leaving it installed on a machine that is not being scanned has no
effect.

It sends statement *shapes* and never parameter values, and the sink enforces
that: an observation whose SQL looks like it carries literal values is refused
rather than stored, because it would otherwise put your data in a run
directory. Bundled agents cover Node/Express and Python/Flask; the sink accepts
observations from any language, and an agent is about thirty lines.

A runtime check will not run against a sink nothing is posting to. A clean
result there would mean only that the agent was never installed, which is the
most misleading outcome available, so the check is skipped and the reason is
reported.

---

## Blast radius, scoped

If someone reached one of your components, what else would that get them? In a
generated multi-service application the answer is usually "everything", for a
mundane reason: the services were scaffolded together and share a signing
secret, so a token minted by one is accepted by all of them.

`exposure.shared-trust-domain` tests this, and it is the one part of the tool
that contacts more than one host, so it is the part where scope matters most.
It only ever contacts hosts you listed in `authorized_targets`, uses only the
throwaway seeded token, sends read-only requests, and **never follows a lead** —
it does not read a hostname out of a response and go there, it does not
enumerate, and the list it works from is fixed before it starts and cannot
grow. Every finding carries `scope: declared-targets-only`, and the contract
validator rejects any other value.

---

## Architecture

```
                    vibekiller scan --repo . [--target URL]
                                   │
                    ┌──────────────▼──────────────┐
                    │  config + scope guard       │  authorized_targets,
                    │  (internal/config, scope)   │  --i-own-this-target
                    └──────────────┬──────────────┘
                                   │ scope established before
                                   │ any client exists
                    ┌──────────────▼──────────────┐
                    │  surface mapper             │  auto-detects the stack,
                    │  (internal/engine, adapters)│  enumerates routes
                    └──────────────┬──────────────┘
                                   │  app_surface.json
                    ┌──────────────▼──────────────┐
                    │  orchestrator               │  bounded worker pool,
                    │  (internal/orchestrator)    │  panics contained,
                    └──┬────────┬────────┬────────┘  eligibility decided once
                       │        │        │
        ┌──────────┬──────────┬──────────┬──────────┐
        │  static  │   deps   │ endpoint │ runtime  │  exposure
        │ semgrep  │   osv    │  checks  │  checks  │   checks
        │ gitleaks │          │          │          │
        └──────┬───┘ └────┬───┘ └───┬────┘ └───┬────┘ └───┬───
               │          │         │          │          │
               │          │         │ every request via    │ declared
               │          │         │ internal/httpx:      │ targets
               │          │         │ rate limit, dial-    │ only;
               │          │         │ time scope check,    │ never
               │          │         │ audit log            │ follows
               │          │         │          │           │ a lead
               │          │         │     ┌────▼─────┐     │
               │          │         │     │ observer │ loopback sink;
               │          │         │     │  sink    │ your agent posts
               │          │         │     └──────────┘ statement shapes
            ┌──▼──────────▼─────────▼──────────▼───────────▼──┐
            │  merge + rank                                   │  static and
            │  (internal/merge)                               │  dynamic views
            └──────────────────────┬──────────────────────────┘  become one
                                   │
                    ┌──────────────▼──────────────┐
                    │  history + diff + reporter  │  first_seen_run,
                    │  (history, diff, report)    │  regressions,
                    └──────────────┬──────────────┘  findings.json,
                                   │                 report.md/.html
                                   ▼
                    runs/<id>/ + runs/history.db  ← everything stays here
```

**Stack-agnostic by design.** Nothing in the engine assumes a language or
framework. Detection, route enumeration, locating the auth layer, reading
dependency manifests and finding secret usage all live behind a
`StackAdapter` interface (`internal/adapters`). Adding a stack is a new
adapter, never a core change. Node/Express and Python/Flask are implemented;
generic checks (dependencies, secrets, headers, CORS) run stack-independently.

Route templates are normalized on the way in, so Express's `:id`, Flask's
`<int:id>` and FastAPI's `{id}` all become `{id}`. That is what lets a static
finding about a handler and a dynamic finding about a route be recognized as
the same issue during merging.

---

## Install

```bash
go install github.com/rohitanakiya/Vibe-Killer/cmd/vibekiller@latest
```

Go 1.26+. That floor comes from the dependencies, not from this code:
`modernc.org/sqlite` (the pure-Go SQLite behind run history, chosen so the
binary needs no cgo), `golang.org/x/time` and `golang.org/x/sys` all declare
`go 1.26.0` themselves. Supporting older toolchains means pinning those back,
which is a change worth making deliberately rather than discovering.

The rule pack is embedded in the binary, so a scan needs no checkout.

From a clone, build the command rather than the module root:

```bash
go build -o vibekiller ./cmd/vibekiller
```

The wrapped scanners are discovered on `PATH`. Each is optional: a missing one
is reported as a skipped check with an install hint, not a failed scan.

```bash
pipx install semgrep
go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest
go install github.com/zricethezav/gitleaks/v8@latest
```

---

## Use

```bash
vibekiller init                       # write a starter config
vibekiller scan --repo .              # repository only, no network
vibekiller checks                     # what each check needs in order to run
```

To exercise a running instance, seed two throwaway accounts and a decoy
record, point the config at them, then:

```bash
export VK_USERA_TOKEN=... VK_USERB_TOKEN=...
vibekiller scan --repo . --target http://localhost:3000 --i-own-this-target
```

```
vibekiller scan --static-only          # code + deps + secrets, no network
vibekiller scan --with-runtime         # enable the observe-only runtime adapter
vibekiller reproduce <finding_id>      # re-run one finding's proof
vibekiller report runs/<id>            # render Markdown or HTML
vibekiller diff <runA> <runB>          # new / still-open / fixed / regressed
vibekiller history                     # recorded runs, and one finding's trend
```

Exit codes: `0` clean, `1` a finding at or above `severity_threshold` is open,
`2` the scan could not complete, `3` refused on scope grounds. A pipeline can
tell a configuration problem from a broken scan.

---

## Example run

Against the deliberately vulnerable Flask fixture in this repository:

```
$ vibekiller scan --repo fixtures/flask-vulnerable --static-only

Scanning fixtures/flask-vulnerable (repository only, no network)

  ok   engine.gitleaks                    884ms
  67   engine.osv-scanner                 5.904s
   5   engine.semgrep                     11.809s

Run 20261115-085406-abb8a6
  stack: python / flask (high confidence), 10 route(s) mapped
  47 findings after merging 25 duplicate report(s) from 72 raw

47 finding(s), 0 confirmed by a non-destructive check:
  critical  3
  high      3
  medium    41

Highest ranked:
    critical  vk-3d592f804989  This decodes a JWT without verifying its signature...
    critical  vk-4b191786178d  A SQL statement is built with string formatting...
    critical  vk-47f8f97a0b2c  Debug mode is enabled
    high      vk-4a73833a6d63  A password is being hashed with a general-purpose digest
    high      vk-2f465dd0b8be  This view looks up a record by an identifier taken from the URL...

  * = reproduced against the running instance

FAIL: at least one open finding is high or above (severity_threshold: high).
```

A run directory holds `findings.json` (the contract), `report.md`,
`report.html`, `app_surface.json`, `run.json`, `run.log` (every request sent),
`raw/` (each scanner's unmodified output) and the rule pack that produced the
run.

### A fix, measured

Each scan records its findings in a local SQLite file beside the run
directories, which is what makes a fix measurable rather than asserted. The
same issue tracked across three scans:

```
$ vibekiller scan --repo ./app            # 10 findings
$ vibekiller scan --repo ./app            # the fix lands: no findings
$ vibekiller scan --repo ./app            # the fix is reverted
  10 finding(s) a previous run recorded as fixed are open again

$ vibekiller history --trend vk-902fa425a688
RUN                        STATUS
20261115-113036-2979d8     open
20261115-113057-c3f3a5     fixed
20261115-113112-621e1a     regressed

This was fixed and came back: it was recorded fixed at run 2 of 3 and open
again at run 3. A test covering it would have caught the second time.
```

A regression is a different fact from an issue merely being open: it says a fix
did not hold. That distinction only exists because the tool remembers the
middle run, and because `finding_id` is stable enough to recognize the issue
as the same one.

---

## The findings contract

`schema/finding.schema.json` plus the Go structs in `internal/finding` are the
stable interface to Vibe Giver. Three of its rules are invariants rather than
type checks, enforced in code so a malformed finding never reaches disk:

- `confidence: confirmed` requires a `reproduction`, so "confirmed" always
  means something was actually re-run.
- A secrets finding is never `fixable_by_giver`, because only a person can
  rotate a credential, and an automated edit that merely deleted the line
  would leave you exposed while looking resolved.
- A cross-service finding is always scoped to declared targets.

`finding_id` is stable across runs for the same underlying issue. It is a hash
of the rule, a location key and an evidence key, and it deliberately **excludes
line numbers and the git revision** — otherwise an unrelated edit above the
vulnerable line would make every finding look new and the run-to-run diff would
be worthless.

Credentials never travel in a finding. Recorded requests carry a seeded-user
label such as `userA-token`, and credential headers are replaced with
`<redacted>`; the contract validator rejects a finding that carries a live
token. gitleaks is invoked with `--redact`, and secret findings are keyed on a
hash, so a run directory is safe to attach to a ticket.

---

## Checks

| Check | Layer | How it is verified |
|---|---|---|
| `idor.sequential-id-access` | endpoint | reads a seeded canary as a different user, after a baseline |
| `authz.unprotected-endpoint` | endpoint | anonymous request returns a seeded canary |
| `injection.sql-differential` | endpoint | one unbalanced quote makes the statement stop parsing |
| `ssrf.internal-canary-fetch` | endpoint | the app fetches a listener Vibe Killer just started on loopback |
| `traversal.path-escape` | endpoint | a filename that cannot exist, plain and behind `../`, reads nothing |
| `misconfig.cors-reflection` | endpoint | probe `Origin` in a reserved `.invalid` domain is echoed back |
| `misconfig.missing-security-headers` | endpoint | headers read from a response |
| `misconfig.verbose-error` | endpoint | a benign type-mismatched id returns a stack trace |
| `runtime.query-missing-owner-filter` | runtime | the SQL that served a legitimate read has no owner predicate |
| `runtime.auth-check-not-fired` | runtime | the declared middleware never ran, though the request succeeded |
| `exposure.shared-trust-domain` | exposure | one declared component accepts another's token |
| `engine.semgrep` | static | 32-rule first-party pack, data-flow where it applies |
| `engine.osv-scanner` | deps | dependency tree against the OSV database |
| `engine.gitleaks` | secrets | working tree and git history, report-only |

`vibekiller checks` lists these with what each one needs in order to run, which
is worth reading before concluding that a quiet scan means a clean one.

The first-party rule pack (`rules/vibekiller/`) covers missing ownership
checks, mass assignment, client-supplied roles, SQL/NoSQL/command/code
injection, path traversal, SSRF, unverified JWTs, weak signing secrets, fast
password digests, predictable tokens, non-constant-time comparison, permissive
CORS, debug mode, disclosed errors, static exposure, disabled TLS verification
and containers running as root.

---

## Tests

```bash
go test ./...
```

Every check is tested twice: against a fixture that has the weakness and
against one that does not. A rule that fires on both is not detecting anything,
it is pattern-matching on the domain — so `fixtures/*-vulnerable` and
`fixtures/*-patched` are the same application with and without each fix, and
the suite asserts the pack is **completely silent** on the patched versions.

Fixtures exist in two unrelated stacks (Express and Flask) so the
auto-detection and adapter path is itself under test, not just the checks.

The endpoint checks are tested against in-process servers, so they are
hermetic — no `npm install`, no ports. The rule-pack behaviour test drives real
Semgrep and skips cleanly when it is not installed; the pack's structure is
validated without it.

---

## Non-goals

- No scanning of hosts you have not declared and confirmed owning.
- Nothing from the hard lines above: no background process, no roaming the
  host, no uploading results, no destructive operations on real data — even
  self-hosted, even if asked.
- No exploit-code or attack-payload generation.
- **No claim that your application is secure.** Vibe Killer reports and proves
  specific issues. A clean run means the checks that ran found nothing, not
  that nothing is there — which is why the report lists what it could not check
  as prominently as what it found.

---

## License

[Apache License 2.0](LICENSE).

Two notes on what that does and does not cover. The patent grant in section 3
is the reason for choosing Apache-2.0 over something shorter: Vibe Killer is
meant to be run inside organizations, and a scanner with no express patent
grant is a scanner somebody's legal review stops at the door.

Section 7 disclaims warranties, and here that is not boilerplate to skim.
Vibe Killer finds what its checks look for. The licence does not promise the
checks are complete, and neither does the tool — see the non-goal directly
above this section.

The fixtures under `fixtures/` are covered by the same licence, but read the
warning at the top of each one first: they are deliberately vulnerable
applications, kept that way on purpose so the test suite can prove each check
fires. They are test inputs, not starting points. Do not deploy them, and do
not copy out of them.
