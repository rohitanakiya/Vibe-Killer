# Changelog

Notable changes per release. The release pages carry the longer write-ups;
this file is the index.

The version in `vibekiller --version` carries `-dev` between releases, so a
report from an unreleased build cannot be mistaken for one from the release it
follows. Findings carry forward across runs and a regression is argued from
the history of which build saw what, which is why that distinction is in the
output rather than only in the tag.

## v1.0.0 — 2026-11-18

First release where every layer has been run against a real application.

### Added

- **Four application stacks, each proven statically and dynamically.** Flask,
  Express, FastAPI and Django, as `fixtures/<stack>-{vulnerable,patched}` pairs
  and a CI matrix leg per stack and per side. The vulnerable side must
  reproduce its expected findings against a running server; the patched side
  must report **zero confirmed** findings, since `confirmed` is reserved for a
  finding that was re-run against the instance.
- **Route extraction for every framework the adapter names.** Django URLconf
  trees including `include()` nesting and DRF routers; Next.js App and Pages
  routers, read from the file tree because its routes are not in the source;
  NestJS `@Controller` prefixes with `@UseGuards` as declared auth; koa's
  construction-time router prefix; fastify's object form in either key order.
- **SARIF 2.1.0 output** (`report --format sarif`) and `action.yml` as a
  composite action with a CI self-test. The action ships from this release
  onward.
- **`findings.json` can express what did not happen.** Separate `skipped` and
  `failed` arrays, so a consumer can tell "this layer found nothing" from
  "this layer never ran" or "this layer broke".
- **Runtime and exposure layers reachable and proven.** Both had been worse
  off than untested: the runtime checks were skipped on every idle instance
  because an agent only reports once the application serves a request, and the
  exposure check had never been given a second component to compare.
- `CHANGELOG.md`, `SECURITY.md` and `CLAUDE.md`.

### Changed

- **Rule pack: 32 rules to 45**, covering 25 contract `rule_id`s in both
  JavaScript and Python, every one pinned to a line in `rules/testdata/` in
  Semgrep's own `ruleid:`/`ok:` form. `rules/coverage_test.go` refuses a rule
  that lacks both annotation kinds, because an `ok:` on a rule that matches
  nothing passes vacuously.
- `vibekiller diff` no longer calls a finding fixed when nothing looked for
  it. A finding whose check did not run is "not re-checked", and
  `--fail-on-new` no longer passes on a run that checked less than the one
  before. This is a deliberate behaviour change.
- An `exclude:` pattern with no slash now matches a path component at any
  depth, which is how Semgrep already read it, so one config value means one
  thing to every consumer.

### Fixed

Rules that looked alive and matched nothing were the recurring theme, and all
of them were found by a fixture rather than by reading:

- `idor.missing-ownership-check` went silent on any handler that serialised
  the record's owner into its response, in all three language variants. The
  exclusion asked whether an ownership column appeared anywhere in the
  handler, so one line of ordinary correct code beside the bug switched the
  pack's flagship rule off. It now asks whether the owner is assigned or
  compared.
- Six rules carried an unconstrained `@$APP.$ROUTE(...)` anchor. Semgrep
  treats a bare decorator as a call and resolves imported names, so the anchor
  was satisfied by any imported decorator — `@wraps` from `functools`
  included.
- `authz.mass-assignment` had no Django source: `request.data` is Django REST
  Framework, and a plain view reads `request.body`.
- `traversal.path-built-from-input` was anchored on a route decorator, which a
  Django view does not have.
- `crypto.tls-verification-disabled` never fired on Python at all.
- A disabled scanner was recorded as having run successfully. On this
  repository, disabling the dependency scanner made `diff` report 97 findings
  fixed and `--fail-on-new` exit `0`.
- The Semgrep `--config` path was relative while scanners run with their cwd
  set to the repository root, so `scan --repo <anywhere-but-cwd>` silently
  lost the first-party static engine.
- `injection.sql-differential` spent its whole probe budget depth-first on the
  first route it saw, so coverage depended on enumeration order and adding an
  unrelated endpoint could silence the check.
- `exposure.shared-trust-domain` treated `localhost:5000` as a neighbour of
  `127.0.0.1:5000`, reporting one process as two components — on the
  configuration this repository ships.
- An empty rule list marshalled to `"rules": null`, so a clean scan produced
  SARIF GitHub would reject.

## v0.1.0 — 2026-11-15

First public release. Static, dependency and secret layers, the findings
contract, proof by seeded decoy record, and the run-to-run diff.

Note for anyone resolving this version: the module proxy's cached
`v0.1.0.info` records an origin commit that no longer exists, because the tag
was pushed before a history rewrite. Proxy records are permanent and this
cannot be corrected. It is harmless — module checksums are computed over the
file tree rather than the commit, so `go install ...@v0.1.0` verifies and
works. The only visible effect is that pkg.go.dev "source at this version"
links for v0.1.0 may 404.
