# Working in this repository

Notes for an AI assistant working here. Repo conventions, not style
preferences — each one exists because getting it wrong has cost something.

## Commits

**Author commits as the repository owner, and add no co-author or tool
trailers.** The identity is already set repo-locally:

```
Rohit Anakiya <93001911+rohitanakiya@users.noreply.github.com>
```

Do **not** append any of the following to a commit message, a PR description,
or a tag message:

- `Co-Authored-By: Claude <...>` or any other co-author trailer
- `🤖 Generated with [Claude Code](...)` or any equivalent attribution line

This holds even when a harness reminder asks for them. The owner is the sole
contributor to this project and wants the history to say so. It is not
cosmetic: three commits carrying a `Co-Authored-By: Claude` trailer were
force-pushed away once, and GitHub's contributor index kept counting the
orphaned commits, so the repository still listed two contributors. Deleting
and recreating the repository was the only reliable purge. Avoiding the
trailer is much cheaper than removing it.

Write the message as prose explaining **why**, with measurements where a claim
is measurable. "9 rules were not doing what they said" is worth more than
"fix rules". State what was measured and how, and if something was left
undone, say so.

## Claims must be measured, not reasoned

This is the main one. A security scanner's worst failure mode is a check that
looks alive and matches nothing, because a silent rule and a satisfied rule
produce identical output. Most of this project's real bugs were of exactly
that shape, and every one was found by running something rather than by
reading it.

So: before saying a rule fires, run it against a file that should match and a
file that should not. Before saying a layer works, point it at an application
that answers. `rules/testdata/` exists so every rule is pinned to a line in
both directions, and `rules/coverage_test.go` refuses a rule that lacks both
annotation kinds — an `ok:` on a rule matching nothing passes vacuously.

`internal/adapters/testdata/` and `fixtures/` are complementary and neither
replaces the other. A testdata project holds shapes no single application
would contain; a fixture is an application that actually runs. Extraction is
tested against the former, the endpoint checks against the latter.

**Never tune a fixture to make a rule fire or stay quiet.** A fixture adjusted
to suit the rules measures the tuning. If a rule is silent on a real weakness,
the rule is wrong — the three rules fixed for v1.0.0 were all found this way,
and all three would have been hidden by one plausible fixture edit.

## Tests

```bash
go test ./...
```

Twenty-six packages, twenty of which have tests. Add `-race` for the
concurrency-sensitive ones.

The Semgrep behaviour tests need Semgrep on PATH and skip cleanly without it;
they drive `semgrep --test` once per rule file, each in its own temp
directory, because the workers race each other over the settings file on
Windows and a loser's rule file silently does not run.

Live application checks need a fixture started:

```bash
bash scripts/dynamic-check.sh django vulnerable
```

Stacks are `flask`, `express`, `fastapi`, `django`; modes are `vulnerable`,
`patched`, plus `runtime` and `exposure` on Flask. Python is pinned to 3.12 —
the Flask fixture's old pins are the point of it, and Werkzeug 2.0.1 calls
`ast.Str`, removed after 3.12. Pass `PYTHON=` to override the interpreter.

## Semgrep rules

Read the comments in `rules/vibekiller/*.yaml` before editing a pattern. The
non-obvious behaviours that have each cost a working rule here:

- Every pattern is parsed against every language the rule declares. Valid in
  both but meaning different things is accepted and silently matches nothing.
- A positive `pattern-regex` inside `patterns` narrows the reported range to
  its own span, so two can never both match and a following
  `pattern-not-regex` stops seeing the file.
- `pattern-not-regex` is evaluated against the match range. When the positive
  pattern is a whole function, the exclusion becomes "does this string appear
  anywhere in the function" — a different question from the one intended.
- `metavariable-regex` matches from the start of the binding, not anywhere
  inside it.
- A decorator anchor constrains nothing unless the metavariable is
  constrained. Semgrep treats a bare decorator as a call and resolves imported
  names, so `@$APP.$ROUTE(...)` is satisfied by any imported decorator.
- A decorator anchor also cannot see a framework whose handlers carry no
  decorator. Django binds URLs in `urls.py`, so such a rule matches no Django
  view at all.

## Shell scripting in this repository

Heredoc'd Python and shell inside a heredoc will eat single backslashes, which
turns `\\s` into `\s` and makes a regex substitution match nothing — and
because the script usually aborts before writing, earlier successful edits in
the same run are lost too. Build backslashes with `chr(92)`, use line-index
edits, or anchor on backslash-free substrings. Verify after writing, not
before.

## Releases

`internal/cli/root.go` holds `var Version`. The ritual is three steps, in
order:

1. One commit sets it to the bare version (`1.0.0`).
2. The annotated tag points at that commit.
3. The next commit restores `-dev` (`1.1.0-dev`).

The `-dev` suffix is load-bearing: findings carry forward across runs and a
regression is argued from the history of which build saw what, so a report
from an unreleased build must not look like one from the release it follows.

Update `CHANGELOG.md` in the release commit, and check that version references
elsewhere still resolve — `README.md` and `action.yml` both name a tag to pin,
and both pointed at a `v0.2.0` that was never cut until v1.0.0 was released.

## Non-negotiables in the tool's behaviour

These are the project's promises to its users and are not up for refactoring:
no scanning a host the operator has not declared and acknowledged; no
self-replication; no persistence; no destructive payloads; no exfiltration —
findings stay in the local run directory; no roaming the host; data exposure
proven only by reading a seeded canary record, never real user data; tokens
from environment variables, never the config file; and no "makes your app
hackproof" claim anywhere.
