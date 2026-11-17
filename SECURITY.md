# Security policy

## Reporting a vulnerability

Report privately through GitHub's **[Report a vulnerability][advisory]** form
on this repository, which opens a draft security advisory visible only to you
and the maintainer. Please do not open a public issue for a vulnerability.

[advisory]: https://github.com/rohitanakiya/Vibe-Killer/security/advisories/new

Useful in a report: the version (`vibekiller --version`), the command you ran,
what happened, and what you expected instead. A failing fixture or a minimal
repository that reproduces it is worth more than a description.

Expect an acknowledgement within a few days. This is a single-maintainer
project, so there is no guaranteed response time beyond that.

## What counts as a vulnerability here

Vibe Killer is a scanner that an operator points at their own code and,
optionally, at their own running instance. Its security properties are mostly
about **staying inside that boundary**, so the reports that matter most are
the ones where it does not:

- **A scan reaching a host the operator did not declare.** Active checks are
  refused unless the host is in `authorized_targets` and the operator passed
  `--i-own-this-target`. Any path that bypasses either, or that touches a host
  not in that list, is a vulnerability.
- **Anything leaving the machine.** Findings are written to the local run
  directory and nowhere else. A code path that uploads, phones home, or
  includes scan contents in an outbound request is a vulnerability.
- **A destructive or persistent side effect.** Verification is read-only by
  default and uses benign markers; there is no daemon, no scheduled task and
  no implant. Anything that writes, deletes, or survives the process is a
  vulnerability.
- **Reading beyond the target.** The scanner works on the repository path it
  was given and does not roam the filesystem. A traversal out of that path is
  a vulnerability.
- **Secret disclosure.** Tokens come from environment variables and are never
  read from or written to the config file. A secret reaching `findings.json`,
  a log line, a report or a request is a vulnerability. The secret scanner is
  report-only and must stay that way.
- **Command injection through operator input** — a repository path, a config
  value, a route, or a filename from a scanned tree reaching a shell.

## What does not count

- **A false positive or a false negative in a rule.** These are bugs and worth
  an issue, with the file that should or should not have matched. They are not
  security vulnerabilities in this tool. The rule pack is deliberately tuned
  toward reporting a weakness it cannot fully prove at `likely` rather than
  staying silent, and `confirmed` is reserved for findings re-run against a
  live instance.
- **The deliberately vulnerable fixtures.** Everything under `fixtures/` is
  broken on purpose: unauthenticated endpoints, string-built SQL, path
  traversal, old pinned dependencies with known CVEs. They exist so the checks
  have something true to find and are never meant to be deployed. Advisories
  against their pinned dependencies are the point of them. The same goes for
  `rules/testdata/` and the sample projects under `internal/adapters/testdata/`.
- **Findings Vibe Killer reports about your own application.** Those are for
  you to fix in your code; this policy covers the scanner itself.
- **Vulnerabilities in the wrapped scanners** (Semgrep, osv-scanner,
  gitleaks). Report those to their own projects. If Vibe Killer invokes one
  unsafely, that is ours.

## Supported versions

The latest release receives fixes. Older tags are not patched; upgrade
instead.

| Version | Supported |
|---|---|
| 1.0.x | yes |
| 0.1.x | no |

## Scope of the tool itself

Vibe Killer is for applications you control. Pointing it at a host you do not
own is outside both this policy and the project's
[rules of engagement](README.md#rules-of-engagement), and the scope guard is
there to make that refusal the default rather than a matter of discipline.
