package staticchecks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rohitanakiya/Vibe-Killer/internal/check"
	"github.com/rohitanakiya/Vibe-Killer/internal/config"
	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
	"github.com/rohitanakiya/Vibe-Killer/internal/run"
	"github.com/rohitanakiya/Vibe-Killer/internal/tool"
	"github.com/rohitanakiya/Vibe-Killer/rules"
)

// This is the test the brief asks for: each check fires on the vulnerable
// fixture and stays silent on the patched one, in two unrelated stacks.
//
// It drives real Semgrep against the real rule pack, so it needs Semgrep
// installed and skips cleanly when it is not. The rule pack's own structure is
// checked without Semgrep by the tests in the rules package, so a machine
// without Semgrep still validates the pack; what it cannot validate is whether
// the patterns match the code they are meant to match, which is exactly what
// this test is for.

func fixtureRoot(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "..", "fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Skipf("fixture %s is not present", name)
	}
	return p
}

func requireSemgrep(t *testing.T) {
	t.Helper()
	if !tool.New(tool.SemgrepSpec, "", nil).Available() {
		t.Skip("semgrep is not installed; skipping the rule-pack behaviour test. " +
			"Install it with: pipx install semgrep")
	}
}

// semgrepEnv builds an environment with the embedded rule pack written to disk.
func semgrepEnv(t *testing.T, repoRoot string) *check.Env {
	t.Helper()

	cfg := config.Defaults()
	// Only the first-party pack: no registry packs, so the test needs no
	// network and measures this project's own rules.
	cfg.Scanners.Semgrep.RulePacks = nil
	cfg.Scanners.OSV.Disabled = true
	cfg.Scanners.Gitleaks.Disabled = true

	r, err := run.Create(t.TempDir(), run.Meta{RunID: "test", Tool: "vibekiller", Mode: "static-only"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })

	rulesDir, err := rules.Materialize(r.Path())
	if err != nil {
		t.Fatal(err)
	}

	return &check.Env{
		Config: &cfg, Run: r, RepoRoot: repoRoot, RulesDir: rulesDir,
	}
}

func runSemgrep(t *testing.T, fixture string) []finding.Finding {
	t.Helper()
	root := fixtureRoot(t, fixture)
	env := semgrepEnv(t, root)

	fs, err := (&SemgrepEngine{}).Detect(context.Background(), env)
	if err != nil {
		t.Fatalf("semgrep failed on %s: %v", fixture, err)
	}
	return fs
}

func ruleIDs(fs []finding.Finding) map[string]int {
	out := map[string]int{}
	for _, f := range fs {
		out[f.RuleID]++
	}
	return out
}

// The vulnerable fixtures must produce a finding for each weakness the pack
// claims to cover in that stack.
func TestRulePackFiresOnVulnerableFixtures(t *testing.T) {
	requireSemgrep(t)

	tests := []struct {
		fixture  string
		wantRule []string
	}{
		{
			fixture: "flask-vulnerable",
			wantRule: []string{
				"idor.missing-ownership-check",
				// `payload = request.json or {}` on one line and
				// `order.update(payload)` on another, which is why the Python
				// mass-assignment rule had to be written in taint mode: no
				// single-expression pattern sees both.
				"authz.mass-assignment",
				"injection.sql-string-built-from-input",
				"injection.command-built-from-input",
				"traversal.path-built-from-input",
				"ssrf.user-supplied-url-fetched",
				"auth.jwt-not-verified",
				"crypto.password-fast-digest",
				"crypto.predictable-token",
				"misconfig.debug-mode-enabled",
				"misconfig.cors-credentialed-wildcard",
			},
		},
		{
			// The fourth stack. It was written to give the endpoint layer a
			// Django server to ask, and what it first measured was how
			// little of the static pack reached one: four rules, where this
			// list now has seven. Each of the three it gained was a defect
			// in a rule, found only because a fixture asked:
			//
			//	idor.missing-ownership-check suppressed itself whenever a
			//	handler serialised the record's owner into its response. One
			//	ordinary line of correct code switched the pack's flagship
			//	rule off, in all three of its language variants.
			//
			//	authz.mass-assignment had every part of the Django flow
			//	except where it starts: request.data is Django REST
			//	Framework, and a plain view reads request.body.
			//
			//	traversal.path-built-from-input was anchored on a route
			//	decorator, which a Django view does not have.
			//
			// All three are pinned in rules/testdata/ with the Django shape
			// beside the Flask and FastAPI ones.
			fixture: "django-vulnerable",
			wantRule: []string{
				"authz.mass-assignment",
				"idor.missing-ownership-check",
				"injection.sql-string-built-from-input",
				"misconfig.cors-credentialed-wildcard",
				"misconfig.debug-mode-enabled",
				"misconfig.wildcard-allowed-hosts",
				"traversal.path-built-from-input",
			},
		},
		{
			// The third stack, and the one that measures whether a rule is
			// written for Python or only for Flask.
			//
			// This list used to be six rules long, and the four that have
			// joined it are the four that could not fire on FastAPI for
			// reasons that had nothing to do with the fixture:
			// idor.missing-ownership-check was anchored on @app.route,
			// ssrf.user-supplied-url-fetched took its taint sources from a
			// Flask request object that FastAPI has no equivalent of,
			// auth.jwt-unsigned-algorithm-accepted only matched "none" as the
			// first algorithm in the list, and
			// crypto.tls-verification-disabled matched nothing on Python at
			// all. All four are reported here now.
			fixture: "fastapi-vulnerable",
			wantRule: []string{
				"injection.sql-string-built-from-input",
				"traversal.path-built-from-input",
				"auth.jwt-not-verified",
				"auth.jwt-unsigned-algorithm-accepted",
				"crypto.password-fast-digest",
				"crypto.predictable-token",
				"crypto.non-constant-time-comparison",
				"crypto.tls-verification-disabled",
				"idor.missing-ownership-check",
				"ssrf.user-supplied-url-fetched",
				// `order.update(payload.model_dump())`, where payload is a
				// handler parameter. The taint only starts because a
				// decorated handler's parameters are sources.
				"authz.mass-assignment",
			},
		},
		{
			// injection.code-evaluation-of-input is deliberately not on this
			// list any more, and its absence is a fix rather than a loss.
			// server.js contains no eval, no Function constructor and no vm
			// call; what it has is `exec('convert ' + req.body.filename)`.
			// The rule declared [javascript, typescript, python] and listed
			// `exec(...)` as a sink for Python's exec builtin, where in
			// JavaScript it matched child_process.exec -- so the fixture's
			// command injection was reported a second time, as code
			// evaluation, in a different category. Splitting the rule per
			// language removed the collision.
			//
			// crypto.password-fast-digest has joined the list for the
			// opposite reason: it never matched JavaScript at all, because
			// the digest pattern stopped at the algorithm name and the
			// credential-name filter had no password left in range.
			fixture: "express-vulnerable",
			wantRule: []string{
				"idor.missing-ownership-check",
				"injection.sql-string-built-from-input",
				"injection.command-built-from-input",
				"traversal.path-built-from-input",
				"ssrf.user-supplied-url-fetched",
				"auth.jwt-not-verified",
				"auth.session-cookie-unprotected",
				"authz.client-supplied-role",
				"crypto.password-fast-digest",
				"crypto.predictable-token",
				"misconfig.cors-credentialed-wildcard",
				"misconfig.error-detail-disclosed",
				"misconfig.static-exposure",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.fixture, func(t *testing.T) {
			fs := runSemgrep(t, tc.fixture)
			got := ruleIDs(fs)

			for _, want := range tc.wantRule {
				if got[want] == 0 {
					t.Errorf("rule %s did not fire on %s", want, tc.fixture)
				}
			}

			t.Logf("%s produced %d findings across %d rules", tc.fixture, len(fs), len(got))
			for id, n := range got {
				t.Logf("  %dx %s", n, id)
			}

			// Everything emitted has to satisfy the contract, or it would fail
			// the findings.json write at the end of a real run.
			if err := finding.ValidateAll(fs); err != nil {
				t.Errorf("findings break the contract: %v", err)
			}
		})
	}
}

// The other half, and the one that actually distinguishes a scanner from a
// keyword search: the same rules must say nothing about the corrected code.
func TestRulePackIsSilentOnPatchedFixtures(t *testing.T) {
	requireSemgrep(t)

	for _, fixture := range []string{
		"flask-patched", "express-patched", "fastapi-patched", "django-patched",
	} {
		t.Run(fixture, func(t *testing.T) {
			fs := runSemgrep(t, fixture)
			if len(fs) == 0 {
				return
			}

			for _, f := range fs {
				t.Errorf("false positive on corrected code: %s at %s:%d\n    %s",
					f.RuleID, f.Location.File, f.Location.Line, f.Evidence.Summary)
			}
		})
	}
}

// A static rule may never claim it reproduced anything. Only an endpoint check
// that actually re-ran the request earns confirmed.
func TestStaticFindingsNeverClaimConfirmed(t *testing.T) {
	requireSemgrep(t)

	for _, fixture := range []string{
		"flask-vulnerable", "express-vulnerable", "fastapi-vulnerable", "django-vulnerable",
	} {
		for _, f := range runSemgrep(t, fixture) {
			if f.Confidence == finding.ConfidenceConfirmed {
				t.Errorf("%s (%s) claims confirmed confidence from a static scan", f.RuleID, fixture)
			}
		}
	}
}

// A credential cannot be fixed by editing code: it is already disclosed and
// has to be rotated. Any rule in the secrets category must say so.
func TestSecretFindingsRequireAHuman(t *testing.T) {
	requireSemgrep(t)

	for _, fixture := range []string{
		"flask-vulnerable", "express-vulnerable", "fastapi-vulnerable", "django-vulnerable",
	} {
		for _, f := range runSemgrep(t, fixture) {
			if f.Category != finding.CategorySecretsExposure {
				continue
			}
			if f.Remediation.FixableByGiver {
				t.Errorf("%s (%s) is marked auto-fixable, but a disclosed credential needs rotating",
					f.RuleID, fixture)
			}
			if f.Remediation.HumanRequiredReason == "" {
				t.Errorf("%s (%s) gives no reason a human is required", f.RuleID, fixture)
			}
		}
	}
}

// Every finding has to point somewhere a person can go, with a repo-relative
// path rather than whatever absolute path the scanner happened to print.
func TestFindingsCarryUsableLocations(t *testing.T) {
	requireSemgrep(t)

	for _, f := range runSemgrep(t, "flask-vulnerable") {
		if f.Location.File == "" {
			t.Errorf("%s has no file", f.RuleID)
			continue
		}
		if filepath.IsAbs(f.Location.File) {
			t.Errorf("%s has an absolute path %q; it should be repo-relative", f.RuleID, f.Location.File)
		}
		if strings.Contains(f.Location.File, `\`) {
			t.Errorf("%s has a backslash path %q; the contract specifies forward slashes", f.RuleID, f.Location.File)
		}
		if f.Location.Line <= 0 {
			t.Errorf("%s has no line number", f.RuleID)
		}
		if f.Evidence.Summary == "" {
			t.Errorf("%s has no evidence summary", f.RuleID)
		}
		if f.Remediation.Guidance == "" {
			t.Errorf("%s has no guidance", f.RuleID)
		}
	}
}

// A missing scanner is a reported skip, not a failed scan. A partial run that
// says which engine was absent is more useful than no run.
func TestAMissingScannerIsReportedNotFatal(t *testing.T) {
	cfg := config.Defaults()
	cfg.Scanners.Semgrep.Path = "definitely-not-a-real-binary-vk"

	r, err := run.Create(t.TempDir(), run.Meta{RunID: "test", Tool: "vibekiller"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })

	env := &check.Env{Config: &cfg, Run: r, RepoRoot: t.TempDir()}

	_, err = (&SemgrepEngine{}).Detect(context.Background(), env)
	if err == nil {
		t.Fatal("expected an error naming the missing scanner")
	}

	var notInstalled *tool.ErrNotInstalled
	if !strings.Contains(err.Error(), "not installed") {
		t.Errorf("error = %v, want it to say the tool is not installed", err)
	}
	_ = notInstalled
}

// A scanner the operator turned off says so, rather than returning nothing.
//
// The previous version of this test asserted that Detect returned no error at
// all, and that assertion is what kept the defect invisible for so long: the
// name said "skipped quietly" while the body asserted
// indistinguishable-from-a-clean-scan. (nil, nil) left the check in neither
// the skipped nor the failed list, so nothing in findings.json said the layer
// had not run and diff called its findings fixed on the next run.
//
// All three engines had it, so all three are checked.
func TestADisabledScannerReportsThatItWasDisabled(t *testing.T) {
	cases := []struct {
		name    string
		disable func(c *config.Config)
		engine  check.Check
		key     string
	}{
		{
			name:    "semgrep",
			disable: func(c *config.Config) { c.Scanners.Semgrep.Disabled = true },
			engine:  &SemgrepEngine{},
			key:     "scanners.semgrep.disabled",
		},
		{
			name:    "osv-scanner",
			disable: func(c *config.Config) { c.Scanners.OSV.Disabled = true },
			engine:  &OSVEngine{},
			key:     "scanners.osv_scanner.disabled",
		},
		{
			name:    "gitleaks",
			disable: func(c *config.Config) { c.Scanners.Gitleaks.Disabled = true },
			engine:  &GitleaksEngine{},
			key:     "scanners.gitleaks.disabled",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			tc.disable(&cfg)

			r, err := run.Create(t.TempDir(), run.Meta{RunID: "test", Tool: "vibekiller"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = r.Close() })

			env := &check.Env{Config: &cfg, Run: r, RepoRoot: t.TempDir()}

			fs, err := tc.engine.Detect(context.Background(), env)
			if len(fs) != 0 {
				t.Errorf("a disabled scanner produced %d findings", len(fs))
			}
			if err == nil {
				t.Fatal("a disabled scanner returned no error, so the orchestrator " +
					"cannot tell it from a scan that ran and found nothing")
			}
			// The sentinel is what the orchestrator classifies on, and it has
			// to be distinguishable from a scanner that is merely absent: a
			// consumer should retry one and not the other.
			if !errors.Is(err, tool.ErrDisabled) {
				t.Errorf("error = %v, want it to wrap tool.ErrDisabled", err)
			}
			var absent *tool.ErrNotInstalled
			if errors.As(err, &absent) {
				t.Errorf("error = %v, want it not to look like a missing binary", err)
			}
			// The reason doubles as the instruction for turning it back on.
			if !strings.Contains(err.Error(), tc.key) {
				t.Errorf("error = %q, want it to name %s", err.Error(), tc.key)
			}
		})
	}
}
