package staticchecks

import (
	"context"
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
			// The third stack. The list is shorter than Flask's and that is
			// the finding rather than an oversight: several rules in the pack
			// are shaped around Flask and Django request idioms and cannot
			// match FastAPI, so they are deliberately absent here. See the
			// FRAMEWORK-GAP notes in the fixture.
			fixture: "fastapi-vulnerable",
			wantRule: []string{
				"injection.sql-string-built-from-input",
				"traversal.path-built-from-input",
				"auth.jwt-not-verified",
				"crypto.password-fast-digest",
				"crypto.predictable-token",
				"crypto.non-constant-time-comparison",
			},
		},
		{
			fixture: "express-vulnerable",
			wantRule: []string{
				"idor.missing-ownership-check",
				"injection.sql-string-built-from-input",
				"injection.command-built-from-input",
				"injection.code-evaluation-of-input",
				"traversal.path-built-from-input",
				"ssrf.user-supplied-url-fetched",
				"auth.jwt-not-verified",
				"auth.session-cookie-unprotected",
				"authz.client-supplied-role",
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

	for _, fixture := range []string{"flask-patched", "express-patched", "fastapi-patched"} {
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

	for _, fixture := range []string{"flask-vulnerable", "express-vulnerable", "fastapi-vulnerable"} {
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

	for _, fixture := range []string{"flask-vulnerable", "express-vulnerable", "fastapi-vulnerable"} {
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

// A scanner the operator turned off produces nothing and no error.
func TestADisabledScannerIsSkippedQuietly(t *testing.T) {
	cfg := config.Defaults()
	cfg.Scanners.Semgrep.Disabled = true

	r, err := run.Create(t.TempDir(), run.Meta{RunID: "test", Tool: "vibekiller"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })

	env := &check.Env{Config: &cfg, Run: r, RepoRoot: t.TempDir()}

	fs, err := (&SemgrepEngine{}).Detect(context.Background(), env)
	if err != nil {
		t.Errorf("a disabled scanner should not error: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("a disabled scanner produced %d findings", len(fs))
	}
}
