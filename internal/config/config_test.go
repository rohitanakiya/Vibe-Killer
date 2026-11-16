package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultFileName)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadMissingFileUsesDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != nil {
		t.Fatalf("a missing config should fall back to defaults, got: %v", err)
	}
	if cfg.SourcePath() != "" {
		t.Errorf("SourcePath should be empty for defaults, got %q", cfg.SourcePath())
	}
	if !cfg.IsNonDestructive() {
		t.Error("the default posture must be non-destructive")
	}
	if cfg.MutatingChecksAllowed() {
		t.Error("mutating checks must not be allowed by default")
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("the defaults should themselves be valid: %v", err)
	}
}

func TestLoadEmptyFileUsesDefaults(t *testing.T) {
	path := writeConfig(t, "# nothing but a comment\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("an empty config file should be valid: %v", err)
	}
	if cfg.Dynamic.MaxRPS != 10 {
		t.Errorf("defaults were not applied, max_rps = %v", cfg.Dynamic.MaxRPS)
	}
}

func TestLoadFullConfig(t *testing.T) {
	path := writeConfig(t, `
repo_path: ./app
authorized_targets:
  - http://localhost:3000
runtime:
  enabled: true
seeded_users:
  - { id: userA, token_env: VK_USERA_TOKEN }
  - { id: userB, token_env: VK_USERB_TOKEN, role: member }
canary_records:
  - { owner: userB, resource: order, id: "90001", marker: "VK-CANARY-B" }
dynamic:
  non_destructive: true
  disposable_env: false
  max_rps: 5
severity_threshold: medium
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a valid config was rejected: %v", err)
	}

	if cfg.RepoPath != "./app" {
		t.Errorf("repo_path = %q", cfg.RepoPath)
	}
	if cfg.SeverityThreshold != finding.SeverityMedium {
		t.Errorf("severity_threshold = %q", cfg.SeverityThreshold)
	}
	if cfg.Dynamic.MaxRPS != 5 {
		t.Errorf("max_rps = %v", cfg.Dynamic.MaxRPS)
	}
	// Unset nested values must keep their defaults.
	if cfg.Dynamic.Concurrency != 4 || cfg.Dynamic.TimeoutSeconds != 15 {
		t.Errorf("nested defaults lost: concurrency=%d timeout=%d", cfg.Dynamic.Concurrency, cfg.Dynamic.TimeoutSeconds)
	}
	if len(cfg.SeededUsers) != 2 || len(cfg.CanaryRecords) != 1 {
		t.Fatalf("seeded data not parsed: %d users, %d canaries", len(cfg.SeededUsers), len(cfg.CanaryRecords))
	}
	if got := cfg.CanariesFor("userB"); len(got) != 1 || got[0].Marker != "VK-CANARY-B" {
		t.Errorf("CanariesFor(userB) = %+v", got)
	}
	if _, ok := cfg.User("userA"); !ok {
		t.Error("User(userA) not found")
	}
	if _, ok := cfg.User("nobody"); ok {
		t.Error("User returned a user that was never declared")
	}
}

// A typo in a safety-relevant key must not silently leave the default scope in
// place: the operator would believe they had declared a target.
func TestLoadRejectsUnknownKeys(t *testing.T) {
	path := writeConfig(t, "authorised_targets:\n  - http://localhost:3000\n")
	_, err := Load(path)
	if err == nil {
		t.Fatal("a misspelled key was accepted silently")
	}
	if !strings.Contains(err.Error(), "authorised_targets") {
		t.Errorf("the error should name the offending key: %v", err)
	}
}

// Both gates must be open before anything mutates state, and a config that
// opens only one is refused rather than quietly downgraded.
func TestMutatingChecksNeedBothGates(t *testing.T) {
	tests := []struct {
		name            string
		nonDestructive  bool
		disposable      bool
		wantAllowed     bool
		wantValidateErr bool
	}{
		{"default posture", true, false, false, false},
		{"disposable env alone changes nothing", true, true, false, false},
		{"destructive without disposable is refused", false, false, false, true},
		{"both gates open", false, true, true, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			nd := tc.nonDestructive
			cfg.Dynamic.NonDestructive = &nd
			cfg.Dynamic.DisposableEnv = tc.disposable

			if got := cfg.MutatingChecksAllowed(); got != tc.wantAllowed {
				t.Errorf("MutatingChecksAllowed() = %v, want %v", got, tc.wantAllowed)
			}

			err := cfg.Validate()
			if tc.wantValidateErr {
				if err == nil {
					t.Error("Validate accepted a half-open gate")
				} else if !strings.Contains(err.Error(), "disposable") {
					t.Errorf("the error should explain the disposable requirement: %v", err)
				}
			} else if err != nil {
				t.Errorf("Validate rejected a legitimate config: %v", err)
			}
		})
	}
}

// Tokens belong in the environment. A token written into the config file would
// land in the operator's git history, so it is an error, not a tolerated
// alternative.
func TestValidateRefusesTokensInTheConfigFile(t *testing.T) {
	cfg := Defaults()
	cfg.SeededUsers = []SeededUser{{ID: "userA", TokenEnv: "VK_USERA_TOKEN", TokenLiteral: "a-token-written-in-the-file"}}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("a token value in the config file was accepted")
	}
	if !strings.Contains(err.Error(), "environment variable") {
		t.Errorf("the error should point to the environment variable: %v", err)
	}
}

func TestValidateCatchesConfigMistakes(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*Config)
		wantInErr string
	}{
		{"no targets", func(c *Config) { c.AuthorizedTargets = nil }, "authorized_targets is empty"},
		{"unusable target", func(c *Config) { c.AuthorizedTargets = []string{"ftp://host"} }, "not supported"},
		{"bad threshold", func(c *Config) { c.SeverityThreshold = "spicy" }, "severity_threshold"},
		{"zero rps", func(c *Config) { c.Dynamic.MaxRPS = 0 }, "max_rps"},
		{"negative concurrency", func(c *Config) { c.Dynamic.Concurrency = -1 }, "concurrency"},
		{"empty repo path", func(c *Config) { c.RepoPath = "  " }, "repo_path"},
		{
			"seeded user without token_env",
			func(c *Config) { c.SeededUsers = []SeededUser{{ID: "userA"}} },
			"token_env is required",
		},
		{
			"duplicate seeded user",
			func(c *Config) {
				c.SeededUsers = []SeededUser{
					{ID: "userA", TokenEnv: "A"}, {ID: "userA", TokenEnv: "B"},
				}
			},
			"declared twice",
		},
		{
			"canary owned by an unknown user",
			func(c *Config) {
				c.SeededUsers = []SeededUser{{ID: "userA", TokenEnv: "A"}}
				c.CanaryRecords = []CanaryRecord{{Owner: "userZ", Resource: "order", ID: "1"}}
			},
			"not one of the seeded_users",
		},
		{
			"canary without an id",
			func(c *Config) { c.CanaryRecords = []CanaryRecord{{Owner: "userA", Resource: "order"}} },
			"id is empty",
		},
		{
			"invalid runtime port",
			func(c *Config) { c.Runtime.Enabled = true; c.Runtime.ProxyPort = 99999 },
			"not a valid port",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("Validate accepted a broken config: %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantInErr) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.wantInErr)
			}
		})
	}
}

func TestDefaultScopeIsLocalOnly(t *testing.T) {
	cfg := Defaults()
	g, err := cfg.Guard(true)
	if err != nil {
		t.Fatal(err)
	}
	if pub := g.PublicTargets(); len(pub) != 0 {
		t.Errorf("the default config declares off-machine targets: %v", pub)
	}
	// Even in scope, an undeclared port must be refused.
	if err := g.AuthorizeTarget("http://localhost:3000"); err == nil {
		t.Error("the default scope authorized a port it never declared")
	}
}

func TestSeededUserTokenComesFromEnv(t *testing.T) {
	u := SeededUser{ID: "userA", TokenEnv: "VK_TEST_TOKEN_A"}

	if _, err := u.Token(); err == nil {
		t.Error("expected an error when the environment variable is unset")
	} else if !strings.Contains(err.Error(), "VK_TEST_TOKEN_A") {
		t.Errorf("the error should name the variable: %v", err)
	}

	t.Setenv("VK_TEST_TOKEN_A", "  token-value  ")
	got, err := u.Token()
	if err != nil {
		t.Fatal(err)
	}
	if got != "token-value" {
		t.Errorf("Token() = %q, want the trimmed value", got)
	}
}

func TestResolvedRepoPathIsRelativeToTheConfigFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultFileName)
	if err := os.WriteFile(path, []byte("repo_path: ./app\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := cfg.ResolvedRepoPath()
	if err != nil {
		t.Fatal(err)
	}

	want := filepath.Join(dir, "app")
	if got != want {
		t.Errorf("ResolvedRepoPath() = %q, want %q", got, want)
	}
}

// An exclude pattern ending in a directory glob does not mean what it looks
// like, so the defaults are not allowed to be written that way.
//
// Semgrep does not act on `node_modules/**` as a prefix: the pattern matches
// nothing, and naming the directory in it turns off Semgrep's own default skip
// for it. The measured effect on a fixture with 81 packages installed was 17
// extra findings inside node_modules that writing no pattern at all would have
// avoided. normalizeExclude in internal/scanners/semgrep.go rewrites an
// operator's pattern for the same reason; this keeps the shipped defaults from
// needing the rewrite in the first place.
func TestDefaultExcludesAreNotWrittenAsDirectoryGlobs(t *testing.T) {
	patterns := Defaults().Exclude
	if len(patterns) == 0 {
		t.Fatal("there are no default excludes; a scan would read node_modules and vendor")
	}

	for _, p := range patterns {
		if strings.HasSuffix(p, "/**") || strings.HasSuffix(p, "/*") {
			t.Errorf("default exclude %q ends in a directory glob; "+
				"write the bare name, which Semgrep matches at any depth", p)
		}
	}
}
