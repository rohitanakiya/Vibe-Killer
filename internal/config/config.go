// Package config loads and validates vibekiller.config.yaml, the file the
// operator keeps in their own repo.
//
// The config is where the operator declares what Vibe Killer is allowed to
// touch, so loading it is a safety-relevant operation and validation is
// strict: an ambiguous or self-contradictory config is an error, never a
// silently-narrowed or silently-widened scope.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
	"github.com/rohitanakiya/Vibe-Killer/internal/scope"
)

// DefaultFileName is the config file Vibe Killer looks for in the repo root.
const DefaultFileName = "vibekiller.config.yaml"

// Config is the whole operator-owned configuration.
type Config struct {
	// RepoPath is the project to analyze, relative to the config file.
	RepoPath string `yaml:"repo_path"`

	// AuthorizedTargets is the complete list of hosts network checks may
	// touch. Anything absent from this list is refused.
	AuthorizedTargets []string `yaml:"authorized_targets"`

	Runtime  RuntimeConfig `yaml:"runtime"`
	Dynamic  DynamicConfig `yaml:"dynamic"`
	Scanners Scanners      `yaml:"scanners"`

	SeededUsers   []SeededUser   `yaml:"seeded_users"`
	CanaryRecords []CanaryRecord `yaml:"canary_records"`

	// SeverityThreshold is the CI gate: scan exits non-zero when a finding at
	// or above this severity is open.
	SeverityThreshold finding.Severity `yaml:"severity_threshold"`

	// Exclude are repo-relative glob patterns skipped by static analysis.
	Exclude []string `yaml:"exclude"`

	// sourcePath is where this config was read from, for error messages.
	sourcePath string `yaml:"-"`
}

// RuntimeConfig controls the observe-only runtime adapter.
type RuntimeConfig struct {
	Enabled bool `yaml:"enabled"`

	// Adapter names the runtime observer to attach, e.g. "proxy". Empty means
	// let the stack adapter choose.
	Adapter string `yaml:"adapter"`

	// ProxyPort is the local port an observing proxy listens on.
	ProxyPort int `yaml:"proxy_port"`
}

// DynamicConfig controls the endpoint-check engine.
type DynamicConfig struct {
	// NonDestructive is the default posture. Setting it false is what the
	// operator must do, explicitly, before any state-mutating check will run,
	// and it is not sufficient on its own: see DisposableEnv.
	NonDestructive *bool `yaml:"non_destructive"`

	// DisposableEnv asserts that the target instance holds throwaway data.
	// Mutating checks require both this and NonDestructive=false.
	DisposableEnv bool `yaml:"disposable_env"`

	// MaxRPS is the per-host request rate ceiling.
	MaxRPS float64 `yaml:"max_rps"`

	// Concurrency is the per-host cap on in-flight requests.
	Concurrency int `yaml:"concurrency"`

	// TimeoutSeconds bounds each individual request.
	TimeoutSeconds int `yaml:"timeout_seconds"`

	// BasePath is prefixed to probe paths for apps mounted under a sub-path.
	BasePath string `yaml:"base_path"`
}

// Scanners configures the external tools Vibe Killer orchestrates. Each may be
// disabled or pointed at an explicit binary.
type Scanners struct {
	Semgrep  ScannerConfig `yaml:"semgrep"`
	OSV      ScannerConfig `yaml:"osv_scanner"`
	Gitleaks ScannerConfig `yaml:"gitleaks"`
}

// ScannerConfig configures one wrapped scanner.
type ScannerConfig struct {
	// Disabled skips this scanner entirely.
	Disabled bool `yaml:"disabled"`

	// Path overrides binary lookup on PATH.
	Path string `yaml:"path"`

	// ExtraArgs are appended to the scanner invocation.
	ExtraArgs []string `yaml:"extra_args"`

	// TimeoutSeconds bounds the scanner run. Zero means use the default.
	TimeoutSeconds int `yaml:"timeout_seconds"`

	// RulePacks are additional rule sources, for Semgrep only.
	//
	// This is empty by default and deliberately so. Vibe Killer runs Semgrep
	// against its own embedded pack, which needs no network. A registry pack
	// such as "p/security-audit" is downloaded at scan time, which is an
	// outbound connection the operator did not ask for, so it is opt-in and
	// named here rather than assumed.
	RulePacks []string `yaml:"rule_packs"`
}

// SeededUser is a throwaway account the operator created in the target
// instance for access-control checks.
type SeededUser struct {
	// ID is the label used in reports, e.g. userA.
	ID string `yaml:"id"`

	// TokenEnv names the environment variable holding this user's token.
	TokenEnv string `yaml:"token_env"`

	// Role is optional and lets privilege-escalation checks tell which
	// direction crossing a boundary would be an escalation.
	Role string `yaml:"role"`

	// Header and Scheme shape how the token is presented. They default to
	// "Authorization" and "Bearer", which covers most generated apps; an app
	// that reads a custom header or a cookie sets them here.
	//
	// A scheme of "cookie" sends the token as a Cookie header value, so an
	// app using session cookies can be tested without a different code path.
	Header string `yaml:"header"`
	Scheme string `yaml:"scheme"`

	// TokenLiteral captures a `token:` key written directly into the config
	// file. It must never be set. It exists only so that an operator who
	// inlines a token gets a clear error instead of having the key silently
	// ignored. The token itself is read from the environment by Token().
	TokenLiteral string `yaml:"token"`
}

// CanaryRecord is a seeded throwaway record used as the proof target. Reading
// one of these across a boundary is how an access-control finding is
// confirmed, so that no real record is ever read.
type CanaryRecord struct {
	// Owner is the SeededUser.ID that should be the only one able to read it.
	Owner string `yaml:"owner"`

	// Resource is the route family, e.g. order.
	Resource string `yaml:"resource"`

	// ID is the record's identifier in the target app.
	ID string `yaml:"id"`

	// Marker is a distinctive string known to be inside the record. When set,
	// a check can confirm the record actually crossed the boundary rather than
	// relying on the status code.
	Marker string `yaml:"marker"`
}

// Defaults returns a Config with every default applied.
func Defaults() Config {
	nonDestructive := true
	return Config{
		RepoPath:          ".",
		AuthorizedTargets: scope.DefaultTargets(),
		Dynamic: DynamicConfig{
			NonDestructive: &nonDestructive,
			DisposableEnv:  false,
			MaxRPS:         10,
			Concurrency:    4,
			TimeoutSeconds: 15,
		},
		Runtime:           RuntimeConfig{Enabled: false, ProxyPort: 18080},
		SeverityThreshold: finding.SeverityHigh,
		Exclude: []string{
			"node_modules/**", "vendor/**", ".git/**", "dist/**", "build/**",
			".venv/**", "venv/**", "__pycache__/**", "target/**",
		},
	}
}

// Load reads a config file. A missing file is not an error: Vibe Killer runs on
// defaults so that a first static scan needs no setup at all.
func Load(path string) (*Config, error) {
	cfg := Defaults()
	cfg.sourcePath = path

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			cfg.sourcePath = ""
			return &cfg, nil
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	// KnownFields makes a typo in a safety-relevant key an error rather than a
	// silently-ignored line. An operator who writes "authorised_targets" must
	// not get the default scope without being told.
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var fromFile Config
	if err := dec.Decode(&fromFile); err != nil {
		// An empty or comment-only file is a legitimate "use the defaults".
		if !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
		return &cfg, nil
	}

	merge(&cfg, &fromFile)
	cfg.sourcePath = path
	return &cfg, nil
}

// merge overlays file values onto defaults, leaving defaults where the file
// said nothing.
func merge(dst, src *Config) {
	if src.RepoPath != "" {
		dst.RepoPath = src.RepoPath
	}
	if len(src.AuthorizedTargets) > 0 {
		dst.AuthorizedTargets = src.AuthorizedTargets
	}
	if len(src.SeededUsers) > 0 {
		dst.SeededUsers = src.SeededUsers
	}
	if len(src.CanaryRecords) > 0 {
		dst.CanaryRecords = src.CanaryRecords
	}
	if len(src.Exclude) > 0 {
		dst.Exclude = append(dst.Exclude, src.Exclude...)
	}
	if src.SeverityThreshold != "" {
		dst.SeverityThreshold = src.SeverityThreshold
	}

	if src.Runtime.Enabled {
		dst.Runtime.Enabled = true
	}
	if src.Runtime.Adapter != "" {
		dst.Runtime.Adapter = src.Runtime.Adapter
	}
	if src.Runtime.ProxyPort != 0 {
		dst.Runtime.ProxyPort = src.Runtime.ProxyPort
	}

	if src.Dynamic.NonDestructive != nil {
		dst.Dynamic.NonDestructive = src.Dynamic.NonDestructive
	}
	if src.Dynamic.DisposableEnv {
		dst.Dynamic.DisposableEnv = true
	}
	if src.Dynamic.MaxRPS != 0 {
		dst.Dynamic.MaxRPS = src.Dynamic.MaxRPS
	}
	if src.Dynamic.Concurrency != 0 {
		dst.Dynamic.Concurrency = src.Dynamic.Concurrency
	}
	if src.Dynamic.TimeoutSeconds != 0 {
		dst.Dynamic.TimeoutSeconds = src.Dynamic.TimeoutSeconds
	}
	if src.Dynamic.BasePath != "" {
		dst.Dynamic.BasePath = src.Dynamic.BasePath
	}

	dst.Scanners = src.Scanners
}

// SourcePath reports which file this config came from, or "" for defaults.
func (c *Config) SourcePath() string { return c.sourcePath }

// IsNonDestructive reports the current posture, defaulting to true.
func (c *Config) IsNonDestructive() bool {
	if c.Dynamic.NonDestructive == nil {
		return true
	}
	return *c.Dynamic.NonDestructive
}

// MutatingChecksAllowed reports whether a state-changing check may run.
//
// Both gates must be open: the operator must have turned off the
// non-destructive default and separately asserted the environment is
// disposable. Two independent statements are required because the first is
// easy to set while experimenting and the second is a claim about the data.
func (c *Config) MutatingChecksAllowed() bool {
	return !c.IsNonDestructive() && c.Dynamic.DisposableEnv
}

// Validate checks the config for errors and contradictions.
func (c *Config) Validate() error {
	var errs []error
	bad := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if strings.TrimSpace(c.RepoPath) == "" {
		bad("repo_path is empty")
	}

	if _, err := finding.ParseSeverity(string(c.SeverityThreshold)); err != nil {
		bad("severity_threshold: %w", err)
	}

	if len(c.AuthorizedTargets) == 0 {
		bad("authorized_targets is empty: declare the instance to test, or run with --static-only")
	}
	if _, err := scope.New(c.AuthorizedTargets); err != nil {
		bad("authorized_targets: %w", err)
	}

	if c.Dynamic.MaxRPS <= 0 {
		bad("dynamic.max_rps must be greater than zero (got %v)", c.Dynamic.MaxRPS)
	}
	if c.Dynamic.Concurrency <= 0 {
		bad("dynamic.concurrency must be greater than zero (got %d)", c.Dynamic.Concurrency)
	}
	if c.Dynamic.TimeoutSeconds <= 0 {
		bad("dynamic.timeout_seconds must be greater than zero (got %d)", c.Dynamic.TimeoutSeconds)
	}

	// A config that turns off the non-destructive default without asserting
	// the environment is disposable is a mistake, not a preference. Refuse it
	// rather than quietly skipping the mutating checks it asked for.
	if !c.IsNonDestructive() && !c.Dynamic.DisposableEnv {
		bad("dynamic.non_destructive is false but dynamic.disposable_env is also false: " +
			"state-changing checks only run against an instance you have explicitly marked disposable")
	}

	seen := map[string]bool{}
	for i, u := range c.SeededUsers {
		if u.ID == "" {
			bad("seeded_users[%d]: id is empty", i)
		}
		if seen[u.ID] {
			bad("seeded_users[%d]: id %q is declared twice", i, u.ID)
		}
		seen[u.ID] = true

		// The contract is that tokens live in the environment. A token written
		// into the config would end up in the operator's git history.
		if strings.TrimSpace(u.TokenLiteral) != "" {
			bad("seeded_users[%d] (%s): a token value is set in the config file. "+
				"Move it to an environment variable and reference it with token_env, "+
				"so it is not committed to your repo", i, u.ID)
		}
		if u.TokenEnv == "" {
			bad("seeded_users[%d] (%s): token_env is required", i, u.ID)
		} else if strings.ContainsAny(u.TokenEnv, " \t=") {
			bad("seeded_users[%d] (%s): token_env %q is not a valid environment variable name", i, u.ID, u.TokenEnv)
		}
	}

	for i, r := range c.CanaryRecords {
		if r.Owner == "" {
			bad("canary_records[%d]: owner is empty", i)
		} else if len(c.SeededUsers) > 0 && !seen[r.Owner] {
			bad("canary_records[%d]: owner %q is not one of the seeded_users", i, r.Owner)
		}
		if r.Resource == "" {
			bad("canary_records[%d]: resource is empty", i)
		}
		if r.ID == "" {
			bad("canary_records[%d]: id is empty", i)
		}
	}

	if c.Runtime.Enabled && (c.Runtime.ProxyPort < 1 || c.Runtime.ProxyPort > 65535) {
		bad("runtime.proxy_port %d is not a valid port", c.Runtime.ProxyPort)
	}

	return errors.Join(errs...)
}

// ErrTokenMissing reports a seeded user whose token environment variable is
// not set.
type ErrTokenMissing struct {
	UserID string
	EnvVar string
}

func (e *ErrTokenMissing) Error() string {
	return fmt.Sprintf("seeded user %s has no token: environment variable %s is not set", e.UserID, e.EnvVar)
}

// Token reads a seeded user's token from the environment.
func (u SeededUser) Token() (string, error) {
	v := strings.TrimSpace(os.Getenv(u.TokenEnv))
	if v == "" {
		return "", &ErrTokenMissing{UserID: u.ID, EnvVar: u.TokenEnv}
	}
	return v, nil
}

// AuthHeader returns the header name and value that present this user's
// token, reading the token from the environment.
//
// The token value never appears in a finding: checks record u.ID as the auth
// label and the header is redacted before it reaches the run log.
func (u SeededUser) AuthHeader() (name, value string, err error) {
	token, err := u.Token()
	if err != nil {
		return "", "", err
	}

	name = strings.TrimSpace(u.Header)
	scheme := strings.TrimSpace(u.Scheme)

	switch {
	case strings.EqualFold(scheme, "cookie"):
		if name == "" {
			name = "Cookie"
		}
		return name, token, nil
	case name == "":
		name = "Authorization"
	}

	if scheme == "" {
		scheme = "Bearer"
	}
	if strings.EqualFold(scheme, "none") || strings.EqualFold(scheme, "raw") {
		return name, token, nil
	}
	return name, scheme + " " + token, nil
}

// User looks up a seeded user by id.
func (c *Config) User(id string) (SeededUser, bool) {
	for _, u := range c.SeededUsers {
		if u.ID == id {
			return u, true
		}
	}
	return SeededUser{}, false
}

// CanariesFor returns the seeded canary records owned by a user.
func (c *Config) CanariesFor(owner string) []CanaryRecord {
	var out []CanaryRecord
	for _, r := range c.CanaryRecords {
		if r.Owner == owner {
			out = append(out, r)
		}
	}
	return out
}

// ResolvedRepoPath returns the absolute repo path, resolved relative to the
// directory holding the config file.
func (c *Config) ResolvedRepoPath() (string, error) {
	if filepath.IsAbs(c.RepoPath) {
		return filepath.Clean(c.RepoPath), nil
	}
	base := "."
	if c.sourcePath != "" {
		base = filepath.Dir(c.sourcePath)
	}
	abs, err := filepath.Abs(filepath.Join(base, c.RepoPath))
	if err != nil {
		return "", fmt.Errorf("resolving repo_path %q: %w", c.RepoPath, err)
	}
	return abs, nil
}

// Guard builds the scope guard for this config.
func (c *Config) Guard(acknowledged bool) (*scope.Guard, error) {
	return scope.New(c.AuthorizedTargets, scope.WithAcknowledgement(acknowledged))
}
