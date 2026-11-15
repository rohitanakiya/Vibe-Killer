// Package staticchecks registers the repo-only engines: static analysis,
// dependency auditing and secret scanning.
//
// Each wraps an external scanner rather than reimplementing it. They are
// modelled as checks so that they get the same treatment as everything else:
// central eligibility, contained panics, contract validation of what they
// emit, and a reported reason when a scanner is simply not installed.
//
// None of these touch the network, except that Semgrep will fetch a registry
// rule pack if the operator opted into one.
package staticchecks

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rohitanakiya/Vibe-Killer/internal/check"
	"github.com/rohitanakiya/Vibe-Killer/internal/config"
	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
	"github.com/rohitanakiya/Vibe-Killer/internal/scanners"
	"github.com/rohitanakiya/Vibe-Killer/internal/tool"
)

func init() {
	check.Register(&SemgrepEngine{})
	check.Register(&OSVEngine{})
	check.Register(&GitleaksEngine{})
}

// scanContext builds the shared context the wrappers need.
func scanContext(env *check.Env) scanners.ScanContext {
	return scanners.ScanContext{
		RepoRoot: env.RepoRoot,
		RepoRev:  env.RepoRev,
		Exclude:  env.Config.Exclude,
	}
}

// runner builds a tool runner from the operator's scanner config.
func runner(spec tool.Spec, cfg config.ScannerConfig) *tool.Runner {
	if cfg.TimeoutSeconds > 0 {
		spec.Timeout = time.Duration(cfg.TimeoutSeconds) * time.Second
	}
	return tool.New(spec, cfg.Path, cfg.ExtraArgs)
}

// ErrScannerDisabled is returned when the operator turned a scanner off. It is
// reported as a skip rather than a failure.
var ErrScannerDisabled = errors.New("disabled in config")

// --- Semgrep ---------------------------------------------------------------

// SemgrepEngine runs Semgrep over the repository with Vibe Killer's embedded
// rule pack.
type SemgrepEngine struct{}

// Meta describes the engine.
func (e *SemgrepEngine) Meta() check.Meta {
	return check.Meta{
		RuleID:   "engine.semgrep",
		Title:    "Static analysis (Semgrep + Vibe Killer rule pack)",
		Layer:    check.LayerStatic,
		Category: finding.CategoryInsecureDesign,
	}
}

// Detect runs Semgrep and returns normalized findings.
func (e *SemgrepEngine) Detect(ctx context.Context, env *check.Env) ([]finding.Finding, error) {
	cfg := env.Config.Scanners.Semgrep
	if cfg.Disabled {
		return nil, nil
	}

	r := runner(tool.SemgrepSpec, cfg)
	if !r.Available() {
		_, err := r.Resolve()
		return nil, err
	}

	// The embedded pack first, then anything the operator opted into.
	packs := []string{}
	if env.RulesDir != "" {
		packs = append(packs, env.RulesDir)
	}
	packs = append(packs, cfg.RulePacks...)
	if len(packs) == 0 {
		return nil, fmt.Errorf("no rule pack is available for semgrep")
	}

	s := scanners.NewSemgrep(r, packs)
	fs, raw, err := s.Run(ctx, scanContext(env))
	if len(raw) > 0 && env.Run != nil {
		if _, werr := env.Run.WriteRaw("semgrep.json", raw); werr != nil {
			env.Run.Errorf("could not store semgrep raw output: %v", werr)
		}
	}
	if err != nil {
		return nil, err
	}
	return fs, nil
}

// --- osv-scanner -----------------------------------------------------------

// OSVEngine runs osv-scanner over the repository's dependency manifests.
type OSVEngine struct{}

// Meta describes the engine.
func (e *OSVEngine) Meta() check.Meta {
	return check.Meta{
		RuleID:   "engine.osv-scanner",
		Title:    "Dependency advisories (osv-scanner)",
		Layer:    check.LayerDeps,
		Category: finding.CategoryVulnerableDep,
	}
}

// Detect runs osv-scanner and returns normalized findings.
func (e *OSVEngine) Detect(ctx context.Context, env *check.Env) ([]finding.Finding, error) {
	cfg := env.Config.Scanners.OSV
	if cfg.Disabled {
		return nil, nil
	}

	r := runner(tool.OSVScannerSpec, cfg)
	if !r.Available() {
		_, err := r.Resolve()
		return nil, err
	}

	o := scanners.NewOSV(r)
	fs, raw, err := o.Run(ctx, scanContext(env))
	if len(raw) > 0 && env.Run != nil {
		if _, werr := env.Run.WriteRaw("osv-scanner.json", raw); werr != nil {
			env.Run.Errorf("could not store osv-scanner raw output: %v", werr)
		}
	}
	if err != nil {
		return nil, err
	}
	return fs, nil
}

// --- gitleaks --------------------------------------------------------------

// GitleaksEngine scans the working tree and git history for credentials.
type GitleaksEngine struct{}

// Meta describes the engine.
func (e *GitleaksEngine) Meta() check.Meta {
	return check.Meta{
		RuleID:   "engine.gitleaks",
		Title:    "Committed credentials (gitleaks, working tree and history)",
		Layer:    check.LayerSecrets,
		Category: finding.CategorySecretsExposure,
	}
}

// Detect runs gitleaks and returns normalized findings.
//
// The raw report is written into the run's raw directory, and gitleaks is
// invoked with --redact so that neither the raw report nor the findings carry
// a usable credential.
func (e *GitleaksEngine) Detect(ctx context.Context, env *check.Env) ([]finding.Finding, error) {
	cfg := env.Config.Scanners.Gitleaks
	if cfg.Disabled {
		return nil, nil
	}

	r := runner(tool.GitleaksSpec, cfg)
	if !r.Available() {
		_, err := r.Resolve()
		return nil, err
	}

	reportDir := env.RepoRoot
	if env.Run != nil {
		reportDir = env.Run.Path("raw")
	}

	g := scanners.NewGitleaks(r)
	fs, _, err := g.Run(ctx, scanContext(env), env.HasGit, reportDir)
	if err != nil {
		return nil, err
	}
	return fs, nil
}
