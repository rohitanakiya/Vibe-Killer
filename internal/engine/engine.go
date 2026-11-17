// Package engine assembles a scan: it loads config, establishes scope, sets up
// the run directory, selects and runs checks, merges the results, and writes
// the outputs.
//
// It exists so that the CLI stays a thin layer over a single well-defined
// operation, and so that the order of the safety steps is fixed in one place:
// scope is established before any client is built, and the client is the only
// way to reach the network.
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/rohitanakiya/Vibe-Killer/internal/check"
	"github.com/rohitanakiya/Vibe-Killer/internal/config"
	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
	"github.com/rohitanakiya/Vibe-Killer/internal/history"
	"github.com/rohitanakiya/Vibe-Killer/internal/httpx"
	"github.com/rohitanakiya/Vibe-Killer/internal/merge"
	"github.com/rohitanakiya/Vibe-Killer/internal/orchestrator"
	"github.com/rohitanakiya/Vibe-Killer/internal/report"
	"github.com/rohitanakiya/Vibe-Killer/internal/run"
	"github.com/rohitanakiya/Vibe-Killer/internal/runtime"
	"github.com/rohitanakiya/Vibe-Killer/internal/sarif"
	"github.com/rohitanakiya/Vibe-Killer/internal/scope"
	"github.com/rohitanakiya/Vibe-Killer/internal/surface"
	"github.com/rohitanakiya/Vibe-Killer/internal/tool"
	"github.com/rohitanakiya/Vibe-Killer/internal/vcs"
	"github.com/rohitanakiya/Vibe-Killer/rules"

	// Registering the check packages for their side effects is what populates
	// the registry; the engine itself knows nothing about individual checks.
	_ "github.com/rohitanakiya/Vibe-Killer/internal/checks/endpointchecks"
	_ "github.com/rohitanakiya/Vibe-Killer/internal/checks/exposurechecks"
	_ "github.com/rohitanakiya/Vibe-Killer/internal/checks/runtimechecks"
	_ "github.com/rohitanakiya/Vibe-Killer/internal/checks/staticchecks"
)

// Version is the build version, set by the CLI.
var Version = "dev"

// InformationURI is the project home, stamped into SARIF so an alert in
// someone else's repository can be traced to the tool that raised it.
var InformationURI = "https://github.com/rohitanakiya/Vibe-Killer"

// Mode names what a scan was asked to do.
type Mode string

const (
	// ModeStaticOnly analyzes the repository and nothing else. No network.
	ModeStaticOnly Mode = "static-only"

	// ModeFull adds endpoint checks against a running instance.
	ModeFull Mode = "full"

	// ModeWithRuntime adds the observe-only runtime adapter.
	ModeWithRuntime Mode = "with-runtime"
)

// ScanOptions is what the CLI passes in.
type ScanOptions struct {
	// ConfigPath is the config file. Empty means look for the default name in
	// the repo root.
	ConfigPath string

	// RepoPath overrides config's repo_path.
	RepoPath string

	// Target is the running instance to exercise. Empty means static-only.
	Target string

	// Acknowledged records --i-own-this-target.
	Acknowledged bool

	StaticOnly  bool
	WithRuntime bool

	// RunsDir is where run directories are created.
	RunsDir string

	// Workers bounds concurrent checks.
	Workers int

	// Only restricts the run to these check rule ids.
	Only []string

	// Progress receives orchestrator events.
	Progress func(orchestrator.Event)

	// Notice reports setup messages worth showing the operator.
	Notice func(string)
}

// Result is a completed scan.
type Result struct {
	RunID    string
	RunDir   string
	Meta     run.Meta
	Findings []finding.Finding
	Surface  *surface.Surface

	Skipped []check.SkipReason
	Failed  []orchestrator.CheckError

	MergeSummary merge.Summary

	// GateTripped is true when a finding at or above the configured severity
	// threshold is open, which is what makes the CLI exit non-zero.
	GateTripped bool

	// GateSeverity is the threshold that was applied.
	GateSeverity finding.Severity

	// Regressions is how many findings a previous run had recorded as fixed
	// and this run found open again.
	Regressions int

	ReportMarkdownPath string
	ReportHTMLPath     string

	// ReportSARIFPath is the machine-readable report, for GitHub code
	// scanning or any other SARIF consumer.
	ReportSARIFPath string
}

// ErrTargetNotAcknowledged is returned when a target was given without the
// ownership acknowledgement.
type ErrTargetNotAcknowledged struct{ Target string }

func (e *ErrTargetNotAcknowledged) Error() string {
	return fmt.Sprintf("refusing to send any request to %s without --i-own-this-target.\n"+
		"Vibe Killer exercises a running instance, which is an active test. Pass that flag to\n"+
		"confirm this instance is yours, or run with --static-only to analyze the repository alone.", e.Target)
}

// Scan performs one full scan.
func Scan(ctx context.Context, opts ScanOptions) (*Result, error) {
	notice := opts.Notice
	if notice == nil {
		notice = func(string) {}
	}

	cfg, cfgPath, err := loadConfig(opts)
	if err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("the configuration is not usable:\n%w", err)
	}

	repoRoot, err := cfg.ResolvedRepoPath()
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("repo_path %s cannot be read: %w", repoRoot, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("repo_path %s is not a directory", repoRoot)
	}

	if cfgPath == "" {
		notice(fmt.Sprintf("No %s found; running with defaults. "+
			"Endpoint checks need seeded users and canary records, so this run is static only unless you add them.",
			config.DefaultFileName))
	}

	// Establish scope before anything that could make a request exists.
	target := opts.Target
	mode := ModeFull
	switch {
	case opts.StaticOnly:
		mode = ModeStaticOnly
		if target != "" {
			notice("--static-only was given, so --target is ignored and no requests will be sent.")
			target = ""
		}
	case target == "":
		mode = ModeStaticOnly
	case opts.WithRuntime:
		mode = ModeWithRuntime
	}

	var guard *scope.Guard
	if target != "" {
		guard, err = cfg.Guard(opts.Acknowledged)
		if err != nil {
			return nil, fmt.Errorf("building the authorized scope: %w", err)
		}
		if !opts.Acknowledged {
			return nil, &ErrTargetNotAcknowledged{Target: target}
		}
		if err := guard.AuthorizeTarget(target); err != nil {
			return nil, fmt.Errorf("the requested target is not in scope: %w", err)
		}
		if pub := guard.PublicTargets(); len(pub) > 0 {
			notice(fmt.Sprintf("Note: authorized_targets includes non-local host(s): %v. "+
				"Only test hosts you own.", pub))
		}
	}

	git := vcs.Read(ctx, repoRoot)
	if !git.IsRepo {
		notice("This is not a git checkout, so secret scanning covers the working tree only, not history.")
	} else if git.Dirty {
		notice(fmt.Sprintf("The working tree has uncommitted changes, so findings are not reproducible from revision %s alone.",
			shortRev(git.Rev)))
	}

	runsDir := opts.RunsDir
	if runsDir == "" {
		runsDir = run.DirName
	}

	meta := run.Meta{
		StartedAt: time.Now().UTC().Format(time.RFC3339),
		Tool:      "vibekiller",
		Version:   Version,
		RepoPath:  repoRoot,
		RepoRev:   git.Rev,
		Mode:      string(mode),
		Target:    target,

		NonDestructive: cfg.IsNonDestructive(),
		DisposableEnv:  cfg.Dynamic.DisposableEnv,
		RuntimeEnabled: mode == ModeWithRuntime,

		TargetOwnershipAcknowledged: target != "" && opts.Acknowledged,
	}
	if guard != nil {
		meta.AuthorizedTargets = guard.Targets()
	}
	if meta.TargetOwnershipAcknowledged {
		meta.AcknowledgedAt = time.Now().UTC().Format(time.RFC3339)
	}

	r, err := run.Create(runsDir, meta)
	if err != nil {
		return nil, err
	}
	// Close runs every registered cleanup. It is deferred immediately after
	// Create so that no early return can leave a run half-finished.
	defer func() {
		if cerr := r.Close(); cerr != nil {
			notice(fmt.Sprintf("warning: finalizing the run directory failed: %v", cerr))
		}
	}()

	// The embedded rule pack is written into the run directory, which both
	// feeds Semgrep and records exactly which rules produced this run.
	rulesDir, err := rules.Materialize(r.Path())
	if err != nil {
		r.Errorf("could not write the embedded rule pack: %v", err)
		rulesDir = ""
	}

	// The path has to be absolute, and that is not a tidiness preference.
	// A run directory is created relative to the working directory
	// ("runs/<id>"), while the scanners are executed with their working
	// directory set to the repository root. A relative --config therefore
	// resolved against the wrong directory whenever the repository was not
	// also the working directory, semgrep exited 7 (MISSING_CONFIG) with
	// nothing on stderr, and the entire first-party static engine silently did
	// not run. `scan --repo .` hid it, because there the two directories
	// coincide.
	if rulesDir != "" {
		if abs, aerr := filepath.Abs(rulesDir); aerr == nil {
			rulesDir = abs
		} else {
			r.Errorf("could not resolve the rule pack path, so semgrep may not find it: %v", aerr)
		}
	}

	env := &check.Env{
		Config:   cfg,
		Guard:    guard,
		Run:      r,
		Target:   target,
		RepoRoot: repoRoot,
		RepoRev:  git.Rev,
		RulesDir: rulesDir,
		HasGit:   git.IsRepo,
	}

	if target != "" {
		client, cerr := httpx.New(httpx.Options{
			Guard:       guard,
			MaxRPS:      cfg.Dynamic.MaxRPS,
			Concurrency: cfg.Dynamic.Concurrency,
			Timeout:     time.Duration(cfg.Dynamic.TimeoutSeconds) * time.Second,
			UserAgent:   "vibekiller/" + Version + " (security scan of your own instance)",
			Recorder:    r,
		})
		if cerr != nil {
			return nil, cerr
		}
		env.HTTP = client
		r.Defer("close http client", client.Close)
	}

	// Map the application surface. A failure here degrades the run to the
	// checks that do not need a route model, rather than ending it.
	if s, serr := MapSurface(ctx, env); serr != nil {
		r.Errorf("surface mapping failed: %v", serr)
		notice(fmt.Sprintf("Could not map the application surface: %v", serr))
	} else {
		env.Surface = s
		if werr := r.WriteSurface(s); werr != nil {
			r.Errorf("could not write app_surface.json: %v", werr)
		}
	}

	// The runtime observer is started after the surface is mapped, because the
	// agent to offer depends on the detected stack.
	if mode == ModeWithRuntime {
		if err := attachRuntime(ctx, env, cfg, notice); err != nil {
			r.Errorf("runtime observation could not be set up: %v", err)
			notice(fmt.Sprintf("Runtime observation is unavailable, so the runtime checks will be "+
				"skipped: %v", err))
		}
	}

	selected := selectChecks(mode, opts.Only)
	if len(selected) == 0 {
		return nil, fmt.Errorf("no checks matched the selection %v", opts.Only)
	}

	// Everything the selection left out is recorded as a skip before the
	// orchestrator runs, and merged with the skips it produces. See
	// deselectedSkips for why both halves are needed.
	deselected := deselectedSkips(mode, opts.Only, selected)

	recordScannerVersions(ctx, cfg, r)

	orch := orchestrator.New(orchestrator.Options{
		Workers:  opts.Workers,
		Progress: opts.Progress,
	})

	orchReport, runErr := orch.Run(ctx, selected, env)
	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		return nil, runErr
	}

	linker, lerr := rules.DynamicRules()
	if lerr != nil {
		r.Errorf("could not read the static-to-dynamic rule links: %v", lerr)
	}

	merged, summary := merge.ProcessWithSummary(orchReport.Findings, linker)
	r.Log("merge.done", map[string]any{
		"before": summary.Before, "after": summary.After, "merged": summary.Merged,
	})

	// History fills in first_seen_run and last_seen_run, and promotes a
	// finding that a previous run recorded as fixed to regressed. A failure
	// here costs those fields, not the scan, so it is reported and the run
	// continues: the findings themselves are already established.
	var regressions int
	if store, herr := history.Open(runsDir); herr != nil {
		r.Errorf("could not open the run history: %v", herr)
		notice(fmt.Sprintf("Run history is unavailable, so first_seen_run and regression detection "+
			"are not filled in for this run: %v", herr))
	} else {
		defer func() { _ = store.Close() }()

		if enriched, eerr := store.Enrich(r.ID(), merged); eerr != nil {
			r.Errorf("could not read the run history: %v", eerr)
		} else {
			merged = enriched
		}
		for _, f := range merged {
			if f.Status == finding.StatusRegressed {
				regressions++
			}
		}

		counts := finding.Summarize(merged)
		if rerr := store.Record(history.RunRecord{
			RunID:       r.ID(),
			StartedAt:   meta.StartedAt,
			RepoPath:    repoRoot,
			RepoRev:     git.Rev,
			Target:      target,
			Mode:        string(mode),
			ToolVersion: Version,
			Total:       counts.Total,
			Confirmed:   counts.Confirmed,
		}, merged); rerr != nil {
			r.Errorf("could not record this run in the history: %v", rerr)
		}
	}

	// One list from here on: the checks gated out by CanRun and the checks
	// the selection never scheduled, so findings.json, the Markdown report,
	// the terminal summary and Result.Skipped all describe the same run.
	allSkips := mergeSkips(orchReport.Skipped, deselected)

	if err := r.WriteFindings(merged, finding.Coverage{
		Skipped: skippedChecks(allSkips),
		Failed:  failedChecks(orchReport.Failed),
	}); err != nil {
		return nil, err
	}

	if env.HTTP != nil {
		r.SetMeta(func(m *run.Meta) { m.RequestCount = env.HTTP.Count() })
	}

	result := &Result{
		RunID:        r.ID(),
		RunDir:       r.Dir(),
		Findings:     merged,
		Surface:      env.Surface,
		Skipped:      allSkips,
		Failed:       orchReport.Failed,
		MergeSummary: summary,
		GateSeverity: cfg.SeverityThreshold,
		Regressions:  regressions,
	}

	// The gate considers open findings only: one that was reviewed and
	// accepted should not fail a build forever.
	for _, f := range merged {
		if f.Status != finding.StatusOpen && f.Status != finding.StatusRegressed {
			continue
		}
		if f.Severity.AtLeast(cfg.SeverityThreshold) {
			result.GateTripped = true
			break
		}
	}

	// Render the reports while the run is still open, so their paths are part
	// of the run directory.
	result.Meta = r.Meta()
	in := report.Input{
		Meta:     result.Meta,
		Findings: merged,
		Skipped:  check.GroupSkipLines(allSkips),
		Failed:   failStrings(orchReport.Failed),
	}
	if env.Surface != nil {
		in.RouteCount = len(env.Surface.Routes)
	}

	// The SARIF report is derived from findings.json after it has been
	// written, rather than from the in-memory findings. That makes it
	// provably a function of the published contract: if the two ever
	// disagreed, the one a consumer reads would be the one in the file.
	if doc, derr := run.LoadFindings(r.Dir()); derr != nil {
		r.Errorf("could not re-read findings.json to build SARIF: %v", derr)
	} else {
		log := sarif.Convert(doc, sarif.Options{
			ToolVersion:    Version,
			InformationURI: InformationURI,
			Surface:        env.Surface,
		})
		if b, merr := json.MarshalIndent(log, "", "  "); merr != nil {
			r.Errorf("could not encode SARIF: %v", merr)
		} else {
			sarifPath := r.Path("report.sarif")
			if werr := os.WriteFile(sarifPath, append(b, '\n'), 0o644); werr != nil {
				r.Errorf("could not write report.sarif: %v", werr)
			} else {
				result.ReportSARIFPath = sarifPath
			}
		}
	}

	mdPath := r.Path("report.md")
	if werr := os.WriteFile(mdPath, []byte(report.Markdown(in)), 0o644); werr != nil {
		r.Errorf("could not write report.md: %v", werr)
	} else {
		result.ReportMarkdownPath = mdPath
	}

	htmlPath := r.Path("report.html")
	if werr := os.WriteFile(htmlPath, []byte(report.HTML(in)), 0o644); werr != nil {
		r.Errorf("could not write report.html: %v", werr)
	} else {
		result.ReportHTMLPath = htmlPath
	}

	return result, nil
}

// loadConfig finds and loads the config file.
func loadConfig(opts ScanOptions) (*config.Config, string, error) {
	path := opts.ConfigPath
	if path == "" {
		base := opts.RepoPath
		if base == "" {
			base = "."
		}
		candidate := filepath.Join(base, config.DefaultFileName)
		if _, err := os.Stat(candidate); err == nil {
			path = candidate
		} else {
			path = config.DefaultFileName
		}
	}

	cfg, err := config.Load(path)
	if err != nil {
		return nil, "", err
	}
	if opts.RepoPath != "" {
		cfg.RepoPath = opts.RepoPath
		// An explicit --repo is relative to the working directory, not to the
		// config file, so resolve it here rather than letting the config's own
		// base directory apply.
		if abs, aerr := filepath.Abs(opts.RepoPath); aerr == nil {
			cfg.RepoPath = abs
		}
	}
	return cfg, cfg.SourcePath(), nil
}

// selectChecks picks which registered checks a mode runs.
func selectChecks(mode Mode, only []string) []check.Check {
	if len(only) > 0 {
		var out []check.Check
		for _, id := range only {
			if c, ok := check.Default.Get(id); ok {
				out = append(out, c)
			}
		}
		return out
	}

	switch mode {
	case ModeStaticOnly:
		return check.Default.ByLayer(check.LayerStatic, check.LayerDeps, check.LayerSecrets)
	case ModeWithRuntime:
		return check.Default.All()
	default:
		return check.Default.ByLayer(
			check.LayerStatic, check.LayerDeps, check.LayerSecrets,
			check.LayerEndpoint, check.LayerExposure,
		)
	}
}

// recordScannerVersions notes which external tools were present and at what
// version, since a finding is only reproducible against a known scanner.
func recordScannerVersions(ctx context.Context, cfg *config.Config, r *run.Run) {
	used := map[string]string{}
	skipped := map[string]string{}

	type entry struct {
		spec tool.Spec
		cfg  config.ScannerConfig
	}
	for _, e := range []entry{
		{tool.SemgrepSpec, cfg.Scanners.Semgrep},
		{tool.OSVScannerSpec, cfg.Scanners.OSV},
		{tool.GitleaksSpec, cfg.Scanners.Gitleaks},
	} {
		if e.cfg.Disabled {
			skipped[e.spec.Name] = "disabled in config"
			continue
		}
		runner := tool.New(e.spec, e.cfg.Path, nil)
		if !runner.Available() {
			_, err := runner.Resolve()
			skipped[e.spec.Name] = err.Error()
			continue
		}
		v, err := runner.Version(ctx)
		if err != nil || v == "" {
			v = "unknown version"
		}
		used[e.spec.Name] = v
	}

	r.SetMeta(func(m *run.Meta) {
		m.ScannersUsed = used
		m.ScannersSkipped = skipped
	})
	r.Log("scanners.resolved", map[string]any{"used": used, "unavailable": skipped})
}

// deselectedSkips records the checks a mode or an --only filter left out.
//
// These are not skips in the orchestrator's sense: selectChecks returns a
// subset and the rest never reach it, so nothing was ever gated and nothing
// was recorded. That distinction is invisible outside this function and
// actively harmful beyond it. A --static-only run produced a findings.json
// with an empty skip list, so every endpoint finding from an earlier run read
// as fixed -- and "full scan locally, narrower scan in CI" is the single most
// common way two runs differ, which made it the likeliest shape of the bug
// rather than an edge case.
//
// Whether a check was filtered out before scheduling or gated out after, the
// consumer needs the same fact: it did not run, and here is why.
func deselectedSkips(mode Mode, only []string, selected []check.Check) []check.SkipReason {
	ran := map[string]bool{}
	for _, c := range selected {
		ran[c.Meta().RuleID] = true
	}

	var out []check.SkipReason
	for _, c := range check.Default.All() {
		m := c.Meta()
		if ran[m.RuleID] {
			continue
		}
		out = append(out, check.SkipReason{
			RuleID: m.RuleID,
			Layer:  m.Layer,
			Reason: deselectionReason(mode, only, m.Layer),
		})
	}
	return out
}

// deselectionReason explains an omission in terms of the flag that caused it,
// so the reason doubles as the instruction for including it next time.
func deselectionReason(mode Mode, only []string, layer check.Layer) string {
	if len(only) > 0 {
		return "this run was limited to the checks named with --only, which did not include this one"
	}
	switch mode {
	case ModeStaticOnly:
		return fmt.Sprintf("this run was static-only, so the %s layer did not run; --static-only makes no outbound connection by design", layer)
	default:
		if layer == check.LayerRuntime {
			return "runtime observation was not enabled for this run (pass --with-runtime)"
		}
		return fmt.Sprintf("this run did not include the %s layer", layer)
	}
}

// mergeSkips combines the gated and deselected skips into one list, ordered by
// rule id so a report and a findings.json do not disagree about ordering
// between runs.
func mergeSkips(gated, deselected []check.SkipReason) []check.SkipReason {
	if len(gated) == 0 && len(deselected) == 0 {
		return nil
	}
	out := make([]check.SkipReason, 0, len(gated)+len(deselected))
	out = append(out, gated...)
	out = append(out, deselected...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].RuleID < out[j].RuleID })
	return out
}

// skippedChecks converts the orchestrator's skip list into the findings.json
// shape. It exists so the machine-readable contract carries what the terminal
// and the Markdown report have always shown: that a check did not run, and
// why.
func skippedChecks(in []check.SkipReason) []finding.SkippedCheck {
	if len(in) == 0 {
		return nil
	}
	out := make([]finding.SkippedCheck, 0, len(in))
	for _, s := range in {
		out = append(out, finding.SkippedCheck{
			CheckID: s.RuleID,
			Layer:   string(s.Layer),
			Reason:  s.Reason,
		})
	}
	return out
}

// failedChecks converts the orchestrator's failure list into the findings.json
// shape, for the same reason skippedChecks exists: the human report has always
// said "these checks failed to complete" and the machine contract said nothing,
// so a consumer could not tell a broken scanner from a clean layer.
func failedChecks(in []orchestrator.CheckError) []finding.FailedCheck {
	if len(in) == 0 {
		return nil
	}
	out := make([]finding.FailedCheck, 0, len(in))
	for _, e := range in {
		msg := ""
		if e.Err != nil {
			msg = e.Err.Error()
		}
		out = append(out, finding.FailedCheck{
			CheckID: e.RuleID,
			Layer:   string(e.Layer),
			Error:   msg,
		})
	}
	return out
}

func failStrings(in []orchestrator.CheckError) []string {
	out := make([]string, 0, len(in))
	for _, e := range in {
		out = append(out, e.String())
	}
	return out
}

// attachRuntime starts the observation sink and tells the operator how to
// install the agent in their own application.
//
// Vibe Killer does not instrument the target process. It opens a sink on
// loopback and prints the few lines the operator adds themselves, so there is
// never any question of what was changed, and nothing to undo afterwards.
func attachRuntime(ctx context.Context, env *check.Env, cfg *config.Config, notice func(string)) error {
	sink := runtime.NewSink(cfg.Runtime.ProxyPort)
	if err := sink.Start(ctx); err != nil {
		return err
	}
	env.Run.Defer("shut down the runtime observation sink", sink.Stop)
	env.Runtime = sink

	env.Run.Log("runtime.sink.started", map[string]any{
		"addr": sink.Addr(),
		"url":  sink.URL(),
		"note": "loopback only; accepts statement shapes, never parameter values",
	})

	adapter := "unknown"
	if env.Surface != nil && env.Surface.Stack.Adapter != "" {
		adapter = env.Surface.Stack.Adapter
	}

	agent, err := runtime.AgentFor(adapter)
	if err != nil {
		notice(fmt.Sprintf("Runtime sink is listening on %s, but %v", sink.URL(), err))
		return nil
	}

	path, werr := agent.Write(env.RepoRoot)
	if werr != nil {
		// An existing file is not an error: it is probably the one the
		// operator already installed.
		notice(werr.Error())
	}
	notice("\n" + agent.Instructions(sink.URL(), path))

	// One request of our own, and it is what makes the runtime layer reachable
	// at all.
	//
	// Eligibility for the whole run is decided before any check executes, and
	// the runtime gate asks whether an observation has arrived. An agent only
	// reports when the application serves a request, so on an instance that is
	// not being used nothing had arrived, the runtime checks were skipped, and
	// the advice printed was "restart your application and scan again" -- which
	// fails the same way, because the next run opens a new sink and waits
	// another two seconds. Measured against the Flask fixture with the agent
	// correctly installed and VIBEKILLER_SINK set: skipped, every time. The
	// layer was documented, had two checks and a pair of shipped agents, and
	// could not be reached without the operator generating traffic inside a
	// two-second window nothing told them about.
	//
	// The checks themselves send their own correlated requests once they are
	// eligible, so the only thing missing was proof that the agent was alive.
	// This sends it. The guard authorizes it like any other request, and a 404
	// serves the purpose as well as a 200 -- what matters is that the
	// application handled something and said so.
	if env.Target != "" && env.HTTP != nil {
		if _, perr := env.HTTP.Do(ctx, httpx.Request{
			RuleID:  "runtime.agent-liveness",
			Method:  http.MethodGet,
			URL:     env.Target,
			Headers: map[string]string{runtime.HeaderCorrelation: "vk-agent-liveness"},
			Note: "one request so the agent has something to report, which is how " +
				"an attached agent is told from an absent one",
		}); perr != nil {
			env.Run.Log("runtime.liveness.failed", map[string]any{"error": perr.Error()})
		}
	}

	if sink.WaitForAgent(ctx, 2*time.Second) {
		notice("The runtime agent is reporting; runtime checks will run.")
		return nil
	}

	notice("No observations have arrived, so the runtime checks will be skipped for this run. " +
		"Install the agent as above and restart your application; a request was just sent to " +
		"the target, so if the agent were attached it would have reported.")
	return nil
}

func shortRev(rev string) string {
	if len(rev) > 8 {
		return rev[:8]
	}
	return rev
}
