package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/rohitanakiya/Vibe-Killer/internal/check"
	"github.com/rohitanakiya/Vibe-Killer/internal/config"
	"github.com/rohitanakiya/Vibe-Killer/internal/diff"
	"github.com/rohitanakiya/Vibe-Killer/internal/engine"
	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
	"github.com/rohitanakiya/Vibe-Killer/internal/httpx"
	"github.com/rohitanakiya/Vibe-Killer/internal/report"
	"github.com/rohitanakiya/Vibe-Killer/internal/run"
	"github.com/rohitanakiya/Vibe-Killer/internal/sarif"
	"github.com/rohitanakiya/Vibe-Killer/internal/surface"
	"github.com/rohitanakiya/Vibe-Killer/internal/vcs"
)

// --- report ----------------------------------------------------------------

func newReportCmd() *cobra.Command {
	var (
		format   string
		output   string
		category string
	)

	cmd := &cobra.Command{
		Use:   "report <run-dir>",
		Short: "Re-render a run's report",
		Long: `Report re-renders the human-readable report for a run that has already
completed, reading findings.json and run.json from the run directory.

The HTML report is a single self-contained file with no external assets, so it
can be opened offline and attached to a ticket.

--format sarif emits SARIF 2.1.0, which GitHub code scanning ingests: upload it
and each finding becomes an annotated alert on the pull request. Checks that
were skipped or that failed are carried as tool execution notifications, so the
file says what was not covered as well as what was found.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := args[0]

			doc, err := run.LoadFindings(dir)
			if err != nil {
				return exitWith(ExitError, "could not read findings from %s: %v", dir, err)
			}
			meta, err := run.LoadMeta(dir)
			if err != nil {
				// A run directory without run.json is still renderable; the
				// report just carries less context.
				meta = &run.Meta{RunID: doc.RunID, RepoPath: doc.RepoPath, RepoRev: doc.RepoRev, Target: doc.Target}
			}

			// The coverage section used to be lost on a re-render, because
			// only the findings were read back. Now that findings.json
			// carries what did not run, a re-rendered report says the same
			// thing the original did instead of looking cleaner than it was.
			in := report.Input{
				Meta:     *meta,
				Findings: doc.Findings,
				Skipped:  check.GroupSkipLines(skipReasonsFromDoc(doc)),
				Failed:   failureLinesFromDoc(doc),
			}

			var rendered string
			switch strings.ToLower(format) {
			case "md", "markdown":
				rendered = report.Markdown(in)
			case "html":
				rendered = report.HTML(in)
			case "sarif":
				// The surface is what lets an endpoint finding resolve to the
				// handler serving the route. A run directory always has one if
				// mapping ran, and its absence only costs precision.
				var mapped *surface.Surface
				if loaded, serr := run.LoadSurface(dir); serr == nil {
					mapped = loaded
				}
				log := sarif.Convert(doc, sarif.Options{
					ToolVersion:    Version,
					InformationURI: engine.InformationURI,
					Surface:        mapped,
					Category:       category,
				})
				b, merr := json.MarshalIndent(log, "", "  ")
				if merr != nil {
					return exitWith(ExitError, "encoding SARIF: %v", merr)
				}
				rendered = string(b) + "\n"
			default:
				return exitWith(ExitError, "unknown format %q (want markdown, html or sarif)", format)
			}

			if output == "" {
				fmt.Fprint(cmd.OutOrStdout(), rendered)
				return nil
			}
			if err := os.WriteFile(output, []byte(rendered), 0o644); err != nil {
				return exitWith(ExitError, "writing %s: %v", output, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Wrote %s\n", output)
			return nil
		},
	}

	cmd.Flags().StringVar(&format, "format", "markdown", "output format: markdown, html or sarif")
	cmd.Flags().StringVar(&category, "category", "", "SARIF automation category, which is what lets two uploads coexist on one commit")
	cmd.Flags().StringVarP(&output, "output", "o", "", "write to this file instead of stdout")
	return cmd
}

// --- diff ------------------------------------------------------------------

func newDiffCmd() *cobra.Command {
	var failOnNew bool

	cmd := &cobra.Command{
		Use:   "diff <run-a> [run-b]",
		Short: "Compare two runs: what is new, fixed or regressed",
		Long: `Diff compares two runs by finding identity.

A finding is "fixed" when it is no longer reported by a check that ran, which
for a dynamic finding means it is no longer reproducible. A finding is
"regressed" when it had been marked fixed and is reported again.

A finding is "not re-checked" when it was open before and the check that would
have found it did not run this time -- a missing scanner, no --target, or a
framework whose routes cannot be extracted. Those are counted separately and
never as fixed, because absence is only evidence when something looked.

With one argument, the run is compared against the run immediately before it.`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()

			var fromDir, toDir string
			switch len(args) {
			case 2:
				fromDir, toDir = args[0], args[1]
			case 1:
				toDir = args[0]
				base := filepath.Dir(toDir)
				id := filepath.Base(toDir)
				prev, ok := run.Previous(base, id)
				if !ok {
					return exitWith(ExitError,
						"no earlier run was found next to %s, so there is nothing to compare against", toDir)
				}
				fromDir = filepath.Join(base, prev)
				fmt.Fprintf(out, "Comparing against the previous run: %s\n\n", prev)
			}

			from, err := run.LoadFindings(fromDir)
			if err != nil {
				return exitWith(ExitError, "could not read %s: %v", fromDir, err)
			}
			to, err := run.LoadFindings(toDir)
			if err != nil {
				return exitWith(ExitError, "could not read %s: %v", toDir, err)
			}

			result := diff.Compare(from, to)
			fmt.Fprint(out, report.DiffMarkdown(result))

			if failOnNew && !result.Improved() {
				return &exitCodeError{
					code:    ExitFindings,
					message: fmt.Sprintf("\nFAIL: %s", result.Progress()),
				}
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&failOnNew, "fail-on-new", false,
		"exit non-zero if the later run has new or regressed findings")
	return cmd
}

// --- reproduce -------------------------------------------------------------

func newReproduceCmd() *cobra.Command {
	var (
		runDir     string
		runsDir    string
		configPath string
		repo       string
		target     string
		iOwnTarget bool
	)

	cmd := &cobra.Command{
		Use:   "reproduce <finding-id>",
		Short: "Re-run one finding's proof against the running instance",
		Long: `Reproduce re-runs the non-destructive check behind a single finding and reports
whether it still holds.

This is how a fix gets verified: the same request sequence that proved the
finding is sent again, and the finding is only reported as fixed when the
boundary actually holds.

Like any other request to a running instance, this needs the host to be in
authorized_targets and requires --i-own-this-target.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			findingID := args[0]

			if runsDir == "" {
				runsDir = run.DirName
			}

			f, foundIn, err := locateFinding(runsDir, runDir, findingID)
			if err != nil {
				return exitWith(ExitError, "%v", err)
			}
			fmt.Fprintf(out, "Found %s in run %s\n", findingID, foundIn)
			fmt.Fprintf(out, "  %s\n  %s\n\n", f.RuleID, f.Title)

			c, ok := check.Default.Get(f.RuleID)
			if !ok {
				return exitWith(ExitError,
					"no check is registered for rule %s, so this finding cannot be re-run by this build", f.RuleID)
			}
			reproducer, ok := c.(check.Reproducer)
			if !ok {
				if f.Reproduction != nil && len(f.Reproduction.Steps) > 0 {
					fmt.Fprintln(out, "This is a static finding; it is verified by reading the code:")
					for i, s := range f.Reproduction.Steps {
						fmt.Fprintf(out, "  %d. %s\n", i+1, s)
					}
					return nil
				}
				return exitWith(ExitError, "check %s cannot re-run a single finding", f.RuleID)
			}

			env, cleanup, err := buildReproEnv(cmd, reproEnvOptions{
				ConfigPath: configPath,
				Repo:       repo,
				Target:     target,
				Ack:        iOwnTarget,
				RunsDir:    runsDir,
			})
			if err != nil {
				return err
			}
			defer cleanup()

			result, err := reproducer.Reproduce(cmd.Context(), env, *f)
			if err != nil {
				return exitWith(ExitError, "could not re-run this finding: %v", err)
			}

			fmt.Fprintln(out, result.Detail)
			if result.Evidence.Observed != "" {
				fmt.Fprintf(out, "  observed: %s\n", result.Evidence.Observed)
			}
			if result.Evidence.Expected != "" {
				fmt.Fprintf(out, "  expected: %s\n", result.Evidence.Expected)
			}

			if result.Reproduced {
				return &exitCodeError{
					code:    ExitFindings,
					message: "\nStill reproducible.",
				}
			}
			fmt.Fprintln(out, "\nNo longer reproducible.")
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&runDir, "run", "", "look in this run directory only")
	f.StringVar(&runsDir, "runs-dir", run.DirName, "directory holding run output")
	f.StringVar(&configPath, "config", "", "path to vibekiller.config.yaml")
	f.StringVar(&repo, "repo", ".", "path to the repository")
	f.StringVar(&target, "target", "", "base URL of the running instance (default: the target recorded in the run)")
	f.BoolVar(&iOwnTarget, "i-own-this-target", false, "confirm you own the instance at --target")

	return cmd
}

// locateFinding searches run directories for a finding id, newest first.
func locateFinding(runsDir, runDir, findingID string) (*finding.Finding, string, error) {
	search := func(dir string) (*finding.Finding, bool) {
		doc, err := run.LoadFindings(dir)
		if err != nil {
			return nil, false
		}
		for i := range doc.Findings {
			if doc.Findings[i].FindingID == findingID {
				return &doc.Findings[i], true
			}
		}
		return nil, false
	}

	if runDir != "" {
		if f, ok := search(runDir); ok {
			return f, filepath.Base(runDir), nil
		}
		return nil, "", fmt.Errorf("finding %s is not in %s", findingID, runDir)
	}

	ids, err := run.List(runsDir)
	if err != nil {
		return nil, "", fmt.Errorf("could not list runs in %s: %w", runsDir, err)
	}
	if len(ids) == 0 {
		return nil, "", fmt.Errorf("no runs were found in %s; run a scan first", runsDir)
	}

	for i := len(ids) - 1; i >= 0; i-- {
		if f, ok := search(filepath.Join(runsDir, ids[i])); ok {
			return f, ids[i], nil
		}
	}
	return nil, "", fmt.Errorf("finding %s was not found in any run under %s", findingID, runsDir)
}

type reproEnvOptions struct {
	ConfigPath string
	Repo       string
	Target     string
	Ack        bool
	RunsDir    string
}

// buildReproEnv assembles the minimum environment a single reproduction needs,
// including its own run directory so the replayed requests are logged like any
// other.
func buildReproEnv(cmd *cobra.Command, opts reproEnvOptions) (*check.Env, func(), error) {
	noop := func() {}

	cfgPath := opts.ConfigPath
	if cfgPath == "" {
		cfgPath = filepath.Join(opts.Repo, config.DefaultFileName)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, noop, exitWith(ExitError, "could not load config: %v", err)
	}
	if opts.Repo != "" {
		if abs, aerr := filepath.Abs(opts.Repo); aerr == nil {
			cfg.RepoPath = abs
		}
	}
	if err := cfg.Validate(); err != nil {
		return nil, noop, exitWith(ExitError, "the configuration is not usable:\n%v", err)
	}

	target := opts.Target
	if target == "" {
		// Fall back to the single declared target, when there is exactly one.
		if len(cfg.AuthorizedTargets) == 1 {
			target = cfg.AuthorizedTargets[0]
		} else {
			return nil, noop, exitWith(ExitRefused,
				"several targets are declared, so --target is required to say which instance to replay against")
		}
	}

	guard, err := cfg.Guard(opts.Ack)
	if err != nil {
		return nil, noop, exitWith(ExitError, "building the authorized scope: %v", err)
	}
	if !opts.Ack {
		return nil, noop, exitWith(ExitRefused, "refused: %v", (&engine.ErrTargetNotAcknowledged{Target: target}))
	}
	if err := guard.AuthorizeTarget(target); err != nil {
		return nil, noop, exitWith(ExitRefused, "refused: %v", err)
	}

	repoRoot, err := cfg.ResolvedRepoPath()
	if err != nil {
		return nil, noop, exitWith(ExitError, "%v", err)
	}
	git := vcs.Read(cmd.Context(), repoRoot)

	r, err := run.Create(opts.RunsDir, run.Meta{
		StartedAt: time.Now().UTC().Format(time.RFC3339),
		Tool:      "vibekiller",
		Version:   Version,
		RepoPath:  repoRoot,
		RepoRev:   git.Rev,
		Mode:      "reproduce",
		Target:    target,

		AuthorizedTargets:           guard.Targets(),
		TargetOwnershipAcknowledged: true,
		AcknowledgedAt:              time.Now().UTC().Format(time.RFC3339),
		NonDestructive:              cfg.IsNonDestructive(),
		DisposableEnv:               cfg.Dynamic.DisposableEnv,
	})
	if err != nil {
		return nil, noop, exitWith(ExitError, "could not create a run directory: %v", err)
	}

	client, err := httpx.New(httpx.Options{
		Guard:       guard,
		MaxRPS:      cfg.Dynamic.MaxRPS,
		Concurrency: cfg.Dynamic.Concurrency,
		Timeout:     time.Duration(cfg.Dynamic.TimeoutSeconds) * time.Second,
		UserAgent:   "vibekiller/" + Version + " (reproducing one finding)",
		Recorder:    r,
	})
	if err != nil {
		_ = r.Close()
		return nil, noop, exitWith(ExitError, "%v", err)
	}

	env := &check.Env{
		Config:   cfg,
		Guard:    guard,
		Run:      r,
		HTTP:     client,
		Target:   target,
		RepoRoot: repoRoot,
		RepoRev:  git.Rev,
		HasGit:   git.IsRepo,
	}

	// The IDOR reproduction needs the route model only when it has to rebuild
	// a URL; the recorded request path is normally enough, so a mapping
	// failure here is not fatal.
	if s, serr := engine.MapSurface(cmd.Context(), env); serr == nil {
		env.Surface = s
	}

	return env, func() {
		_ = client.Close()
		_ = r.Close()
	}, nil
}

// --- checks ----------------------------------------------------------------

func newChecksCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "checks",
		Short: "List the registered checks and what each one needs",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			all := check.Default.All()

			byLayer := map[check.Layer][]check.Check{}
			for _, c := range all {
				m := c.Meta()
				byLayer[m.Layer] = append(byLayer[m.Layer], c)
			}

			layers := []check.Layer{
				check.LayerStatic, check.LayerDeps, check.LayerSecrets,
				check.LayerEndpoint, check.LayerRuntime, check.LayerExposure,
			}

			fmt.Fprintf(out, "%d check(s) registered.\n", len(all))
			for _, layer := range layers {
				checks := byLayer[layer]
				if len(checks) == 0 {
					continue
				}
				fmt.Fprintf(out, "\n%s\n", strings.ToUpper(string(layer)))
				for _, c := range checks {
					m := c.Meta()
					fmt.Fprintf(out, "  %-32s %s\n", m.RuleID, m.Title)
					if reqs := requirements(m); len(reqs) > 0 {
						fmt.Fprintf(out, "  %-32s needs: %s\n", "", strings.Join(reqs, ", "))
					}
				}
			}
			return nil
		},
	}
	return cmd
}

// skipReasonsFromDoc re-hydrates the document's skip list into the shape the
// grouping helper takes. The two types stay separate on purpose: findings.json
// must not depend on an internal check type, and the check package must not
// depend on the serialized contract.
func skipReasonsFromDoc(doc *finding.Document) []check.SkipReason {
	if len(doc.Skipped) == 0 {
		return nil
	}
	out := make([]check.SkipReason, 0, len(doc.Skipped))
	for _, s := range doc.Skipped {
		out = append(out, check.SkipReason{
			RuleID: s.CheckID,
			Layer:  check.Layer(s.Layer),
			Reason: s.Reason,
		})
	}
	return out
}

func failureLinesFromDoc(doc *finding.Document) []string {
	if len(doc.Failed) == 0 {
		return nil
	}
	out := make([]string, 0, len(doc.Failed))
	for _, f := range doc.Failed {
		out = append(out, f.CheckID+": "+f.Error)
	}
	sort.Strings(out)
	return out
}

func requirements(m check.Meta) []string {
	var reqs []string
	if m.NeedsTarget {
		reqs = append(reqs, "a running instance")
	}
	if m.NeedsSurface {
		reqs = append(reqs, "mapped routes")
	}
	if m.NeedsSeededUsers > 0 {
		reqs = append(reqs, fmt.Sprintf("%d seeded users with tokens", m.NeedsSeededUsers))
	}
	if m.NeedsCanary {
		reqs = append(reqs, "a seeded canary record")
	}
	if m.Mutating {
		reqs = append(reqs, "a disposable environment (changes state)")
	}
	sort.Strings(reqs)
	return reqs
}

// --- init ------------------------------------------------------------------

func newInitCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Write a starter vibekiller.config.yaml",
		Long: `Init writes a commented starter config into the current directory.

The file declares nothing beyond your own machine, and sets the non-destructive
posture, so a scan run straight after init is safe by default.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()

			if _, err := os.Stat(config.DefaultFileName); err == nil && !force {
				return exitWith(ExitError,
					"%s already exists; pass --force to overwrite it", config.DefaultFileName)
			}

			if err := os.WriteFile(config.DefaultFileName, []byte(starterConfig), 0o644); err != nil {
				return exitWith(ExitError, "writing %s: %v", config.DefaultFileName, err)
			}

			fmt.Fprintf(out, "Wrote %s\n\n", config.DefaultFileName)
			fmt.Fprintln(out, "Next:")
			fmt.Fprintln(out, "  1. vibekiller scan --repo .")
			fmt.Fprintln(out, "     Analyzes the repository. No network.")
			fmt.Fprintln(out, "  2. To test a running instance, seed two throwaway accounts and a decoy record,")
			fmt.Fprintln(out, "     fill in seeded_users and canary_records, export the token variables, then:")
			fmt.Fprintln(out, "     vibekiller scan --repo . --target http://localhost:3000 --i-own-this-target")
			return nil
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing config file")
	return cmd
}

const starterConfig = `# Vibe Killer configuration.
#
# This file declares what Vibe Killer is allowed to touch. Nothing outside
# authorized_targets is ever contacted, and endpoint checks additionally
# require the --i-own-this-target flag.

repo_path: .

# Endpoint checks refuse any host that is not listed here. The default is your
# own machine. Add a host only if you own it or are authorized to test it.
authorized_targets:
  - http://localhost:3000

# Two throwaway accounts in your own instance. Access-control checks compare
# what one can see against what the other owns.
#
# Tokens are read from environment variables, never from this file, so that
# this file is safe to commit.
seeded_users:
  - { id: userA, token_env: VK_USERA_TOKEN }
  - { id: userB, token_env: VK_USERB_TOKEN }

# Decoy records you created for the purpose. These are what a check reads to
# prove a boundary failed, so no real record is ever read.
#
# marker is any distinctive string inside the record. With it, a check can tell
# that the record itself came back rather than inferring it from a status code.
canary_records:
  - { owner: userB, resource: order, id: "90001", marker: "VK-CANARY-USERB" }

dynamic:
  # Non-destructive is the default. Setting it false is not enough on its own
  # to enable state-changing checks: disposable_env must also be true.
  non_destructive: true
  disposable_env: false

  # Request rate and concurrency, per host. These are low on purpose: the
  # target is usually a development server on the same machine.
  max_rps: 10
  concurrency: 4
  timeout_seconds: 15

runtime:
  enabled: false

# Scanners are discovered on PATH. A missing one is reported as a skipped
# check, not a failure.
scanners:
  semgrep:
    disabled: false
    # Vibe Killer always runs its own embedded rule pack, which needs no
    # network. Registry packs are downloaded at scan time, so they are opt-in:
    # rule_packs: ["p/security-audit"]
  osv_scanner:
    disabled: false
  gitleaks:
    disabled: false

# A scan exits non-zero when an open finding is at or above this severity.
severity_threshold: high
`
