package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/rohitanakiya/Vibe-Killer/internal/check"
	"github.com/rohitanakiya/Vibe-Killer/internal/engine"
	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
	"github.com/rohitanakiya/Vibe-Killer/internal/orchestrator"
	"github.com/rohitanakiya/Vibe-Killer/internal/run"
	"github.com/rohitanakiya/Vibe-Killer/internal/scope"
)

func newScanCmd() *cobra.Command {
	var (
		repo        string
		configPath  string
		target      string
		iOwnTarget  bool
		staticOnly  bool
		withRuntime bool
		workers     int
		runsDir     string
		only        []string
		quiet       bool
	)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan a repository, and optionally a running instance of it",
		Long: `Scan analyzes a repository and writes a run directory containing findings.json,
a human-readable report, the audit log of every request sent, and the rule pack
that produced the run.

With no --target, the scan is entirely local and makes no network connections.

With --target, it also exercises that running instance. That is an active test,
so the host must appear in authorized_targets and you must pass
--i-own-this-target.`,
		Example: `  # Repository only. No network.
  vibekiller scan --repo .

  # Repository plus a local instance.
  vibekiller scan --repo . --target http://localhost:3000 --i-own-this-target

  # One check, for iterating on a fix.
  vibekiller scan --repo . --target http://localhost:3000 --i-own-this-target \
      --only idor.sequential-id-access`,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()

			opts := engine.ScanOptions{
				ConfigPath:   configPath,
				RepoPath:     repo,
				Target:       target,
				Acknowledged: iOwnTarget,
				StaticOnly:   staticOnly,
				WithRuntime:  withRuntime,
				Workers:      workers,
				RunsDir:      runsDir,
				Only:         only,
				Notice: func(msg string) {
					fmt.Fprintf(out, "  note: %s\n", msg)
				},
			}

			if !quiet {
				opts.Progress = func(e orchestrator.Event) {
					switch e.Kind {
					case orchestrator.EventDone:
						marker := "  ok  "
						if e.Findings > 0 {
							marker = fmt.Sprintf("  %2d  ", e.Findings)
						}
						fmt.Fprintf(out, "%s %-34s %s\n", marker, e.RuleID, e.Elapsed.Round(time.Millisecond))
					case orchestrator.EventSkipped:
						fmt.Fprintf(out, "  --   %-34s skipped: %s\n", e.RuleID, e.Reason)
					case orchestrator.EventFailed:
						fmt.Fprintf(out, "  !!   %-34s failed: %v\n", e.RuleID, e.Err)
					}
				}
			}

			if target != "" && !staticOnly {
				fmt.Fprintf(out, "Scanning %s and exercising %s\n\n", displayRepo(repo), target)
			} else {
				fmt.Fprintf(out, "Scanning %s (repository only, no network)\n\n", displayRepo(repo))
			}

			result, err := engine.Scan(cmd.Context(), opts)
			if err != nil {
				return classifyScanError(err)
			}

			printResult(cmd, result)

			if result.GateTripped {
				return &exitCodeError{
					code: ExitFindings,
					message: fmt.Sprintf("\nFAIL: at least one open finding is %s or above (severity_threshold: %s).",
						result.GateSeverity, result.GateSeverity),
				}
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&repo, "repo", ".", "path to the repository to scan")
	f.StringVar(&configPath, "config", "", "path to vibekiller.config.yaml (default: look in the repo root)")
	f.StringVar(&target, "target", "", "base URL of a running instance of this application to exercise")
	f.BoolVar(&iOwnTarget, "i-own-this-target", false,
		"confirm you own or are authorized to test the instance at --target; required for any request")
	f.BoolVar(&staticOnly, "static-only", false, "analyze the repository only: no network connections at all")
	f.BoolVar(&withRuntime, "with-runtime", false, "also attach the observe-only runtime adapter")
	f.IntVar(&workers, "workers", 4, "how many checks to run concurrently")
	f.StringVar(&runsDir, "runs-dir", run.DirName, "directory to write run output into")
	f.StringSliceVar(&only, "only", nil, "run only these checks, by rule id (repeatable)")
	f.BoolVar(&quiet, "quiet", false, "suppress per-check progress output")

	return cmd
}

// classifyScanError maps a setup failure to the right exit code, so that a
// refusal on scope grounds is distinguishable from a crash.
func classifyScanError(err error) error {
	var notAck *engine.ErrTargetNotAcknowledged
	if errors.As(err, &notAck) {
		return exitWith(ExitRefused, "refused: %v", err)
	}

	var oos *scope.ErrOutOfScope
	if errors.As(err, &oos) {
		return exitWith(ExitRefused, "refused: %v", err)
	}

	var notAckScope *scope.ErrNotAcknowledged
	if errors.As(err, &notAckScope) {
		return exitWith(ExitRefused, "refused: %v", err)
	}

	return exitWith(ExitError, "scan failed: %v", err)
}

// printResult writes the human summary of a completed scan.
func printResult(cmd *cobra.Command, r *engine.Result) {
	out := cmd.OutOrStdout()
	counts := finding.Summarize(r.Findings)

	fmt.Fprintf(out, "\nRun %s\n", r.RunID)
	fmt.Fprintf(out, "  %s\n", r.RunDir)

	if r.Surface != nil && r.Surface.Stack.Adapter != "none" {
		s := r.Surface.Stack
		desc := s.Language
		if s.Framework != "" {
			desc += " / " + s.Framework
		}
		if s.Database != "" {
			desc += " / " + s.Database
		}
		fmt.Fprintf(out, "  stack: %s (%s confidence), %d route(s) mapped\n",
			desc, s.Confidence, len(r.Surface.Routes))
	}

	if r.MergeSummary.Merged > 0 {
		fmt.Fprintf(out, "  %s\n", r.MergeSummary)
	}

	// A regression is the one result that deserves its own line: it says a fix
	// did not hold, which is different from the issue merely being open.
	if r.Regressions > 0 {
		fmt.Fprintf(out, "  %d finding(s) a previous run recorded as fixed are open again\n", r.Regressions)
	}

	fmt.Fprintln(out)

	if counts.Total == 0 {
		fmt.Fprintln(out, "No findings from the checks that ran.")
	} else {
		fmt.Fprintf(out, "%d finding(s), %d confirmed by a non-destructive check:\n", counts.Total, counts.Confirmed)
		for _, sev := range []finding.Severity{
			finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium,
			finding.SeverityLow, finding.SeverityInfo,
		} {
			if n := counts.BySeverity[string(sev)]; n > 0 {
				fmt.Fprintf(out, "  %-9s %d\n", sev, n)
			}
		}

		fmt.Fprintln(out, "\nHighest ranked:")
		shown := 0
		for _, f := range r.Findings {
			if shown >= 5 {
				break
			}
			tag := " "
			if f.Confidence == finding.ConfidenceConfirmed {
				tag = "*"
			}
			fmt.Fprintf(out, "  %s %-9s %-24s %s\n", tag, f.Severity, f.FindingID, truncate(f.Title, 76))
			shown++
		}
		if len(r.Findings) > shown {
			fmt.Fprintf(out, "    ... and %d more\n", len(r.Findings)-shown)
		}
		fmt.Fprintln(out, "\n  * = reproduced against the running instance")
	}

	// Coverage gaps are printed after the findings but before the paths, so
	// they are the last thing read before someone decides the app is fine.
	if len(r.Skipped) > 0 {
		fmt.Fprintf(out, "\n%d check(s) did not run, so nothing is known about what they cover:\n", len(r.Skipped))
		for _, s := range check.GroupSkipLines(r.Skipped) {
			fmt.Fprintf(out, "  - %s\n", s)
		}
	}
	if len(r.Failed) > 0 {
		fmt.Fprintf(out, "\n%d check(s) failed:\n", len(r.Failed))
		for _, e := range r.Failed {
			fmt.Fprintf(out, "  - %s\n", e)
		}
	}

	fmt.Fprintln(out)
	if r.ReportMarkdownPath != "" {
		fmt.Fprintf(out, "Report:   %s\n", r.ReportMarkdownPath)
	}
	if r.ReportHTMLPath != "" {
		fmt.Fprintf(out, "          %s\n", r.ReportHTMLPath)
	}
	if r.ReportSARIFPath != "" {
		fmt.Fprintf(out, "SARIF:    %s\n", r.ReportSARIFPath)
	}
	fmt.Fprintf(out, "Findings: %s\n", r.RunDir+string(os.PathSeparator)+run.FileFindings)
	fmt.Fprintf(out, "Log:      %s\n", r.RunDir+string(os.PathSeparator)+run.FileLog)
}

func displayRepo(repo string) string {
	if repo == "" || repo == "." {
		if wd, err := os.Getwd(); err == nil {
			return wd
		}
		return "."
	}
	return repo
}

func truncate(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}
