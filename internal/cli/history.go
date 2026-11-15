package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/rohitanakiya/Vibe-Killer/internal/history"
	"github.com/rohitanakiya/Vibe-Killer/internal/run"
)

func newHistoryCmd() *cobra.Command {
	var (
		runsDir string
		limit   int
		trend   string
	)

	cmd := &cobra.Command{
		Use:   "history",
		Short: "Show recorded runs, and how one finding changed across them",
		Long: `History reads the local run database that each scan writes to.

It is what makes a fix measurable rather than asserted: a finding that was
reported, then absent, then reported again is a regression, and that is only
visible if the tool remembers the middle part.

The database is a file in the runs directory. Nothing leaves your machine.`,
		Example: `  vibekiller history
  vibekiller history --trend vk-902fa425a688`,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()

			store, err := history.Open(runsDir)
			if err != nil {
				return exitWith(ExitError, "could not open the run history: %v", err)
			}
			defer func() { _ = store.Close() }()

			if trend != "" {
				t, err := store.TrendFor(trend)
				if err != nil {
					return exitWith(ExitError, "%v", err)
				}

				fmt.Fprintf(out, "%s  %s\n", t.FindingID, t.RuleID)
				fmt.Fprintf(out, "%s\n\n", t.Title)
				fmt.Fprintf(out, "%-26s %s\n", "RUN", "STATUS")
				for i, runID := range t.Runs {
					fmt.Fprintf(out, "%-26s %s\n", runID, t.Statuses[i])
				}

				// The shape of the history is the interesting part, so say it
				// in words rather than leaving it to be read off the table.
				fmt.Fprintf(out, "\n%s\n", describeTrend(t))
				return nil
			}

			stats, err := store.Stats()
			if err != nil {
				return exitWith(ExitError, "could not summarize the history: %v", err)
			}

			runs, err := store.Runs(limit)
			if err != nil {
				return exitWith(ExitError, "could not list runs: %v", err)
			}

			if len(runs) == 0 {
				fmt.Fprintf(out, "No runs are recorded in %s yet.\n", store.Path())
				return nil
			}

			fmt.Fprintf(out, "%d run(s) recorded in %s\n\n", stats.Runs, store.Path())
			fmt.Fprintf(out, "  distinct issues ever seen: %d\n", stats.UniqueIssues)
			fmt.Fprintf(out, "  open in the latest run:    %d\n", stats.CurrentlyOpen)
			fmt.Fprintf(out, "  ever recorded fixed:       %d\n", stats.EverFixed)
			if stats.Regressions > 0 {
				fmt.Fprintf(out, "  regressed at some point:   %d\n", stats.Regressions)
			}

			fmt.Fprintf(out, "\n%-26s %-13s %-7s %-10s %s\n", "RUN", "MODE", "TOTAL", "CONFIRMED", "TARGET")
			for _, r := range runs {
				target := r.Target
				if target == "" {
					target = "-"
				}
				fmt.Fprintf(out, "%-26s %-13s %-7d %-10d %s\n",
					r.RunID, r.Mode, r.Total, r.Confirmed, target)
			}

			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&runsDir, "runs-dir", run.DirName, "directory holding run output and the history database")
	f.IntVar(&limit, "limit", 20, "how many runs to list")
	f.StringVar(&trend, "trend", "", "show how one finding changed across runs, by finding id")

	return cmd
}

// describeTrend states what a finding's recorded history amounts to.
func describeTrend(t *history.Trend) string {
	if len(t.Statuses) == 0 {
		return "No status was recorded."
	}

	last := t.Statuses[len(t.Statuses)-1]

	var fixedAt, reopenedAt int
	for i, s := range t.Statuses {
		if s == "fixed" {
			fixedAt = i + 1
		}
		if s == "regressed" {
			reopenedAt = i + 1
		}
	}

	switch {
	case reopenedAt > 0:
		return fmt.Sprintf("This was fixed and came back: it was recorded fixed at run %d of %d and open again at run %d. "+
			"A test covering it would have caught the second time.", fixedAt, len(t.Runs), reopenedAt)
	case last == "fixed":
		return fmt.Sprintf("Fixed, and it has stayed fixed for %d run(s).", len(t.Runs)-fixedAt+1)
	case last == "accepted":
		return "Someone reviewed this and accepted it. Later runs leave that decision alone."
	case last == "false_positive":
		return "Someone marked this a false positive. Later runs leave that decision alone."
	case len(t.Runs) == 1:
		return "Seen once, in the run above."
	default:
		return fmt.Sprintf("Open across all %d recorded run(s). It has not been fixed at any point.", len(t.Runs))
	}
}
