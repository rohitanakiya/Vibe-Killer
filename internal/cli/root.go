// Package cli is the command-line surface of Vibe Killer.
//
// It stays thin: parsing flags and printing results. The work belongs to the
// engine, so that the same operation can be driven from a test or from another
// program without going through argv.
package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/rohitanakiya/Vibe-Killer/internal/engine"
)

// Version is overridden at build time with -ldflags, but the value here is
// not a placeholder: `go install <module>@vX.Y.Z` passes no ldflags, so for
// anyone who installs rather than builds, this constant IS the reported
// version. It is also stamped into every findings.json and into the
// User-Agent sent to the operator's own instance, which is what lets a report
// be traced back to the code that produced it.
//
// Hence the -dev suffix, and the release ritual it implies. Between releases
// this carries -dev so that a report from an unreleased build cannot be
// mistaken for one from the release it follows -- which matters here more
// than in most projects, because findings carry forward across runs and a
// regression is argued from the history of which build saw what. At release
// time, one commit sets this to the bare version, the tag points at that
// commit, and the next commit restores -dev.
var Version = "1.0.0"

// Exit codes. These are the CLI's contract with a CI pipeline, so they are
// deliberately few and stable.
const (
	// ExitOK means the scan completed and nothing reached the severity gate.
	ExitOK = 0

	// ExitFindings means the scan completed and a finding at or above the
	// configured threshold is open. This is what fails a build.
	ExitFindings = 1

	// ExitError means the scan could not complete.
	ExitError = 2

	// ExitRefused means the operation was refused on scope or safety grounds,
	// for example a target that was not declared, or a missing ownership
	// acknowledgement. It is distinct from ExitError so a pipeline can tell a
	// configuration problem from a broken scan.
	ExitRefused = 3
)

// Main runs the CLI and returns the process exit code.
func Main() int {
	engine.Version = Version

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	root := newRootCmd()
	root.SetContext(ctx)

	if err := root.Execute(); err != nil {
		var ec *exitCodeError
		if errors.As(err, &ec) {
			if ec.message != "" {
				fmt.Fprintln(os.Stderr, ec.message)
			}
			return ec.code
		}
		fmt.Fprintf(os.Stderr, "vibekiller: %v\n", err)
		return ExitError
	}
	return ExitOK
}

// exitCodeError carries a specific exit code out of a command.
type exitCodeError struct {
	code    int
	message string
}

func (e *exitCodeError) Error() string {
	if e.message != "" {
		return e.message
	}
	return fmt.Sprintf("exit %d", e.code)
}

func exitWith(code int, format string, args ...any) error {
	return &exitCodeError{code: code, message: fmt.Sprintf(format, args...)}
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vibekiller",
		Short: "Find and prove security weaknesses in an application you own",
		Long: `Vibe Killer is a self-hosted security scanner for applications you own.

It reads your repository and, optionally, exercises a running instance of the
same application on a host you declare, looking for the weaknesses that
AI-generated code repeatedly ships: missing authorization, exposed credentials,
insecure configuration and vulnerable dependencies.

It verifies non-destructively. Access-control findings are proven by reading a
decoy record you seeded for the purpose, so no real data is read and nothing is
modified. Findings are written to the local runs/ directory and are never sent
anywhere.

Endpoint checks only ever contact a host listed in authorized_targets, and
require --i-own-this-target.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       Version,
	}

	cmd.AddCommand(
		newScanCmd(),
		newReportCmd(),
		newDiffCmd(),
		newReproduceCmd(),
		newChecksCmd(),
		newHistoryCmd(),
		newInitCmd(),
	)

	return cmd
}
