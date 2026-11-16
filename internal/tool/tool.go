// Package tool runs the external scanners Vibe Killer orchestrates.
//
// Vibe Killer does not reimplement static analysis, dependency auditing or
// secret detection. It drives Semgrep, osv-scanner and gitleaks, parses their
// JSON, and normalizes the result into the findings contract. This package is
// the single place that knows how to invoke one of them safely: with a bounded
// timeout, a cancellable context, captured output, and a clear distinction
// between "the tool is not installed" and "the tool failed".
package tool

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// DefaultTimeout bounds a scanner run when the config gives no override.
// Static analysis over a large repo is slow, so this is generous.
const DefaultTimeout = 10 * time.Minute

// ErrNotInstalled means the binary is not on PATH. It is not a scan failure:
// the orchestrator records the scanner as skipped and continues, because a
// partial scan that says which engine was missing is more useful than no scan.
type ErrNotInstalled struct {
	Name string
	Hint string
}

func (e *ErrNotInstalled) Error() string {
	msg := fmt.Sprintf("%s is not installed or not on PATH", e.Name)
	if e.Hint != "" {
		msg += " (" + e.Hint + ")"
	}
	return msg
}

// ErrDisabled means the operator switched this scanner off.
//
// It is a skip rather than a failure, and it has to be tellable from one: a
// consumer should not retry a scanner the operator declined, and a layer that
// was switched off is not a layer that found nothing. Before this existed a
// disabled scanner returned (nil, nil), which is indistinguishable from a
// successful scan of a clean tree -- so the check was recorded as having run,
// the report listed nothing, and `diff` called that scanner's findings fixed
// on the next run. ErrScannerDisabled was declared in the staticchecks
// package with a doc comment saying it was "reported as a skip", and was
// returned by nothing.
//
// It lives here beside ErrNotInstalled, which is its sibling -- both mean the
// scanner was not available to this run -- so that the orchestrator can
// classify it without importing a checks package.
var ErrDisabled = errors.New("disabled in config")

// ErrFailed means the tool ran but exited with an unexpected status.
type ErrFailed struct {
	Name     string
	Args     []string
	ExitCode int
	Stderr   string
}

func (e *ErrFailed) Error() string {
	stderr := strings.TrimSpace(e.Stderr)
	if len(stderr) > 600 {
		stderr = stderr[:600] + "..."
	}
	return fmt.Sprintf("%s exited with status %d: %s", e.Name, e.ExitCode, stderr)
}

// Spec describes one external tool.
type Spec struct {
	// Name is the logical name used in reports, e.g. "semgrep".
	Name string

	// Binary is the executable to look for. Defaults to Name.
	Binary string

	// VersionArgs produce a version string, e.g. ["--version"].
	VersionArgs []string

	// OKExitCodes are statuses that mean "ran successfully". Scanners
	// conventionally exit non-zero when they find something, so a bare
	// "exit != 0 is a failure" rule would discard every real result.
	OKExitCodes []int

	// InstallHint is shown when the binary is missing.
	InstallHint string

	// Timeout bounds the run. Zero means DefaultTimeout.
	Timeout time.Duration
}

// Result is the outcome of one tool invocation.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Duration time.Duration
	Command  string
}

// Runner invokes a tool according to its Spec.
type Runner struct {
	spec Spec

	// path overrides PATH lookup, from the operator's config.
	path string

	// extraArgs are appended to every invocation, from the operator's config.
	extraArgs []string
}

// New builds a Runner. path and extraArgs come from the operator's config and
// may be empty.
func New(spec Spec, path string, extraArgs []string) *Runner {
	if spec.Binary == "" {
		spec.Binary = spec.Name
	}
	if len(spec.OKExitCodes) == 0 {
		spec.OKExitCodes = []int{0}
	}
	if spec.Timeout == 0 {
		spec.Timeout = DefaultTimeout
	}
	return &Runner{spec: spec, path: path, extraArgs: extraArgs}
}

// Name returns the tool's logical name.
func (r *Runner) Name() string { return r.spec.Name }

// Resolve locates the binary, returning ErrNotInstalled if it is absent.
func (r *Runner) Resolve() (string, error) {
	if r.path != "" {
		// An explicitly configured path must exist; falling back to PATH here
		// would silently run a different binary than the operator named.
		if _, err := exec.LookPath(r.path); err != nil {
			return "", &ErrNotInstalled{
				Name: r.spec.Name,
				Hint: fmt.Sprintf("configured path %q is not executable", r.path),
			}
		}
		return r.path, nil
	}
	p, err := exec.LookPath(r.spec.Binary)
	if err != nil {
		return "", &ErrNotInstalled{Name: r.spec.Name, Hint: r.spec.InstallHint}
	}
	return p, nil
}

// Available reports whether the tool can be run.
func (r *Runner) Available() bool {
	_, err := r.Resolve()
	return err == nil
}

// Version returns the tool's reported version, or "" if it cannot be read.
// The version goes into run.json, because a finding is only reproducible
// against a known scanner version.
func (r *Runner) Version(ctx context.Context) (string, error) {
	if len(r.spec.VersionArgs) == 0 {
		return "", nil
	}
	bin, err := r.Resolve()
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, r.spec.VersionArgs...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("reading %s version: %w", r.spec.Name, err)
	}

	// Tools print anything from "1.2.3" to a multi-line banner. Take the first
	// non-empty line and let the reader interpret it.
	for _, line := range strings.Split(out.String(), "\n") {
		if s := strings.TrimSpace(line); s != "" {
			return s, nil
		}
	}
	return "", nil
}

// Run invokes the tool in workDir with the given arguments.
//
// The context governs cancellation, so a Ctrl-C during a scan tears down every
// child process rather than orphaning a long-running scanner.
func (r *Runner) Run(ctx context.Context, workDir string, args ...string) (*Result, error) {
	bin, err := r.Resolve()
	if err != nil {
		return nil, err
	}

	full := append(append([]string(nil), args...), r.extraArgs...)

	ctx, cancel := context.WithTimeout(ctx, r.spec.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, full...)
	cmd.Dir = workDir

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Scanner output on a large repo can be tens of megabytes; nothing here
	// streams, so the caller should not point this at an unbounded target.
	start := time.Now()
	runErr := cmd.Run()
	elapsed := time.Since(start)

	res := &Result{
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
		Duration: elapsed,
		Command:  r.spec.Name + " " + strings.Join(full, " "),
	}

	var exitErr *exec.ExitError
	switch {
	case runErr == nil:
		res.ExitCode = 0
	case errors.As(runErr, &exitErr):
		res.ExitCode = exitErr.ExitCode()
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return res, fmt.Errorf("%s timed out after %s", r.spec.Name, r.spec.Timeout)
	case errors.Is(ctx.Err(), context.Canceled):
		return res, ctx.Err()
	default:
		return res, fmt.Errorf("running %s: %w", r.spec.Name, runErr)
	}

	for _, ok := range r.spec.OKExitCodes {
		if res.ExitCode == ok {
			return res, nil
		}
	}
	return res, &ErrFailed{
		Name:     r.spec.Name,
		Args:     full,
		ExitCode: res.ExitCode,
		Stderr:   stderr.String(),
	}
}

// Specs for the tools Vibe Killer wraps.
//
// Exit codes are from each tool's documented behaviour: Semgrep exits 1 when
// it has findings, gitleaks exits 1 when it has leaks, and osv-scanner exits 1
// when it finds a vulnerability. Treating those as failures would throw away
// exactly the runs that matter.
var (
	SemgrepSpec = Spec{
		Name:        "semgrep",
		VersionArgs: []string{"--version"},
		OKExitCodes: []int{0, 1},
		InstallHint: "install with: pipx install semgrep  (or: pip install semgrep)",
	}

	OSVScannerSpec = Spec{
		Name:        "osv-scanner",
		VersionArgs: []string{"--version"},
		OKExitCodes: []int{0, 1},
		InstallHint: "install with: go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest",
		Timeout:     5 * time.Minute,
	}

	GitleaksSpec = Spec{
		Name:        "gitleaks",
		VersionArgs: []string{"version"},
		OKExitCodes: []int{0, 1},
		InstallHint: "install from: https://github.com/gitleaks/gitleaks/releases",
		Timeout:     5 * time.Minute,
	}

	NPMSpec = Spec{
		Name:        "npm",
		VersionArgs: []string{"--version"},
		OKExitCodes: []int{0, 1},
		InstallHint: "install Node.js to enable npm audit",
		Timeout:     5 * time.Minute,
	}

	PipAuditSpec = Spec{
		Name:        "pip-audit",
		VersionArgs: []string{"--version"},
		OKExitCodes: []int{0, 1},
		InstallHint: "install with: pipx install pip-audit",
		Timeout:     5 * time.Minute,
	}
)
