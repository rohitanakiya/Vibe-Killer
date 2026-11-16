// Package orchestrator runs a set of checks against one target.
//
// It is a bounded worker pool over a queue of checks, with every check's
// eligibility decided centrally before it runs, every panic contained so one
// bad check cannot end the scan, and cleanup guaranteed on the way out. A run
// is one process that starts, works, and exits; nothing here schedules,
// persists, or survives the call.
package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"sort"
	"sync"
	"time"

	"github.com/rohitanakiya/Vibe-Killer/internal/check"
	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
	"github.com/rohitanakiya/Vibe-Killer/internal/tool"
)

// DefaultWorkers is the worker count when none is configured.
const DefaultWorkers = 4

// Options configures a run.
type Options struct {
	// Workers is the number of checks executed concurrently. The per-host
	// request rate is governed separately by the HTTP client, so this only
	// bounds CPU and in-flight check state.
	Workers int

	// Progress is called as checks finish, for CLI output. Optional.
	Progress func(Event)
}

// EventKind describes what happened to a check.
type EventKind string

const (
	EventStarted EventKind = "started"
	EventDone    EventKind = "done"
	EventSkipped EventKind = "skipped"
	EventFailed  EventKind = "failed"
)

// Event is one progress notification.
type Event struct {
	Kind     EventKind
	RuleID   string
	Title    string
	Layer    check.Layer
	Findings int
	Elapsed  time.Duration
	Reason   string
	Err      error
}

// Report is the outcome of an orchestrated run.
type Report struct {
	Findings []finding.Finding

	// Skipped records every check that could not run, with the reason. This
	// is part of the result: an operator has to be able to see that the
	// access-control checks were skipped because no tokens were set, rather
	// than reading a clean report as an all-clear.
	Skipped []check.SkipReason

	// Failed records checks that errored.
	Failed []CheckError

	// Ran is how many checks actually executed.
	Ran int

	Elapsed time.Duration
}

// CheckError is a check that failed to complete.
type CheckError struct {
	RuleID string
	Err    error

	// Layer is carried for the same reason SkipReason carries it: a consumer
	// joining a failure to the findings it suppressed cannot do so on rule_id
	// alone, because engine.osv-scanner produces deps.known-vulnerability.
	Layer check.Layer
}

func (c CheckError) String() string { return c.RuleID + ": " + c.Err.Error() }

// Orchestrator executes checks.
type Orchestrator struct {
	opts Options
}

// New builds an Orchestrator.
func New(opts Options) *Orchestrator {
	if opts.Workers <= 0 {
		opts.Workers = DefaultWorkers
	}
	return &Orchestrator{opts: opts}
}

// Run executes the checks and collects their findings.
//
// Cancelling ctx stops the scan: in-flight checks are given the cancelled
// context and the queue drains without starting more. Whatever was found
// before cancellation is still returned, so an interrupted scan is partial
// rather than lost.
func (o *Orchestrator) Run(ctx context.Context, checks []check.Check, env *check.Env) (*Report, error) {
	start := time.Now()
	report := &Report{}

	if len(checks) == 0 {
		report.Elapsed = time.Since(start)
		return report, nil
	}

	// Decide eligibility up front, on the main goroutine, so that the skip
	// list is deterministic and independent of worker scheduling.
	var eligible []check.Check
	for _, c := range checks {
		m := c.Meta()
		ok, reason := check.CanRun(m, env)
		if !ok {
			report.Skipped = append(report.Skipped, check.SkipReason{RuleID: m.RuleID, Layer: m.Layer, Reason: reason})
			o.emit(Event{Kind: EventSkipped, RuleID: m.RuleID, Title: m.Title, Layer: m.Layer, Reason: reason})
			if env.Run != nil {
				env.Run.Log("check.skipped", map[string]any{
					"rule_id": m.RuleID,
					"layer":   string(m.Layer),
					"reason":  reason,
				})
			}
			continue
		}
		eligible = append(eligible, c)
	}

	if len(eligible) == 0 {
		report.Elapsed = time.Since(start)
		return report, nil
	}

	queue := make(chan check.Check)

	var (
		mu       sync.Mutex
		findings []finding.Finding
	)

	workers := o.opts.Workers
	if workers > len(eligible) {
		workers = len(eligible)
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range queue {
				m := c.Meta()

				// A cancelled context drains the queue without starting more
				// work, so Ctrl-C returns promptly.
				if ctx.Err() != nil {
					mu.Lock()
					report.Skipped = append(report.Skipped, check.SkipReason{
						RuleID: m.RuleID, Layer: m.Layer, Reason: "run was cancelled before this check started",
					})
					mu.Unlock()
					continue
				}

				o.emit(Event{Kind: EventStarted, RuleID: m.RuleID, Title: m.Title, Layer: m.Layer})
				checkStart := time.Now()

				fs, err := runOne(ctx, c, env)
				elapsed := time.Since(checkStart)

				mu.Lock()
				report.Ran++
				if err != nil {
					// An absent optional scanner is not a failure, and
					// tool.ErrNotInstalled has said so in its own
					// documentation all along -- "the orchestrator records
					// the scanner as skipped and continues" -- while this
					// branch classified every error the same way. The
					// distinction is not cosmetic: a skip is a deliberate
					// gap the operator can close by installing something,
					// a failure is something broken, and they belong in
					// different sections of the report, carry different
					// SARIF levels, and warrant different responses from a
					// consumer. The error text already carries the install
					// hint, so it makes the reason as it stands.
					var absent *tool.ErrNotInstalled
					if errors.As(err, &absent) {
						reason := err.Error()
						report.Skipped = append(report.Skipped, check.SkipReason{
							RuleID: m.RuleID, Layer: m.Layer, Reason: reason,
						})
						mu.Unlock()

						if env.Run != nil {
							env.Run.Log("check.skipped", map[string]any{
								"rule_id": m.RuleID,
								"layer":   string(m.Layer),
								"reason":  reason,
							})
						}
						o.emit(Event{Kind: EventSkipped, RuleID: m.RuleID, Title: m.Title, Layer: m.Layer, Reason: reason, Elapsed: elapsed})
						continue
					}

					report.Failed = append(report.Failed, CheckError{RuleID: m.RuleID, Layer: m.Layer, Err: err})
					mu.Unlock()

					if env.Run != nil {
						env.Run.Errorf("check %s failed: %v", m.RuleID, err)
					}
					o.emit(Event{Kind: EventFailed, RuleID: m.RuleID, Title: m.Title, Layer: m.Layer, Err: err, Elapsed: elapsed})
					continue
				}
				findings = append(findings, fs...)
				mu.Unlock()

				if env.Run != nil {
					env.Run.Log("check.done", map[string]any{
						"rule_id":  m.RuleID,
						"layer":    string(m.Layer),
						"findings": len(fs),
						"ms":       elapsed.Milliseconds(),
					})
				}
				o.emit(Event{
					Kind: EventDone, RuleID: m.RuleID, Title: m.Title, Layer: m.Layer,
					Findings: len(fs), Elapsed: elapsed,
				})
			}
		}()
	}

	for _, c := range eligible {
		queue <- c
	}
	close(queue)
	wg.Wait()

	// Deterministic output: same repo, same findings, same order, which is
	// what makes the run-to-run diff meaningful.
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		return findings[i].FindingID < findings[j].FindingID
	})

	report.Findings = findings
	report.Elapsed = time.Since(start)
	return report, ctx.Err()
}

// runOne executes a single check with its panic contained.
//
// A check is a plugin. One that panics on an unexpected response shape should
// cost its own finding, not the whole scan, and the operator should see the
// failure rather than a missing result.
func runOne(ctx context.Context, c check.Check, env *check.Env) (fs []finding.Finding, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("check panicked: %v\n%s", r, debug.Stack())
			fs = nil
		}
	}()

	fs, err = c.Detect(ctx, env)
	if err != nil {
		return nil, err
	}

	// A check that emits a finding violating the contract is a bug in that
	// check. Reject it here, named, rather than letting it fail the whole
	// findings.json write at the end of the run.
	for i := range fs {
		if fs[i].FindingID == "" {
			fs[i].AssignID()
		}
		if verr := fs[i].Validate(); verr != nil {
			return nil, fmt.Errorf("check produced an invalid finding: %w", verr)
		}
	}
	return fs, nil
}

func (o *Orchestrator) emit(e Event) {
	if o.opts.Progress != nil {
		o.opts.Progress(e)
	}
}
