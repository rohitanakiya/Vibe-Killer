package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rohitanakiya/Vibe-Killer/internal/check"
	"github.com/rohitanakiya/Vibe-Killer/internal/config"
	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
	"github.com/rohitanakiya/Vibe-Killer/internal/run"
	"github.com/rohitanakiya/Vibe-Killer/internal/surface"
	"github.com/rohitanakiya/Vibe-Killer/internal/tool"
)

// stubCheck is a check whose behaviour the test controls.
type stubCheck struct {
	meta     check.Meta
	findings []finding.Finding
	err      error
	panics   bool
	delay    time.Duration
	calls    *int32
	inFlight *int32
	maxSeen  *int32
}

func (s *stubCheck) Meta() check.Meta { return s.meta }

func (s *stubCheck) Detect(ctx context.Context, env *check.Env) ([]finding.Finding, error) {
	if s.calls != nil {
		atomic.AddInt32(s.calls, 1)
	}
	if s.inFlight != nil {
		now := atomic.AddInt32(s.inFlight, 1)
		defer atomic.AddInt32(s.inFlight, -1)
		for {
			max := atomic.LoadInt32(s.maxSeen)
			if now <= max || atomic.CompareAndSwapInt32(s.maxSeen, max, now) {
				break
			}
		}
	}
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if s.panics {
		panic("this check is broken")
	}
	return s.findings, s.err
}

func meta(ruleID string, layer check.Layer) check.Meta {
	return check.Meta{RuleID: ruleID, Title: ruleID, Layer: layer, Category: finding.CategoryInjection}
}

func validFinding(ruleID string) finding.Finding {
	f := finding.Finding{
		RuleID: ruleID, Title: "t", Category: finding.CategoryInjection,
		Severity: finding.SeverityHigh, Confidence: finding.ConfidenceLikely,
		Source: finding.SourceSAST, Status: finding.StatusOpen,
		Location:    finding.Location{Type: finding.LocationCode, File: "a.js", Symbol: ruleID},
		Evidence:    finding.Evidence{Summary: "s"},
		Remediation: finding.Remediation{Guidance: "g", FixableByGiver: true},
	}
	f.AssignID()
	return f
}

func testEnv(t *testing.T) *check.Env {
	t.Helper()
	cfg := config.Defaults()
	r, err := run.Create(t.TempDir(), run.Meta{RunID: "test", Tool: "vibekiller"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return &check.Env{Config: &cfg, Run: r, RepoRoot: t.TempDir()}
}

func TestRunCollectsFindingsFromEveryCheck(t *testing.T) {
	env := testEnv(t)
	o := New(Options{Workers: 2})

	checks := []check.Check{
		&stubCheck{meta: meta("a.one", check.LayerStatic), findings: []finding.Finding{validFinding("a.one")}},
		&stubCheck{meta: meta("b.two", check.LayerStatic), findings: []finding.Finding{validFinding("b.two")}},
		&stubCheck{meta: meta("c.three", check.LayerStatic)},
	}

	report, err := o.Run(context.Background(), checks, env)
	if err != nil {
		t.Fatal(err)
	}
	if report.Ran != 3 {
		t.Errorf("ran = %d, want 3", report.Ran)
	}
	if len(report.Findings) != 2 {
		t.Errorf("findings = %d, want 2", len(report.Findings))
	}
	if len(report.Failed) != 0 {
		t.Errorf("failed = %v", report.Failed)
	}
}

// A check is a plugin. One that panics on an unexpected response shape should
// cost its own finding, not the whole scan, and the operator should see the
// failure rather than a silently missing result.
func TestAPanickingCheckDoesNotEndTheScan(t *testing.T) {
	env := testEnv(t)
	o := New(Options{Workers: 2})

	checks := []check.Check{
		&stubCheck{meta: meta("a.good", check.LayerStatic), findings: []finding.Finding{validFinding("a.good")}},
		&stubCheck{meta: meta("b.broken", check.LayerStatic), panics: true},
		&stubCheck{meta: meta("c.good", check.LayerStatic), findings: []finding.Finding{validFinding("c.good")}},
	}

	report, err := o.Run(context.Background(), checks, env)
	if err != nil {
		t.Fatal(err)
	}

	if len(report.Findings) != 2 {
		t.Errorf("findings = %d, want the two working checks' results", len(report.Findings))
	}
	if len(report.Failed) != 1 {
		t.Fatalf("failed = %v, want the panicking check reported", report.Failed)
	}
	if report.Failed[0].RuleID != "b.broken" {
		t.Errorf("failed check = %q", report.Failed[0].RuleID)
	}
	// The stack has to be in the error, or the bug is undiagnosable.
	if !strings.Contains(report.Failed[0].Err.Error(), "panicked") {
		t.Errorf("error = %v", report.Failed[0].Err)
	}
}

func TestAFailingCheckIsReportedNotFatal(t *testing.T) {
	env := testEnv(t)
	o := New(Options{Workers: 1})

	sentinel := errors.New("semgrep is not installed")
	checks := []check.Check{
		&stubCheck{meta: meta("a.fails", check.LayerStatic), err: sentinel},
		&stubCheck{meta: meta("b.works", check.LayerStatic), findings: []finding.Finding{validFinding("b.works")}},
	}

	report, err := o.Run(context.Background(), checks, env)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Failed) != 1 || !errors.Is(report.Failed[0].Err, sentinel) {
		t.Errorf("failed = %v", report.Failed)
	}
	if len(report.Findings) != 1 {
		t.Errorf("the working check's finding was lost")
	}
}

// A check that emits a finding violating the contract is a bug in that check,
// and it must be named rather than failing the whole findings.json write at
// the end of the run.
func TestAnInvalidFindingFailsItsOwnCheck(t *testing.T) {
	env := testEnv(t)
	o := New(Options{Workers: 1})

	// Confirmed with no reproduction: the contract forbids it.
	bad := validFinding("a.liar")
	bad.Confidence = finding.ConfidenceConfirmed
	bad.Reproduction = nil

	checks := []check.Check{
		&stubCheck{meta: meta("a.liar", check.LayerStatic), findings: []finding.Finding{bad}},
		&stubCheck{meta: meta("b.honest", check.LayerStatic), findings: []finding.Finding{validFinding("b.honest")}},
	}

	report, err := o.Run(context.Background(), checks, env)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Failed) != 1 {
		t.Fatalf("failed = %v, want the invalid finding's check reported", report.Failed)
	}
	if !strings.Contains(report.Failed[0].Err.Error(), "invalid finding") {
		t.Errorf("error = %v", report.Failed[0].Err)
	}
	if len(report.Findings) != 1 {
		t.Errorf("the valid finding was lost along with the invalid one")
	}
}

// A skip is part of the result. A scan that quietly ran half its checks is
// worse than one that says what it could not do.
func TestIneligibleChecksAreSkippedWithAReason(t *testing.T) {
	env := testEnv(t)
	o := New(Options{Workers: 2})

	needsTarget := meta("a.dynamic", check.LayerEndpoint)
	needsTarget.NeedsTarget = true

	checks := []check.Check{
		&stubCheck{meta: needsTarget},
		&stubCheck{meta: meta("b.static", check.LayerStatic), findings: []finding.Finding{validFinding("b.static")}},
	}

	report, err := o.Run(context.Background(), checks, env)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Skipped) != 1 {
		t.Fatalf("skipped = %v", report.Skipped)
	}
	if report.Skipped[0].RuleID != "a.dynamic" {
		t.Errorf("skipped the wrong check: %q", report.Skipped[0].RuleID)
	}
	// The reason must tell the operator how to enable it.
	if !strings.Contains(report.Skipped[0].Reason, "--target") {
		t.Errorf("skip reason = %q, want it to name the flag", report.Skipped[0].Reason)
	}
	if report.Ran != 1 {
		t.Errorf("ran = %d, want only the eligible check", report.Ran)
	}
}

// Eligibility is decided before any worker starts, so the skip list does not
// depend on scheduling.
func TestSkipListIsDeterministic(t *testing.T) {
	env := testEnv(t)

	build := func() []check.Check {
		var out []check.Check
		for i := 0; i < 6; i++ {
			m := meta(fmt.Sprintf("x.check%d", i), check.LayerEndpoint)
			m.NeedsTarget = true
			out = append(out, &stubCheck{meta: m})
		}
		return out
	}

	var first []string
	for attempt := 0; attempt < 5; attempt++ {
		report, err := New(Options{Workers: 4}).Run(context.Background(), build(), env)
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, s := range report.Skipped {
			ids = append(ids, s.RuleID)
		}
		if attempt == 0 {
			first = ids
			continue
		}
		if strings.Join(ids, ",") != strings.Join(first, ",") {
			t.Fatalf("skip order varies between runs:\n%v\n%v", first, ids)
		}
	}
}

// Deterministic output is what makes the run-to-run diff meaningful.
func TestFindingOrderIsDeterministic(t *testing.T) {
	env := testEnv(t)

	build := func() []check.Check {
		var out []check.Check
		for _, id := range []string{"z.last", "a.first", "m.middle"} {
			out = append(out, &stubCheck{
				meta:     meta(id, check.LayerStatic),
				findings: []finding.Finding{validFinding(id)},
				delay:    time.Duration(len(id)) * time.Millisecond,
			})
		}
		return out
	}

	var first []string
	for attempt := 0; attempt < 5; attempt++ {
		report, err := New(Options{Workers: 3}).Run(context.Background(), build(), env)
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, f := range report.Findings {
			ids = append(ids, f.RuleID)
		}
		if attempt == 0 {
			first = ids
			if len(ids) != 3 {
				t.Fatalf("findings = %v", ids)
			}
			// Sorted by rule id, regardless of which check finished first.
			if ids[0] != "a.first" {
				t.Errorf("findings are not in rule-id order: %v", ids)
			}
			continue
		}
		if strings.Join(ids, ",") != strings.Join(first, ",") {
			t.Fatalf("finding order varies between runs:\n%v\n%v", first, ids)
		}
	}
}

func TestWorkerCountBoundsConcurrency(t *testing.T) {
	env := testEnv(t)

	var inFlight, maxSeen int32
	var checks []check.Check
	for i := 0; i < 12; i++ {
		checks = append(checks, &stubCheck{
			meta:     meta(fmt.Sprintf("x.check%02d", i), check.LayerStatic),
			delay:    20 * time.Millisecond,
			inFlight: &inFlight,
			maxSeen:  &maxSeen,
		})
	}

	if _, err := New(Options{Workers: 3}).Run(context.Background(), checks, env); err != nil {
		t.Fatal(err)
	}

	if got := atomic.LoadInt32(&maxSeen); got > 3 {
		t.Errorf("%d checks ran concurrently with Workers=3", got)
	}
}

// An interrupted scan should be partial, not lost.
func TestCancellationReturnsWhatWasAlreadyFound(t *testing.T) {
	env := testEnv(t)

	ctx, cancel := context.WithCancel(context.Background())

	var checks []check.Check
	checks = append(checks, &stubCheck{
		meta:     meta("a.quick", check.LayerStatic),
		findings: []finding.Finding{validFinding("a.quick")},
	})
	for i := 0; i < 8; i++ {
		checks = append(checks, &stubCheck{
			meta:  meta(fmt.Sprintf("z.slow%d", i), check.LayerStatic),
			delay: 2 * time.Second,
		})
	}

	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	report, err := New(Options{Workers: 1}).Run(ctx, checks, env)
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if elapsed > 5*time.Second {
		t.Errorf("cancellation took %s to drain", elapsed)
	}
	// The quick check ran first and its finding must survive.
	if len(report.Findings) == 0 {
		t.Error("a cancelled run discarded the findings it had already collected")
	}
}

func TestProgressEventsAreEmitted(t *testing.T) {
	env := testEnv(t)

	var kinds []EventKind
	o := New(Options{Workers: 1, Progress: func(e Event) {
		kinds = append(kinds, e.Kind)
	}})

	needsTarget := meta("c.skipped", check.LayerEndpoint)
	needsTarget.NeedsTarget = true

	checks := []check.Check{
		&stubCheck{meta: meta("a.ok", check.LayerStatic), findings: []finding.Finding{validFinding("a.ok")}},
		&stubCheck{meta: meta("b.broken", check.LayerStatic), panics: true},
		&stubCheck{meta: needsTarget},
	}

	if _, err := o.Run(context.Background(), checks, env); err != nil {
		t.Fatal(err)
	}

	seen := map[EventKind]bool{}
	for _, k := range kinds {
		seen[k] = true
	}
	for _, want := range []EventKind{EventStarted, EventDone, EventFailed, EventSkipped} {
		if !seen[want] {
			t.Errorf("no %s event was emitted (got %v)", want, kinds)
		}
	}
}

func TestEmptyCheckListIsNotAnError(t *testing.T) {
	env := testEnv(t)

	report, err := New(Options{}).Run(context.Background(), nil, env)
	if err != nil {
		t.Fatal(err)
	}
	if report.Ran != 0 || len(report.Findings) != 0 {
		t.Errorf("report = %+v", report)
	}
}

func TestFindingsGetIDsAssignedIfTheCheckForgot(t *testing.T) {
	env := testEnv(t)

	// A check that built a finding but never called AssignID.
	bare := finding.Finding{
		RuleID: "a.forgetful", Title: "t", Category: finding.CategoryInjection,
		Severity: finding.SeverityLow, Confidence: finding.ConfidenceHeuristic,
		Source: finding.SourceSAST, Status: finding.StatusOpen,
		Location:    finding.Location{Type: finding.LocationCode, File: "a.js"},
		Evidence:    finding.Evidence{Summary: "s"},
		Remediation: finding.Remediation{Guidance: "g", FixableByGiver: true},
	}

	report, err := New(Options{}).Run(context.Background(),
		[]check.Check{&stubCheck{meta: meta("a.forgetful", check.LayerStatic), findings: []finding.Finding{bare}}},
		env)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %d; the orchestrator should have filled in the id", len(report.Findings))
	}
	if report.Findings[0].FindingID == "" {
		t.Error("the finding still has no id")
	}
}

func TestCheckErrorStringNamesTheRule(t *testing.T) {
	e := CheckError{RuleID: "a.rule", Err: errors.New("boom")}
	if !strings.Contains(e.String(), "a.rule") || !strings.Contains(e.String(), "boom") {
		t.Errorf("String() = %q", e.String())
	}
}

// The skip has to reach the report, not merely the gate. An operator learns
// what went unchecked from the report, and for a framework whose routes this
// tool cannot extract that line is the only signal they get that the endpoint
// layer covered nothing.
func TestSurfaceWithNoRoutesIsReportedAsASkip(t *testing.T) {
	env := testEnv(t)
	env.Surface = &surface.Surface{Stack: surface.Stack{Language: "python", Framework: "django"}}
	o := New(Options{Workers: 2})

	needsSurface := meta("a.endpoint", check.LayerEndpoint)
	needsSurface.NeedsSurface = true

	checks := []check.Check{
		&stubCheck{meta: needsSurface},
		&stubCheck{meta: meta("b.static", check.LayerStatic), findings: []finding.Finding{validFinding("b.static")}},
	}

	report, err := o.Run(context.Background(), checks, env)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Skipped) != 1 || report.Skipped[0].RuleID != "a.endpoint" {
		t.Fatalf("skipped = %v, want exactly the check that needs routes", report.Skipped)
	}
	if r := report.Skipped[0].Reason; !strings.Contains(r, "django") || !strings.Contains(r, "no routes") {
		t.Errorf("skip reason = %q, want it to name the framework and the empty route list", r)
	}
	if report.Ran != 1 {
		t.Errorf("ran = %d, want only the check that does not need routes", report.Ran)
	}
}

// An optional scanner that is not installed is a coverage gap, not a broken
// scan. tool.ErrNotInstalled documented that the orchestrator "records the
// scanner as skipped and continues" long before this branch existed; every
// error was classified as a failure instead, so a CI box without semgrep
// reported a failing check rather than a missing one.
func TestAnAbsentScannerIsSkippedNotFailed(t *testing.T) {
	env := testEnv(t)
	o := New(Options{Workers: 2})

	absent := &stubCheck{
		meta: meta("engine.semgrep", check.LayerStatic),
		err:  &tool.ErrNotInstalled{Name: "semgrep", Hint: "install with: pipx install semgrep"},
	}
	broken := &stubCheck{
		meta: meta("engine.osv-scanner", check.LayerDeps),
		err:  errors.New("osv-scanner exited with status 2"),
	}

	report, err := o.Run(context.Background(), []check.Check{absent, broken}, env)
	if err != nil {
		t.Fatal(err)
	}

	if len(report.Skipped) != 1 || report.Skipped[0].RuleID != "engine.semgrep" {
		t.Fatalf("skipped = %v, want just the absent scanner", report.Skipped)
	}
	// The reason has to be actionable, and the error text already carries the
	// install hint.
	if r := report.Skipped[0].Reason; !strings.Contains(r, "not installed") || !strings.Contains(r, "pipx install semgrep") {
		t.Errorf("skip reason = %q, want it to name the tool and how to install it", r)
	}
	if report.Skipped[0].Layer != check.LayerStatic {
		t.Errorf("layer = %q, want it carried so the skip can be joined to its findings", report.Skipped[0].Layer)
	}

	// A real failure must still be a failure, or this change would trade one
	// misclassification for another.
	if len(report.Failed) != 1 || report.Failed[0].RuleID != "engine.osv-scanner" {
		t.Fatalf("failed = %v, want just the broken scanner", report.Failed)
	}
}

// The sibling of TestAnAbsentScannerIsSkippedNotFailed, and the same defect by
// a third route.
//
// A scanner the operator switched off used to return (nil, nil), which the
// orchestrator could only read as a scan that ran and found nothing. So a
// layer that was deliberately turned off was recorded as a layer that came
// back clean: nothing in findings.json said it had not run, the report listed
// it under neither heading, and diff called its findings fixed on the next
// run. tool.ErrDisabled makes it tellable, and this asserts the three things
// that follow from that.
func TestADisabledScannerIsSkippedAndNotCountedAsRun(t *testing.T) {
	env := testEnv(t)
	o := New(Options{Workers: 2})

	disabled := &stubCheck{
		meta: meta("engine.gitleaks", check.LayerSecrets),
		err: fmt.Errorf("%w (scanners.gitleaks.disabled in vibekiller.config.yaml)",
			tool.ErrDisabled),
	}
	ran := &stubCheck{
		meta:     meta("engine.semgrep", check.LayerStatic),
		findings: []finding.Finding{validFinding("vk-ran")},
	}
	broken := &stubCheck{
		meta: meta("engine.osv-scanner", check.LayerDeps),
		err:  errors.New("osv-scanner exited with status 2"),
	}

	report, err := o.Run(context.Background(), []check.Check{disabled, ran, broken}, env)
	if err != nil {
		t.Fatal(err)
	}

	if len(report.Skipped) != 1 || report.Skipped[0].RuleID != "engine.gitleaks" {
		t.Fatalf("skipped = %v, want just the disabled scanner", report.Skipped)
	}
	// The reason doubles as the instruction for turning it back on, so it has
	// to name the key and the file rather than only the fact.
	if r := report.Skipped[0].Reason; !strings.Contains(r, "disabled") ||
		!strings.Contains(r, "scanners.gitleaks.disabled") {
		t.Errorf("skip reason = %q, want it to name the config key that switched it off", r)
	}
	if report.Skipped[0].Layer != check.LayerSecrets {
		t.Errorf("layer = %q, want it carried so the skip can be joined to its findings", report.Skipped[0].Layer)
	}

	// Switching a scanner off is not a failure, and a real failure is still
	// one, or this would trade one misclassification for another.
	if len(report.Failed) != 1 || report.Failed[0].RuleID != "engine.osv-scanner" {
		t.Fatalf("failed = %v, want just the broken scanner", report.Failed)
	}

	// A check that did not run has no business in the total that says how many
	// did. The one that ran and the one that broke both did.
	if report.Ran != 2 {
		t.Errorf("ran = %d, want 2: the check that succeeded and the one that broke, "+
			"but not the one that never started", report.Ran)
	}
}
