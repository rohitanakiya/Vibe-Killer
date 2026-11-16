package diff

import (
	"strings"
	"testing"

	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
)

func f(ruleID, symbol string, sev finding.Severity, conf finding.Confidence, status finding.Status) finding.Finding {
	out := finding.Finding{
		RuleID:     ruleID,
		Title:      ruleID + " in " + symbol,
		Category:   finding.CategoryBrokenAccessControl,
		Severity:   sev,
		Confidence: conf,
		Source:     finding.SourceSAST,
		Location: finding.Location{
			Type: finding.LocationCode, File: "src/app.js", Symbol: symbol,
		},
		Evidence:    finding.Evidence{Summary: "s", EvidenceKey: ruleID + symbol},
		Remediation: finding.Remediation{Guidance: "g", FixableByGiver: true},
		Status:      status,
	}
	if conf == finding.ConfidenceConfirmed {
		out.Reproduction = &finding.Reproduction{Kind: finding.ReproHTTP}
	}
	out.AssignID()
	return out
}

func doc(runID string, findings ...finding.Finding) *finding.Document {
	return &finding.Document{
		SchemaVersion: finding.SchemaVersion,
		RunID:         runID,
		Counts:        finding.Summarize(findings),
		Findings:      findings,
	}
}

func TestCompareClassifiesEveryChange(t *testing.T) {
	stillOpen := f("idor.a", "handlerA", finding.SeverityHigh, finding.ConfidenceLikely, finding.StatusOpen)
	wasFixed := f("idor.b", "handlerB", finding.SeverityHigh, finding.ConfidenceLikely, finding.StatusOpen)
	isNew := f("idor.c", "handlerC", finding.SeverityMedium, finding.ConfidenceLikely, finding.StatusOpen)

	// A finding that had been marked fixed and is reported again.
	regressedBefore := f("idor.d", "handlerD", finding.SeverityHigh, finding.ConfidenceLikely, finding.StatusFixed)
	regressedAfter := f("idor.d", "handlerD", finding.SeverityHigh, finding.ConfidenceLikely, finding.StatusOpen)

	before := doc("run-1", stillOpen, wasFixed, regressedBefore)
	after := doc("run-2", stillOpen, isNew, regressedAfter)

	res := Compare(before, after)

	if res.Counts.StillOpen != 1 || res.StillOpen[0].Finding.FindingID != stillOpen.FindingID {
		t.Errorf("still-open = %+v", res.StillOpen)
	}
	if res.Counts.New != 1 || res.New[0].Finding.FindingID != isNew.FindingID {
		t.Errorf("new = %+v", res.New)
	}
	if res.Counts.Fixed != 1 || res.Fixed[0].Finding.FindingID != wasFixed.FindingID {
		t.Errorf("fixed = %+v", res.Fixed)
	}
	if res.Counts.Regressed != 1 || res.Regressed[0].Finding.FindingID != regressedAfter.FindingID {
		t.Errorf("regressed = %+v", res.Regressed)
	}

	// A fixed finding's status has to be rewritten, since the later run never
	// reported it and so never set it.
	if res.Fixed[0].Finding.Status != finding.StatusFixed {
		t.Errorf("a fixed finding's status = %q", res.Fixed[0].Finding.Status)
	}

	if res.FromRun != "run-1" || res.ToRun != "run-2" {
		t.Errorf("run ids = %s -> %s", res.FromRun, res.ToRun)
	}
}

// A finding someone reviewed and accepted is not a fix. Counting it as one
// would make the diff congratulate the team for a decision to live with it.
func TestAcceptedAndFalsePositiveFindingsAreNotCountedAsFixed(t *testing.T) {
	accepted := f("idor.a", "handlerA", finding.SeverityHigh, finding.ConfidenceLikely, finding.StatusAccepted)
	falsePositive := f("idor.b", "handlerB", finding.SeverityHigh, finding.ConfidenceLikely, finding.StatusFalsePositive)
	alreadyFixed := f("idor.c", "handlerC", finding.SeverityHigh, finding.ConfidenceLikely, finding.StatusFixed)

	res := Compare(doc("run-1", accepted, falsePositive, alreadyFixed), doc("run-2"))

	if res.Counts.Fixed != 0 {
		t.Errorf("fixed = %d, want 0: none of these were fixed in this run", res.Counts.Fixed)
	}
}

// A finding that moved from likely to confirmed has not got worse; it has been
// proven. The diff should surface that rather than hide it.
func TestConfidenceAndSeverityChangesAreSurfaced(t *testing.T) {
	before := f("idor.a", "handlerA", finding.SeverityMedium, finding.ConfidenceLikely, finding.StatusOpen)
	after := f("idor.a", "handlerA", finding.SeverityHigh, finding.ConfidenceConfirmed, finding.StatusOpen)

	res := Compare(doc("run-1", before), doc("run-2", after))

	if res.Counts.StillOpen != 1 {
		t.Fatalf("still-open = %d", res.Counts.StillOpen)
	}
	e := res.StillOpen[0]
	if e.PreviousSeverity != finding.SeverityMedium {
		t.Errorf("previous severity = %q", e.PreviousSeverity)
	}
	if e.PreviousConfidence != finding.ConfidenceLikely {
		t.Errorf("previous confidence = %q", e.PreviousConfidence)
	}
}

func TestUnchangedFindingsReportNoDelta(t *testing.T) {
	same := f("idor.a", "handlerA", finding.SeverityHigh, finding.ConfidenceLikely, finding.StatusOpen)

	res := Compare(doc("run-1", same), doc("run-2", same))
	if res.StillOpen[0].PreviousSeverity != "" || res.StillOpen[0].PreviousConfidence != "" {
		t.Errorf("a delta was reported for an unchanged finding: %+v", res.StillOpen[0])
	}
}

// Fixing nine things and introducing one critical has not made the
// application safer, and the summary should not say otherwise.
func TestProgressIsConservative(t *testing.T) {
	tests := []struct {
		name       string
		before     []finding.Finding
		after      []finding.Finding
		wantWord   string
		wantBetter bool
	}{
		{
			name:       "all fixed",
			before:     []finding.Finding{f("a", "h1", finding.SeverityHigh, finding.ConfidenceLikely, finding.StatusOpen)},
			after:      nil,
			wantWord:   "clean",
			wantBetter: true,
		},
		{
			name: "some fixed, some open",
			before: []finding.Finding{
				f("a", "h1", finding.SeverityHigh, finding.ConfidenceLikely, finding.StatusOpen),
				f("b", "h2", finding.SeverityHigh, finding.ConfidenceLikely, finding.StatusOpen),
			},
			after:      []finding.Finding{f("b", "h2", finding.SeverityHigh, finding.ConfidenceLikely, finding.StatusOpen)},
			wantWord:   "better",
			wantBetter: true,
		},
		{
			name:       "fixed nine, introduced one",
			before:     []finding.Finding{f("a", "h1", finding.SeverityHigh, finding.ConfidenceLikely, finding.StatusOpen)},
			after:      []finding.Finding{f("b", "h2", finding.SeverityCritical, finding.ConfidenceConfirmed, finding.StatusOpen)},
			wantWord:   "mixed",
			wantBetter: false,
		},
		{
			name:       "something new",
			before:     nil,
			after:      []finding.Finding{f("a", "h1", finding.SeverityHigh, finding.ConfidenceLikely, finding.StatusOpen)},
			wantWord:   "worse",
			wantBetter: false,
		},
		{
			name:       "nothing at all",
			before:     nil,
			after:      nil,
			wantWord:   "no findings",
			wantBetter: true,
		},
		{
			name:       "unchanged",
			before:     []finding.Finding{f("a", "h1", finding.SeverityHigh, finding.ConfidenceLikely, finding.StatusOpen)},
			after:      []finding.Finding{f("a", "h1", finding.SeverityHigh, finding.ConfidenceLikely, finding.StatusOpen)},
			wantWord:   "unchanged",
			wantBetter: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := Compare(doc("run-1", tc.before...), doc("run-2", tc.after...))

			if !strings.Contains(res.Progress(), tc.wantWord) {
				t.Errorf("Progress() = %q, want it to mention %q", res.Progress(), tc.wantWord)
			}
			if res.Improved() != tc.wantBetter {
				t.Errorf("Improved() = %v, want %v", res.Improved(), tc.wantBetter)
			}
		})
	}
}

// A regression outranks any amount of fixing in the summary, because it is the
// signal that a fix did not hold.
func TestRegressionDominatesTheSummary(t *testing.T) {
	wasFixed := f("a", "h1", finding.SeverityHigh, finding.ConfidenceLikely, finding.StatusFixed)
	isBack := f("a", "h1", finding.SeverityHigh, finding.ConfidenceLikely, finding.StatusOpen)
	alsoFixed := f("b", "h2", finding.SeverityHigh, finding.ConfidenceLikely, finding.StatusOpen)

	res := Compare(doc("run-1", wasFixed, alsoFixed), doc("run-2", isBack))

	if !strings.Contains(res.Progress(), "regressed") {
		t.Errorf("Progress() = %q, want the regression to lead", res.Progress())
	}
	if res.Improved() {
		t.Error("Improved() = true although a previously-fixed finding is open again")
	}
}

// The diff rests entirely on finding_id being stable for the same issue. If an
// unrelated edit shifted ids, every run would look like a rewrite.
func TestDiffSurvivesLineChurn(t *testing.T) {
	before := f("idor.a", "handlerA", finding.SeverityHigh, finding.ConfidenceLikely, finding.StatusOpen)

	after := before
	after.Location.Line = 999
	after.Location.RepoRev = "newsha"
	after.AssignID()

	res := Compare(doc("run-1", before), doc("run-2", after))
	if res.Counts.StillOpen != 1 {
		t.Errorf("an unrelated line shift was reported as %d new and %d fixed, want one still-open",
			res.Counts.New, res.Counts.Fixed)
	}
}

func TestEntriesAreOrderedByRank(t *testing.T) {
	low := f("a", "h1", finding.SeverityLow, finding.ConfidenceHeuristic, finding.StatusOpen)
	low.Rank = 1
	high := f("b", "h2", finding.SeverityCritical, finding.ConfidenceConfirmed, finding.StatusOpen)
	high.Rank = 16

	res := Compare(doc("run-1"), doc("run-2", low, high))
	if len(res.New) != 2 {
		t.Fatalf("new = %d", len(res.New))
	}
	if res.New[0].Finding.Rank < res.New[1].Finding.Rank {
		t.Error("new findings are not ordered worst first")
	}
}

// withSource builds a finding attributed to a particular engine, which is what
// the layer half of the skip join matches on.
func withSource(ruleID, symbol string, src finding.Source) finding.Finding {
	out := f(ruleID, symbol, finding.SeverityHigh, finding.ConfidenceLikely, finding.StatusOpen)
	out.Source = src
	out.AssignID()
	return out
}

func docWithSkips(runID string, skips []finding.SkippedCheck, findings ...finding.Finding) *finding.Document {
	d := doc(runID, findings...)
	d.Skipped = skips
	return d
}

// The defect this guards: absence was read as a fix with no regard for whether
// anything looked. A run that skipped a check reported its findings as fixed
// and the verdict line said "better".
func TestAFindingIsNotFixedWhenItsCheckWasSkipped(t *testing.T) {
	open := f("idor.a", "handlerA", finding.SeverityHigh, finding.ConfidenceLikely, finding.StatusOpen)

	from := doc("run-1", open)
	to := docWithSkips("run-2", []finding.SkippedCheck{{
		CheckID: "idor.a",
		Layer:   "endpoint",
		Reason:  "no running instance was given (pass --target)",
	}})

	res := Compare(from, to)

	if res.Counts.Fixed != 0 {
		t.Errorf("fixed = %d, want 0: the check never ran", res.Counts.Fixed)
	}
	if res.Counts.Unchecked != 1 {
		t.Fatalf("unchecked = %d, want 1", res.Counts.Unchecked)
	}
	if r := res.Unchecked[0].Reason; !strings.Contains(r, "--target") {
		t.Errorf("skip reason = %q, want the reason carried through", r)
	}
	// The status is left alone. Marking it fixed was the bug; marking it
	// anything else would be inventing a different claim.
	if got := res.Unchecked[0].Finding.Status; got != finding.StatusOpen {
		t.Errorf("status = %q, want it untouched", got)
	}
}

// A scanner's rule_id is not the rule_id of its findings: engine.osv-scanner
// produces deps.known-vulnerability. Joining on rule_id alone would miss the
// likeliest real case, a scanner binary absent on a CI box.
func TestAScannerSkipIsJoinedThroughItsLayer(t *testing.T) {
	vuln := withSource("deps.known-vulnerability", "lodash", finding.SourceDeps)

	from := doc("run-1", vuln)
	to := docWithSkips("run-2", []finding.SkippedCheck{{
		CheckID: "engine.osv-scanner",
		Layer:   "deps",
		Reason:  "osv-scanner is not installed or not on PATH",
	}})

	res := Compare(from, to)

	if res.Counts.Unchecked != 1 || res.Counts.Fixed != 0 {
		t.Fatalf("unchecked = %d, fixed = %d, want 1 and 0", res.Counts.Unchecked, res.Counts.Fixed)
	}
	if r := res.Unchecked[0].Reason; !strings.Contains(r, "osv-scanner") {
		t.Errorf("skip reason = %q, want it to name the missing scanner", r)
	}
}

// The layer join must not swallow real fixes. When a layer is only partly
// skipped and still produced findings, its producers evidently ran, so a
// finding that vanished from it is a fix and must be reported as one.
func TestAPartlySkippedLayerStillReportsRealFixes(t *testing.T) {
	gone := withSource("dast.one", "handlerA", finding.SourceDAST)
	stayed := withSource("dast.two", "handlerB", finding.SourceDAST)

	from := doc("run-1", gone, stayed)
	to := docWithSkips("run-2", []finding.SkippedCheck{{
		CheckID: "misconfig.verbose-error",
		Layer:   "endpoint",
		Reason:  "the application surface was not mapped",
	}}, stayed)

	res := Compare(from, to)

	if res.Counts.Fixed != 1 {
		t.Errorf("fixed = %d, want 1: the endpoint layer still produced findings, so this one was really fixed", res.Counts.Fixed)
	}
	if res.Counts.Unchecked != 0 {
		t.Errorf("unchecked = %d, want 0", res.Counts.Unchecked)
	}
}

// A run directory written before the skipped array existed carries no skip
// list. Inventing uncertainty about it would be its own dishonesty, so the
// old reading stands.
func TestADocumentWithNoSkipListBehavesAsBefore(t *testing.T) {
	open := f("idor.a", "handlerA", finding.SeverityHigh, finding.ConfidenceLikely, finding.StatusOpen)

	res := Compare(doc("run-1", open), doc("run-2"))

	if res.Counts.Fixed != 1 || res.Counts.Unchecked != 0 {
		t.Errorf("fixed = %d, unchecked = %d, want 1 and 0", res.Counts.Fixed, res.Counts.Unchecked)
	}
}

// --fail-on-new gates on Improved(). Before this, a CI run that checked less
// than the previous one passed precisely because coverage had vanished.
func TestUncheckedFindingsBlockTheImprovedGate(t *testing.T) {
	open := f("idor.a", "handlerA", finding.SeverityHigh, finding.ConfidenceLikely, finding.StatusOpen)

	res := Compare(doc("run-1", open), docWithSkips("run-2", []finding.SkippedCheck{{
		CheckID: "idor.a", Layer: "endpoint", Reason: "no running instance was given (pass --target)",
	}}))

	if res.Improved() {
		t.Error("Improved() = true, want false: nothing re-checked this finding")
	}
	if p := res.Progress(); !strings.Contains(p, "inconclusive") {
		t.Errorf("Progress() = %q, want it to refuse a verdict", p)
	}
}

// Issue #2: a check that ran and broke established no more than one that never
// ran, but only skips were consulted, so a scanner crashing between runs read
// as every one of its findings being fixed.
func TestAFindingIsNotFixedWhenItsCheckFailed(t *testing.T) {
	vuln := withSource("deps.known-vulnerability", "lodash", finding.SourceDeps)

	from := doc("run-1", vuln)
	to := doc("run-2")
	to.Failed = []finding.FailedCheck{{
		CheckID: "engine.osv-scanner",
		Layer:   "deps",
		Error:   "osv-scanner exited with status 2: could not resolve lockfile",
	}}

	res := Compare(from, to)

	if res.Counts.Fixed != 0 {
		t.Errorf("fixed = %d, want 0: the scanner crashed", res.Counts.Fixed)
	}
	if res.Counts.Unchecked != 1 {
		t.Fatalf("unchecked = %d, want 1", res.Counts.Unchecked)
	}
	r := res.Unchecked[0].Reason
	if !strings.Contains(r, "failed") || !strings.Contains(r, "status 2") {
		t.Errorf("reason = %q, want it to say the check failed and carry the error", r)
	}
	if res.Improved() {
		t.Error("Improved() = true, want false when a check failed")
	}
}

// Skips and failures arrive together in a partly broken run, and both have to
// be honoured rather than whichever is consulted first.
func TestSkippedAndFailedChecksAreBothHonoured(t *testing.T) {
	skippedOne := f("idor.a", "handlerA", finding.SeverityHigh, finding.ConfidenceLikely, finding.StatusOpen)
	failedOne := withSource("deps.known-vulnerability", "lodash", finding.SourceDeps)

	from := doc("run-1", skippedOne, failedOne)
	to := doc("run-2")
	to.Skipped = []finding.SkippedCheck{{CheckID: "idor.a", Layer: "endpoint", Reason: "no running instance was given (pass --target)"}}
	to.Failed = []finding.FailedCheck{{CheckID: "engine.osv-scanner", Layer: "deps", Error: "exited with status 2"}}

	res := Compare(from, to)

	if res.Counts.Unchecked != 2 || res.Counts.Fixed != 0 {
		t.Fatalf("unchecked = %d, fixed = %d, want 2 and 0", res.Counts.Unchecked, res.Counts.Fixed)
	}
}
