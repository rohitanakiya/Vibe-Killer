package history

import (
	"path/filepath"
	"testing"

	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func mk(ruleID, symbol string, status finding.Status) finding.Finding {
	f := finding.Finding{
		RuleID:      ruleID,
		Title:       ruleID + " in " + symbol,
		Category:    finding.CategoryBrokenAccessControl,
		Severity:    finding.SeverityHigh,
		Confidence:  finding.ConfidenceLikely,
		Source:      finding.SourceSAST,
		Location:    finding.Location{Type: finding.LocationCode, File: "src/app.js", Symbol: symbol},
		Evidence:    finding.Evidence{Summary: "s", EvidenceKey: ruleID + symbol},
		Remediation: finding.Remediation{Guidance: "g", FixableByGiver: true},
		Status:      status,
	}
	f.AssignID()
	return f
}

func record(t *testing.T, s *Store, runID string, findings ...finding.Finding) []finding.Finding {
	t.Helper()

	enriched, err := s.Enrich(runID, findings)
	if err != nil {
		t.Fatal(err)
	}
	counts := finding.Summarize(enriched)
	if err := s.Record(RunRecord{
		RunID: runID, StartedAt: runID, Mode: "static-only",
		Total: counts.Total, Confirmed: counts.Confirmed,
	}, enriched); err != nil {
		t.Fatal(err)
	}
	return enriched
}

func TestOpenCreatesTheDatabase(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	if s.Path() != filepath.Join(dir, FileName) {
		t.Errorf("path = %q", s.Path())
	}
	// Opening twice must be fine: a second scan has to be able to append.
	again, err := Open(dir)
	if err != nil {
		t.Fatalf("reopening failed: %v", err)
	}
	_ = again.Close()
}

func TestFirstSeenIsPreservedAcrossRuns(t *testing.T) {
	s := open(t)
	f := mk("idor.a", "handlerA", finding.StatusOpen)

	first := record(t, s, "20260101-000000-aaa", f)
	if first[0].FirstSeenRun != "20260101-000000-aaa" {
		t.Errorf("first_seen_run = %q on a first sighting", first[0].FirstSeenRun)
	}
	if first[0].LastSeenRun != "20260101-000000-aaa" {
		t.Errorf("last_seen_run = %q", first[0].LastSeenRun)
	}

	second := record(t, s, "20260102-000000-bbb", f)
	if second[0].FirstSeenRun != "20260101-000000-aaa" {
		t.Errorf("first_seen_run = %q, want the original run: this is the same issue",
			second[0].FirstSeenRun)
	}
	if second[0].LastSeenRun != "20260102-000000-bbb" {
		t.Errorf("last_seen_run = %q, want the current run", second[0].LastSeenRun)
	}
}

// The reason this package exists: a finding that was fixed and is open again
// is a different fact from one that is merely open, and only history can tell
// them apart.
func TestAReappearingFindingIsMarkedRegressed(t *testing.T) {
	s := open(t)
	f := mk("idor.a", "handlerA", finding.StatusOpen)
	other := mk("idor.b", "handlerB", finding.StatusOpen)

	// Run 1: both open.
	record(t, s, "20260101-000000-aaa", f, other)

	// Run 2: f is gone, so Record carries it forward as fixed.
	record(t, s, "20260102-000000-bbb", other)

	// Run 3: f is back.
	third := record(t, s, "20260103-000000-ccc", f, other)

	var regressed, plainOpen int
	for _, got := range third {
		switch got.Status {
		case finding.StatusRegressed:
			regressed++
			if got.FindingID != f.FindingID {
				t.Errorf("the wrong finding was marked regressed: %s", got.FindingID)
			}
		case finding.StatusOpen:
			plainOpen++
		}
	}

	if regressed != 1 {
		t.Errorf("regressed = %d, want 1", regressed)
	}
	if plainOpen != 1 {
		t.Errorf("open = %d, want 1: the finding that never went away is not a regression", plainOpen)
	}
}

func TestAFindingThatNeverWentAwayIsNotARegression(t *testing.T) {
	s := open(t)
	f := mk("idor.a", "handlerA", finding.StatusOpen)

	record(t, s, "20260101-000000-aaa", f)
	record(t, s, "20260102-000000-bbb", f)
	third := record(t, s, "20260103-000000-ccc", f)

	if third[0].Status != finding.StatusOpen {
		t.Errorf("status = %q, want open: it was never recorded fixed", third[0].Status)
	}
}

// A decision someone made about a finding is theirs. A later run must not
// quietly reopen it, or the triage would have to be redone every scan.
func TestAcceptedAndFalsePositiveDecisionsSurviveLaterRuns(t *testing.T) {
	for _, decision := range []finding.Status{finding.StatusAccepted, finding.StatusFalsePositive} {
		t.Run(string(decision), func(t *testing.T) {
			s := open(t)

			accepted := mk("idor.a", "handlerA", decision)
			record(t, s, "20260101-000000-aaa", accepted)

			// The next run reports it as open, as a scanner always would.
			stillThere := mk("idor.a", "handlerA", finding.StatusOpen)
			second := record(t, s, "20260102-000000-bbb", stillThere)

			if second[0].Status != decision {
				t.Errorf("status = %q, want the recorded decision %q", second[0].Status, decision)
			}
		})
	}
}

// An accepted finding's absence is not a fix: recording it as one would credit
// the team with work they deliberately did not do.
func TestAnAcceptedFindingIsNotCarriedForwardAsFixed(t *testing.T) {
	s := open(t)

	accepted := mk("idor.a", "handlerA", finding.StatusAccepted)
	other := mk("idor.b", "handlerB", finding.StatusOpen)
	record(t, s, "20260101-000000-aaa", accepted, other)

	// Run 2 reports neither.
	record(t, s, "20260102-000000-bbb")

	trend, err := s.TrendFor(accepted.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	last := trend.Statuses[len(trend.Statuses)-1]
	if last == string(finding.StatusFixed) {
		t.Error("an accepted finding was carried forward as fixed")
	}

	// The ordinary one should have been.
	otherTrend, err := s.TrendFor(other.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	if otherTrend.Statuses[len(otherTrend.Statuses)-1] != string(finding.StatusFixed) {
		t.Errorf("an open finding that disappeared was not recorded fixed: %v", otherTrend.Statuses)
	}
}

func TestLookupOnAnEmptyStore(t *testing.T) {
	s := open(t)

	got, err := s.Lookup([]string{"vk-000000000000"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %v, want nothing known", got)
	}

	if got, err := s.Lookup(nil); err != nil || len(got) != 0 {
		t.Errorf("Lookup(nil) = %v, %v", got, err)
	}
}

func TestEnrichOnAnEmptyStoreSetsBothRunsToTheCurrentOne(t *testing.T) {
	s := open(t)
	f := mk("idor.a", "handlerA", finding.StatusOpen)

	out, err := s.Enrich("run-1", []finding.Finding{f})
	if err != nil {
		t.Fatal(err)
	}
	if out[0].FirstSeenRun != "run-1" || out[0].LastSeenRun != "run-1" {
		t.Errorf("first=%q last=%q", out[0].FirstSeenRun, out[0].LastSeenRun)
	}
	// Enrich must not mutate its input.
	if f.FirstSeenRun != "" {
		t.Error("Enrich mutated its input slice")
	}
}

func TestRecordIsIdempotentForTheSameRun(t *testing.T) {
	s := open(t)
	f := mk("idor.a", "handlerA", finding.StatusOpen)

	record(t, s, "20260101-000000-aaa", f)
	record(t, s, "20260101-000000-aaa", f)

	runs, err := s.Runs(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 {
		t.Errorf("got %d runs, want 1: recording the same run twice must not duplicate it", len(runs))
	}

	trend, err := s.TrendFor(f.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	if len(trend.Runs) != 1 {
		t.Errorf("the finding appears %d times for one run", len(trend.Runs))
	}
}

func TestRunsAreListedNewestFirst(t *testing.T) {
	s := open(t)
	f := mk("idor.a", "handlerA", finding.StatusOpen)

	for _, id := range []string{"20260101-000000-aaa", "20260102-000000-bbb", "20260103-000000-ccc"} {
		record(t, s, id, f)
	}

	runs, err := s.Runs(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 3 {
		t.Fatalf("got %d runs", len(runs))
	}
	if runs[0].RunID != "20260103-000000-ccc" {
		t.Errorf("runs are not newest first: %s came first", runs[0].RunID)
	}

	// The limit has to be honoured, or a long history floods the output.
	limited, err := s.Runs(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(limited) != 2 {
		t.Errorf("limit was ignored: got %d", len(limited))
	}
}

func TestStats(t *testing.T) {
	s := open(t)
	a := mk("idor.a", "handlerA", finding.StatusOpen)
	b := mk("idor.b", "handlerB", finding.StatusOpen)

	record(t, s, "20260101-000000-aaa", a, b)
	record(t, s, "20260102-000000-bbb", b)    // a is fixed
	record(t, s, "20260103-000000-ccc", a, b) // a regresses

	st, err := s.Stats()
	if err != nil {
		t.Fatal(err)
	}

	if st.Runs != 3 {
		t.Errorf("runs = %d, want 3", st.Runs)
	}
	if st.UniqueIssues != 2 {
		t.Errorf("unique issues = %d, want 2", st.UniqueIssues)
	}
	if st.CurrentlyOpen != 2 {
		t.Errorf("currently open = %d, want 2", st.CurrentlyOpen)
	}
	if st.EverFixed != 1 {
		t.Errorf("ever fixed = %d, want 1", st.EverFixed)
	}
	if st.Regressions != 1 {
		t.Errorf("regressions = %d, want 1", st.Regressions)
	}
}

func TestTrendForUnknownFinding(t *testing.T) {
	s := open(t)
	if _, err := s.TrendFor("vk-000000000000"); err == nil {
		t.Error("expected an error for a finding that is not in the history")
	}
}

func TestTrendRecordsTheWholeSequence(t *testing.T) {
	s := open(t)
	a := mk("idor.a", "handlerA", finding.StatusOpen)

	record(t, s, "20260101-000000-aaa", a)
	record(t, s, "20260102-000000-bbb")
	record(t, s, "20260103-000000-ccc", a)

	trend, err := s.TrendFor(a.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	if len(trend.Runs) != 3 {
		t.Fatalf("trend covers %d runs, want 3: %v", len(trend.Runs), trend.Statuses)
	}

	want := []string{"open", "fixed", "regressed"}
	for i, w := range want {
		if trend.Statuses[i] != w {
			t.Errorf("status %d = %q, want %q (full sequence: %v)", i, trend.Statuses[i], w, trend.Statuses)
		}
	}
}
