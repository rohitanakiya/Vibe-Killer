package run

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
)

func create(t *testing.T, meta Meta) (*Run, string) {
	t.Helper()
	base := t.TempDir()
	if meta.Tool == "" {
		meta.Tool = "vibekiller"
	}
	r, err := Create(base, meta)
	if err != nil {
		t.Fatal(err)
	}
	return r, base
}

func validFinding(symbol string) finding.Finding {
	f := finding.Finding{
		RuleID: "idor.missing-ownership-check", Title: "t",
		Category: finding.CategoryBrokenAccessControl,
		Severity: finding.SeverityHigh, Confidence: finding.ConfidenceLikely,
		Source: finding.SourceSAST, Status: finding.StatusOpen,
		Location:    finding.Location{Type: finding.LocationCode, File: "a.js", Symbol: symbol},
		Evidence:    finding.Evidence{Summary: "s"},
		Remediation: finding.Remediation{Guidance: "g", FixableByGiver: true},
	}
	f.AssignID()
	return f
}

func TestCreateMakesTheRunLayout(t *testing.T) {
	r, base := create(t, Meta{RunID: "20260101-000000-aaa"})
	defer func() { _ = r.Close() }()

	if r.ID() != "20260101-000000-aaa" {
		t.Errorf("id = %q", r.ID())
	}
	if r.Dir() != filepath.Join(base, "20260101-000000-aaa") {
		t.Errorf("dir = %q", r.Dir())
	}

	for _, sub := range []string{DirRepro, DirRaw} {
		if _, err := os.Stat(r.Path(sub)); err != nil {
			t.Errorf("%s was not created: %v", sub, err)
		}
	}
	if _, err := os.Stat(r.Path(FileLog)); err != nil {
		t.Errorf("the run log was not opened: %v", err)
	}

	// A run-relative path is what goes into a finding's artifact_path, and it
	// has to use forward slashes whatever the platform.
	rel := r.RelPath(DirRepro, "vk-abc.http")
	if rel != "runs/20260101-000000-aaa/repro/vk-abc.http" {
		t.Errorf("RelPath = %q", rel)
	}
}

func TestNewIDIsSortableAndUnique(t *testing.T) {
	now := time.Date(2026, 11, 15, 10, 30, 0, 0, time.UTC)

	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		id := NewID(now)
		if !strings.HasPrefix(id, "20261115-103000") {
			t.Fatalf("id %q does not carry a sortable timestamp prefix", id)
		}
		if seen[id] {
			t.Fatalf("id %q repeated", id)
		}
		seen[id] = true
	}

	// Lexical order has to be chronological order, since the history and the
	// diff both rely on it.
	earlier := NewID(now)
	later := NewID(now.Add(time.Second))
	if earlier >= later {
		t.Errorf("%q is not lexically before %q", earlier, later)
	}
}

// The authorization record is the first substantive thing in the log, so that
// reading a run log always begins with what the run was permitted to touch.
func TestTheLogOpensWithTheDeclaredScope(t *testing.T) {
	r, _ := create(t, Meta{
		RunID:                       "20260101-000000-aaa",
		Target:                      "http://localhost:3000",
		AuthorizedTargets:           []string{"http://localhost:3000"},
		TargetOwnershipAcknowledged: true,
		NonDestructive:              true,
	})
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	entries := readLog(t, r.Path(FileLog))
	if len(entries) < 2 {
		t.Fatalf("the log has %d entries", len(entries))
	}
	if entries[0].Event != "run.start" {
		t.Errorf("first event = %q", entries[0].Event)
	}
	if entries[1].Event != "scope.declared" {
		t.Errorf("second event = %q, want the scope record", entries[1].Event)
	}
	if ack, _ := entries[1].Data["target_ownership_acknowledged"].(bool); !ack {
		t.Error("the acknowledgement was not recorded in the log")
	}
}

type logEntry struct {
	Event string         `json:"event"`
	Data  map[string]any `json:"data"`
}

func readLog(t *testing.T, path string) []logEntry {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []logEntry
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var e logEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("the log is not valid JSON Lines: %v\n%s", err, line)
		}
		out = append(out, e)
	}
	return out
}

// A run directory gets attached to tickets, so a credential must never reach
// the log.
func TestLogRequestRedactsCredentials(t *testing.T) {
	r, _ := create(t, Meta{RunID: "20260101-000000-aaa"})

	r.LogRequest("idor.sequential-id-access", finding.Request{
		Method: "GET", Path: "/api/orders/90001", Auth: "userA-token",
		Headers: map[string]string{
			"Authorization": "Bearer super-secret-value",
			"Accept":        "application/json",
		},
	}, 200, "probe")

	if r.RequestCount() != 1 {
		t.Errorf("request count = %d", r.RequestCount())
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(r.Path(FileLog))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "super-secret-value") {
		t.Fatal("a credential reached the run log")
	}
	if !strings.Contains(string(raw), finding.RedactedMarker) {
		t.Error("the credential header was not recorded as redacted")
	}
	// The identity used still has to be visible, or the evidence is useless.
	if !strings.Contains(string(raw), "userA-token") {
		t.Error("the seeded-user label was not recorded")
	}
}

// The guarantee that a run leaves nothing behind depends on cleanups actually
// running, in reverse order, with a failure in one not stopping the others.
func TestCleanupsRunInReverseOrderAndSurviveFailures(t *testing.T) {
	r, _ := create(t, Meta{RunID: "20260101-000000-aaa"})

	var order []string
	r.Defer("first", func() error { order = append(order, "first"); return nil })
	r.Defer("second", func() error {
		order = append(order, "second")
		return errors.New("this one fails")
	})
	r.Defer("third", func() error { order = append(order, "third"); return nil })

	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	want := []string{"third", "second", "first"}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Errorf("cleanup order = %v, want %v", order, want)
	}

	// The failure has to be reported, not swallowed.
	meta, err := LoadMeta(r.Dir())
	if err != nil {
		t.Fatal(err)
	}
	var sawFailure bool
	for _, e := range meta.Errors {
		if strings.Contains(e, "second") {
			sawFailure = true
		}
	}
	if !sawFailure {
		t.Errorf("the failing cleanup was not reported: %v", meta.Errors)
	}
}

// A consumer that cannot trust the schema has to re-derive everything itself,
// so a contract violation fails the write rather than being emitted.
func TestWriteFindingsRefusesContractViolations(t *testing.T) {
	r, _ := create(t, Meta{RunID: "20260101-000000-aaa"})
	defer func() { _ = r.Close() }()

	bad := validFinding("handlerA")
	bad.Confidence = finding.ConfidenceConfirmed // confirmed with no reproduction

	err := r.WriteFindings([]finding.Finding{bad})
	if err == nil {
		t.Fatal("findings.json was written with a contract violation in it")
	}
	if !strings.Contains(err.Error(), "refusing to write") {
		t.Errorf("error = %v", err)
	}
	if _, statErr := os.Stat(r.Path(FileFindings)); statErr == nil {
		t.Error("a findings.json was created despite the refusal")
	}
}

func TestWriteAndLoadFindings(t *testing.T) {
	r, _ := create(t, Meta{
		RunID: "20260101-000000-aaa", RepoPath: "/repo", RepoRev: "abc123",
		Target: "http://localhost:3000",
	})

	in := []finding.Finding{validFinding("handlerA"), validFinding("handlerB")}
	if err := r.WriteFindings(in); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	doc, err := LoadFindings(r.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if doc.RunID != "20260101-000000-aaa" {
		t.Errorf("run id = %q", doc.RunID)
	}
	if doc.Counts.Total != 2 {
		t.Errorf("counts = %+v", doc.Counts)
	}
	if doc.RepoRev != "abc123" || doc.Target != "http://localhost:3000" {
		t.Errorf("document context lost: %+v", doc)
	}

	// The run metadata should carry the counts too, for a CI job that reads
	// only run.json.
	meta, err := LoadMeta(r.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if meta.Counts.Total != 2 {
		t.Errorf("meta counts = %+v", meta.Counts)
	}
	if meta.EndedAt == "" {
		t.Error("ended_at was not set on close")
	}
}

// A crash must not leave a half-written findings.json that a consumer would
// read as truth, so the write goes via a temporary file and a rename.
func TestWritesAreAtomic(t *testing.T) {
	r, _ := create(t, Meta{RunID: "20260101-000000-aaa"})

	if err := r.WriteFindings([]finding.Finding{validFinding("handlerA")}); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(r.Dir())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("a temporary file was left behind: %s", e.Name())
		}
	}
}

func TestLoadFindingsRejectsAnUnknownSchemaVersion(t *testing.T) {
	dir := t.TempDir()
	doc := `{"schema_version":"99.0","run_id":"x","findings":[]}`
	if err := os.WriteFile(filepath.Join(dir, FileFindings), []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadFindings(dir)
	if err == nil {
		t.Fatal("a document from a future schema version was accepted")
	}
	if !strings.Contains(err.Error(), "schema_version") {
		t.Errorf("error = %v", err)
	}
}

func TestWriteRawAndRepro(t *testing.T) {
	r, _ := create(t, Meta{RunID: "20260101-000000-aaa"})
	defer func() { _ = r.Close() }()

	if _, err := r.WriteRaw("semgrep.json", []byte(`{"results":[]}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(r.Path(DirRaw, "semgrep.json")); err != nil {
		t.Errorf("raw output was not stored: %v", err)
	}

	rel, err := r.WriteRepro("vk-abc123def456", ".http", []byte("GET /api/x\n"))
	if err != nil {
		t.Fatal(err)
	}
	if rel != "runs/20260101-000000-aaa/repro/vk-abc123def456.http" {
		t.Errorf("artifact path = %q", rel)
	}
	if _, err := os.Stat(r.Path(DirRepro, "vk-abc123def456.http")); err != nil {
		t.Errorf("the artifact was not stored: %v", err)
	}
}

func TestWriteSurface(t *testing.T) {
	r, _ := create(t, Meta{RunID: "20260101-000000-aaa"})
	defer func() { _ = r.Close() }()

	if err := r.WriteSurface(map[string]any{"routes": []string{"GET /api/x"}}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(r.Path(FileSurface))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "GET /api/x") {
		t.Errorf("surface = %s", data)
	}
}

// A partial run must not be mistaken for a clean one, so a non-fatal error is
// recorded rather than dropped.
func TestErrorsAreRecorded(t *testing.T) {
	r, _ := create(t, Meta{RunID: "20260101-000000-aaa"})

	r.Errorf("check %s failed: %v", "engine.semgrep", errors.New("not installed"))

	if got := r.Errors(); len(got) != 1 || !strings.Contains(got[0], "engine.semgrep") {
		t.Errorf("errors = %v", got)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	meta, err := LoadMeta(r.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.Errors) != 1 {
		t.Errorf("meta errors = %v", meta.Errors)
	}
}

func TestSetMetaAndMetaCopy(t *testing.T) {
	r, _ := create(t, Meta{RunID: "20260101-000000-aaa", AuthorizedTargets: []string{"http://localhost:3000"}})
	defer func() { _ = r.Close() }()

	r.SetMeta(func(m *Meta) { m.ScannersUsed = map[string]string{"semgrep": "1.2.3"} })

	got := r.Meta()
	if got.ScannersUsed["semgrep"] != "1.2.3" {
		t.Errorf("meta = %+v", got)
	}

	// Meta returns a copy, so a caller cannot mutate the run's own slice.
	got.AuthorizedTargets[0] = "http://evil.invalid"
	if r.Meta().AuthorizedTargets[0] != "http://localhost:3000" {
		t.Error("Meta exposed the run's own slice")
	}
}

func TestListAndPrevious(t *testing.T) {
	base := t.TempDir()

	ids := []string{"20260101-000000-aaa", "20260102-000000-bbb", "20260103-000000-ccc"}
	for _, id := range ids {
		r, err := Create(base, Meta{RunID: id, Tool: "vibekiller"})
		if err != nil {
			t.Fatal(err)
		}
		if err := r.WriteFindings(nil); err != nil {
			t.Fatal(err)
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
	}

	// A directory with no findings.json is not a run.
	if err := os.MkdirAll(filepath.Join(base, "not-a-run"), 0o755); err != nil {
		t.Fatal(err)
	}

	listed, err := List(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 3 {
		t.Fatalf("listed %v", listed)
	}
	if listed[0] != ids[0] {
		t.Errorf("runs are not oldest first: %v", listed)
	}

	prev, ok := Previous(base, ids[2])
	if !ok || prev != ids[1] {
		t.Errorf("Previous(%s) = %q, %v", ids[2], prev, ok)
	}
	if _, ok := Previous(base, ids[0]); ok {
		t.Error("Previous returned something before the first run")
	}
}

func TestListOnAMissingDirectory(t *testing.T) {
	got, err := List(filepath.Join(t.TempDir(), "nope"))
	if err != nil {
		t.Errorf("List on a missing directory returned %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %v", got)
	}
}

func TestCloseIsSafeTwice(t *testing.T) {
	r, _ := create(t, Meta{RunID: "20260101-000000-aaa"})

	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	// A second Close must not panic, since a deferred Close may follow an
	// explicit one.
	if err := r.Close(); err != nil {
		t.Errorf("the second Close returned %v", err)
	}
	// And logging after close must not panic either.
	r.Log("after.close", map[string]any{"x": 1})
}
