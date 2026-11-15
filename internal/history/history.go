// Package history keeps a local record of past runs, so that a finding can be
// tracked across them.
//
// Two things in the findings contract need this. `first_seen_run` and
// `last_seen_run` are claims about history and cannot be filled from a single
// run. And a regression — a finding that was fixed and is now open again — is
// only visible if the tool remembers that it had been fixed; without history,
// a reappearing finding is indistinguishable from a new one, and the
// difference is exactly what a team needs to know.
//
// The store is a SQLite file inside the runs directory. It is pure Go, so the
// binary still installs with `go install` and needs no toolchain. Like
// everything else here it stays on the operator's machine.
package history

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	_ "modernc.org/sqlite"

	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
)

// FileName is the database file, kept alongside the run directories.
const FileName = "history.db"

// Store is the run history.
type Store struct {
	db   *sql.DB
	path string
}

// Open opens or creates the history database under baseDir.
func Open(baseDir string) (*Store, error) {
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating %s: %w", baseDir, err)
	}
	path := filepath.Join(baseDir, FileName)

	// A short busy timeout matters because a CI job may run two scans at
	// once; without it the second fails instead of waiting.
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	// One connection: this is a single-process tool, and SQLite is happier
	// without concurrent writers.
	db.SetMaxOpenConns(1)

	s := &Store{db: db, path: path}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Path returns the database file's location.
func (s *Store) Path() string { return s.path }

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS runs (
    run_id        TEXT PRIMARY KEY,
    started_at    TEXT NOT NULL,
    recorded_at   TEXT NOT NULL,
    repo_path     TEXT,
    repo_rev      TEXT,
    target        TEXT,
    mode          TEXT,
    tool_version  TEXT,
    total         INTEGER NOT NULL DEFAULT 0,
    confirmed     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id  TEXT NOT NULL,
    run_id      TEXT NOT NULL,
    rule_id     TEXT,
    title       TEXT,
    severity    TEXT,
    confidence  TEXT,
    source      TEXT,
    status      TEXT,
    rank        REAL,
    PRIMARY KEY (finding_id, run_id)
);

CREATE INDEX IF NOT EXISTS idx_findings_finding_id ON findings(finding_id);
CREATE INDEX IF NOT EXISTS idx_findings_run_id ON findings(run_id);
`
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("creating the history schema: %w", err)
	}
	return nil
}

// Seen is what the store knows about one finding before this run.
type Seen struct {
	FirstRun string
	LastRun  string

	// LastStatus is the status recorded in the most recent run that saw it.
	LastStatus finding.Status
}

// Lookup returns what is known about a set of finding ids.
func (s *Store) Lookup(ids []string) (map[string]Seen, error) {
	out := map[string]Seen{}
	if len(ids) == 0 {
		return out, nil
	}

	// One statement per id keeps this simple and is fast enough: the id is
	// indexed and a scan has hundreds of findings, not millions.
	stmt, err := s.db.Prepare(`
        SELECT MIN(run_id), MAX(run_id)
        FROM findings WHERE finding_id = ?`)
	if err != nil {
		return nil, fmt.Errorf("preparing the history lookup: %w", err)
	}
	defer stmt.Close()

	statusStmt, err := s.db.Prepare(`
        SELECT status FROM findings
        WHERE finding_id = ?
        ORDER BY run_id DESC LIMIT 1`)
	if err != nil {
		return nil, fmt.Errorf("preparing the status lookup: %w", err)
	}
	defer statusStmt.Close()

	for _, id := range ids {
		var first, last sql.NullString
		if err := stmt.QueryRow(id).Scan(&first, &last); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			return nil, fmt.Errorf("looking up %s: %w", id, err)
		}
		if !first.Valid {
			continue
		}

		seen := Seen{FirstRun: first.String, LastRun: last.String}

		var status sql.NullString
		if err := statusStmt.QueryRow(id).Scan(&status); err == nil && status.Valid {
			seen.LastStatus = finding.Status(status.String)
		}

		out[id] = seen
	}

	return out, nil
}

// Enrich fills in first_seen_run and last_seen_run, and promotes a finding
// that had been recorded as fixed to regressed.
//
// The promotion is the point. A finding that is open, was fixed, and is open
// again is a different fact from a finding that is merely open: it says a fix
// did not hold, which is the signal a regression test would have caught.
func (s *Store) Enrich(runID string, findings []finding.Finding) ([]finding.Finding, error) {
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.FindingID)
	}

	seen, err := s.Lookup(ids)
	if err != nil {
		return findings, err
	}

	out := make([]finding.Finding, len(findings))
	copy(out, findings)

	for i := range out {
		prior, known := seen[out[i].FindingID]
		if !known {
			out[i].FirstSeenRun = runID
			out[i].LastSeenRun = runID
			continue
		}

		out[i].FirstSeenRun = prior.FirstRun
		out[i].LastSeenRun = runID

		if prior.LastStatus == finding.StatusFixed && out[i].Status == finding.StatusOpen {
			out[i].Status = finding.StatusRegressed
		}
		// A decision someone made about this finding is theirs, and a later
		// run must not quietly reopen it.
		if prior.LastStatus == finding.StatusAccepted || prior.LastStatus == finding.StatusFalsePositive {
			out[i].Status = prior.LastStatus
		}
	}

	return out, nil
}

// RunRecord is the run-level row.
type RunRecord struct {
	RunID       string
	StartedAt   string
	RepoPath    string
	RepoRev     string
	Target      string
	Mode        string
	ToolVersion string
	Total       int
	Confirmed   int
}

// Record stores a run and its findings.
//
// Findings that the previous run reported and this one did not are recorded
// against this run as fixed, which is what lets a later reappearance be
// recognized as a regression rather than as something new.
func (s *Store) Record(rec RunRecord, findings []finding.Finding) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("starting the history transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`
        INSERT INTO runs (run_id, started_at, recorded_at, repo_path, repo_rev, target, mode, tool_version, total, confirmed)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(run_id) DO UPDATE SET
            recorded_at = excluded.recorded_at,
            total = excluded.total,
            confirmed = excluded.confirmed`,
		rec.RunID, rec.StartedAt, time.Now().UTC().Format(time.RFC3339),
		rec.RepoPath, rec.RepoRev, rec.Target, rec.Mode, rec.ToolVersion,
		rec.Total, rec.Confirmed,
	); err != nil {
		return fmt.Errorf("recording the run: %w", err)
	}

	insert, err := tx.Prepare(`
        INSERT INTO findings (finding_id, run_id, rule_id, title, severity, confidence, source, status, rank)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(finding_id, run_id) DO UPDATE SET
            status = excluded.status,
            severity = excluded.severity,
            confidence = excluded.confidence,
            rank = excluded.rank`)
	if err != nil {
		return fmt.Errorf("preparing the finding insert: %w", err)
	}
	defer insert.Close()

	present := map[string]bool{}
	for _, f := range findings {
		present[f.FindingID] = true
		if _, err := insert.Exec(
			f.FindingID, rec.RunID, f.RuleID, f.Title,
			string(f.Severity), string(f.Confidence), string(f.Source),
			string(f.Status), f.Rank,
		); err != nil {
			return fmt.Errorf("recording finding %s: %w", f.FindingID, err)
		}
	}

	// Carry forward whatever the previous run reported but this one did not.
	prevID, err := previousRunID(tx, rec.RunID)
	if err != nil {
		return err
	}
	if prevID == "" {
		return tx.Commit()
	}

	rows, err := tx.Query(`
        SELECT finding_id, rule_id, title, severity, confidence, source, status
        FROM findings WHERE run_id = ?`, prevID)
	if err != nil {
		return fmt.Errorf("reading the previous run: %w", err)
	}

	type carried struct {
		id, ruleID, title, severity, confidence, source, status string
	}
	var toFix []carried
	for rows.Next() {
		var c carried
		if err := rows.Scan(&c.id, &c.ruleID, &c.title, &c.severity, &c.confidence, &c.source, &c.status); err != nil {
			_ = rows.Close()
			return fmt.Errorf("reading the previous run: %w", err)
		}
		if present[c.id] {
			continue
		}
		// A finding someone set aside stays set aside; its absence is not a
		// fix, and recording it as one would credit the team with work they
		// deliberately did not do.
		if c.status == string(finding.StatusAccepted) || c.status == string(finding.StatusFalsePositive) {
			toFix = append(toFix, c)
			continue
		}
		c.status = string(finding.StatusFixed)
		toFix = append(toFix, c)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("reading the previous run: %w", err)
	}
	_ = rows.Close()

	for _, c := range toFix {
		if _, err := insert.Exec(
			c.id, rec.RunID, c.ruleID, c.title, c.severity, c.confidence, c.source, c.status, 0.0,
		); err != nil {
			return fmt.Errorf("carrying forward %s: %w", c.id, err)
		}
	}

	return tx.Commit()
}

// previousRunID returns the run recorded immediately before the given one.
// Run ids are timestamp prefixed, so lexical order is chronological order.
func previousRunID(tx *sql.Tx, runID string) (string, error) {
	var prev sql.NullString
	err := tx.QueryRow(`
        SELECT MAX(run_id) FROM runs WHERE run_id < ?`, runID).Scan(&prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("finding the previous run: %w", err)
	}
	if !prev.Valid {
		return "", nil
	}
	return prev.String, nil
}

// Runs lists recorded runs, newest first.
func (s *Store) Runs(limit int) ([]RunRecord, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.Query(`
        SELECT run_id, started_at, repo_path, repo_rev, target, mode, tool_version, total, confirmed
        FROM runs ORDER BY run_id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("listing runs: %w", err)
	}
	defer rows.Close()

	var out []RunRecord
	for rows.Next() {
		var r RunRecord
		var repoPath, repoRev, target, mode, version sql.NullString
		if err := rows.Scan(&r.RunID, &r.StartedAt, &repoPath, &repoRev,
			&target, &mode, &version, &r.Total, &r.Confirmed); err != nil {
			return nil, fmt.Errorf("listing runs: %w", err)
		}
		r.RepoPath, r.RepoRev = repoPath.String, repoRev.String
		r.Target, r.Mode, r.ToolVersion = target.String, mode.String, version.String
		out = append(out, r)
	}
	return out, rows.Err()
}

// Trend is one finding's life across runs.
type Trend struct {
	FindingID string
	RuleID    string
	Title     string
	Severity  string
	Runs      []string
	Statuses  []string
}

// TrendFor returns the recorded history of one finding, oldest first.
func (s *Store) TrendFor(findingID string) (*Trend, error) {
	rows, err := s.db.Query(`
        SELECT run_id, status, rule_id, title, severity
        FROM findings WHERE finding_id = ? ORDER BY run_id ASC`, findingID)
	if err != nil {
		return nil, fmt.Errorf("reading the trend for %s: %w", findingID, err)
	}
	defer rows.Close()

	t := &Trend{FindingID: findingID}
	for rows.Next() {
		var runID, status string
		var ruleID, title, severity sql.NullString
		if err := rows.Scan(&runID, &status, &ruleID, &title, &severity); err != nil {
			return nil, err
		}
		t.Runs = append(t.Runs, runID)
		t.Statuses = append(t.Statuses, status)
		t.RuleID, t.Title, t.Severity = ruleID.String, title.String, severity.String
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(t.Runs) == 0 {
		return nil, fmt.Errorf("finding %s is not in the history", findingID)
	}

	sort.Strings(t.Runs)
	return t, nil
}

// Stats summarizes the whole history.
type Stats struct {
	Runs          int
	UniqueIssues  int
	CurrentlyOpen int
	EverFixed     int
	Regressions   int
}

// Stats computes a summary over all recorded runs.
func (s *Store) Stats() (Stats, error) {
	var st Stats

	if err := s.db.QueryRow(`SELECT COUNT(*) FROM runs`).Scan(&st.Runs); err != nil {
		return st, err
	}
	if err := s.db.QueryRow(`SELECT COUNT(DISTINCT finding_id) FROM findings`).Scan(&st.UniqueIssues); err != nil {
		return st, err
	}
	if err := s.db.QueryRow(`
        SELECT COUNT(DISTINCT finding_id) FROM findings WHERE status = ?`,
		string(finding.StatusFixed)).Scan(&st.EverFixed); err != nil {
		return st, err
	}
	if err := s.db.QueryRow(`
        SELECT COUNT(DISTINCT finding_id) FROM findings WHERE status = ?`,
		string(finding.StatusRegressed)).Scan(&st.Regressions); err != nil {
		return st, err
	}

	// Currently open means open in the most recent run.
	var latest sql.NullString
	if err := s.db.QueryRow(`SELECT MAX(run_id) FROM runs`).Scan(&latest); err != nil {
		return st, err
	}
	if latest.Valid {
		if err := s.db.QueryRow(`
            SELECT COUNT(*) FROM findings WHERE run_id = ? AND status IN (?, ?)`,
			latest.String, string(finding.StatusOpen), string(finding.StatusRegressed),
		).Scan(&st.CurrentlyOpen); err != nil {
			return st, err
		}
	}

	return st, nil
}
