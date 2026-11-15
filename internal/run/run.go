// Package run owns a single scan's on-disk footprint: the run directory, the
// audit log, and the findings document.
//
// Everything a run produces stays inside runs/<id>/ on the operator's own
// machine. Nothing here uploads, reports, or phones anywhere: the only writer
// of run data is the local filesystem, and that is deliberate.
package run

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
)

// DirName is the directory, relative to the working directory, that holds all
// runs.
const DirName = "runs"

// Layout names the files inside a run directory.
const (
	FileFindings = "findings.json"
	FileMeta     = "run.json"
	FileLog      = "run.log"
	FileSurface  = "app_surface.json"
	DirRepro     = "repro"
	DirRaw       = "raw"
)

// Meta is the run's own record of what it did, written to run.json.
type Meta struct {
	RunID     string `json:"run_id"`
	StartedAt string `json:"started_at"`
	EndedAt   string `json:"ended_at,omitempty"`
	Tool      string `json:"tool"`
	Version   string `json:"version"`

	RepoPath string `json:"repo_path"`
	RepoRev  string `json:"repo_rev,omitempty"`

	Mode string `json:"mode"`

	// Target is the instance that was exercised, if any.
	Target string `json:"target,omitempty"`

	// AuthorizedTargets records the declared scope verbatim. A run is only
	// reproducible if you can see what it was allowed to touch.
	AuthorizedTargets []string `json:"authorized_targets,omitempty"`

	// TargetOwnershipAcknowledged records the one-time --i-own-this-target
	// confirmation. The brief requires it in the run log, and it lands here
	// too so a stored run carries its own authorization record.
	TargetOwnershipAcknowledged bool   `json:"target_ownership_acknowledged"`
	AcknowledgedAt              string `json:"target_ownership_acknowledged_at,omitempty"`

	// NonDestructive and DisposableEnv record the posture the run ran under.
	NonDestructive bool `json:"non_destructive"`
	DisposableEnv  bool `json:"disposable_env"`

	RuntimeEnabled bool `json:"runtime_enabled"`

	// ScannersUsed names the external tools that actually ran, with versions,
	// since their versions affect the findings.
	ScannersUsed map[string]string `json:"scanners_used,omitempty"`

	// ScannersSkipped explains any tool that was expected but absent.
	ScannersSkipped map[string]string `json:"scanners_skipped,omitempty"`

	Counts finding.Counts `json:"counts"`

	// RequestCount is how many HTTP requests the run sent, in total.
	RequestCount int `json:"request_count"`

	Errors []string `json:"errors,omitempty"`
}

// Run is a live scan's bookkeeping. It is safe for concurrent use.
type Run struct {
	id   string
	dir  string
	meta Meta

	mu       sync.Mutex
	logFile  *os.File
	cleanups []cleanup
	errs     []string
	requests int
}

type cleanup struct {
	what string
	fn   func() error
}

// NewID mints a sortable, unique run identifier.
func NewID(now time.Time) string {
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		// A run id only needs to be unique on this machine; the timestamp
		// alone is an acceptable fallback.
		return now.UTC().Format("20060102-150405")
	}
	return now.UTC().Format("20060102-150405") + "-" + hex.EncodeToString(b[:])
}

// Create makes a new run directory under baseDir and opens its audit log.
func Create(baseDir string, meta Meta) (*Run, error) {
	if meta.RunID == "" {
		meta.RunID = NewID(time.Now())
	}
	if meta.StartedAt == "" {
		meta.StartedAt = time.Now().UTC().Format(time.RFC3339)
	}

	dir := filepath.Join(baseDir, meta.RunID)
	for _, sub := range []string{"", DirRepro, DirRaw} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			return nil, fmt.Errorf("creating run directory: %w", err)
		}
	}

	logPath := filepath.Join(dir, FileLog)
	lf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("opening run log: %w", err)
	}

	r := &Run{id: meta.RunID, dir: dir, meta: meta, logFile: lf}

	r.Log("run.start", map[string]any{
		"run_id":    meta.RunID,
		"tool":      meta.Tool,
		"version":   meta.Version,
		"mode":      meta.Mode,
		"repo_path": meta.RepoPath,
		"repo_rev":  meta.RepoRev,
	})

	// The authorization record is the first substantive thing in the log, so
	// that reading a run log always begins with what the run was permitted to
	// touch.
	r.Log("scope.declared", map[string]any{
		"authorized_targets":            meta.AuthorizedTargets,
		"target":                        meta.Target,
		"target_ownership_acknowledged": meta.TargetOwnershipAcknowledged,
		"non_destructive":               meta.NonDestructive,
		"disposable_env":                meta.DisposableEnv,
	})

	return r, nil
}

// ID returns the run identifier.
func (r *Run) ID() string { return r.id }

// Dir returns the run directory.
func (r *Run) Dir() string { return r.dir }

// Path joins a path inside the run directory.
func (r *Run) Path(parts ...string) string {
	return filepath.Join(append([]string{r.dir}, parts...)...)
}

// RelPath returns a run-relative path suitable for a finding's
// reproduction.artifact_path.
func (r *Run) RelPath(parts ...string) string {
	return filepath.ToSlash(filepath.Join(append([]string{DirName, r.id}, parts...)...))
}

// LogEntry is one line of the audit log.
type LogEntry struct {
	Time  string         `json:"time"`
	Event string         `json:"event"`
	Data  map[string]any `json:"data,omitempty"`
}

// Log appends a structured line to run.log.
//
// The log is JSON Lines so that it is both greppable by a human and parseable
// by a tool. Every active check records its exact request here.
func (r *Run) Log(event string, data map[string]any) {
	entry := LogEntry{
		Time:  time.Now().UTC().Format(time.RFC3339Nano),
		Event: event,
		Data:  data,
	}
	// HTML escaping is off deliberately. The default encoder turns < and >
	// into < and >, which would render the redaction marker as
	// "<redacted>" and quietly break grepping the log for it. This
	// file is meant to be read by a person as well as a tool.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(entry); err != nil {
		buf.Reset()
		fmt.Fprintf(&buf, "{\"event\":%q,\"error\":\"could not encode log data\"}\n", event)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.logFile == nil {
		return
	}
	_, _ = r.logFile.Write(buf.Bytes())
}

// LogRequest records an HTTP request a check sent. Credential headers are
// redacted before they reach the log, because a run directory is something an
// operator will attach to a ticket.
func (r *Run) LogRequest(ruleID string, req finding.Request, status int, note string) {
	r.mu.Lock()
	r.requests++
	r.mu.Unlock()

	r.Log("http.request", map[string]any{
		"rule_id": ruleID,
		"method":  req.Method,
		"path":    req.Path,
		"auth":    req.Auth,
		"headers": finding.RedactHeaders(req.Headers),
		"status":  status,
		"note":    note,
	})
}

// RequestCount reports how many requests were logged.
func (r *Run) RequestCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.requests
}

// Errorf records a non-fatal run error. A scan continues when one check fails;
// the failure is reported rather than silently dropped, so a partial run is
// never mistaken for a clean one.
func (r *Run) Errorf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	r.mu.Lock()
	r.errs = append(r.errs, msg)
	r.mu.Unlock()
	r.Log("run.error", map[string]any{"message": msg})
}

// Errors returns the recorded non-fatal errors.
func (r *Run) Errors() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.errs...)
}

// Defer registers a cleanup to run at Close. The runtime observer and any
// temporary file registers here, which is how "one run leaves nothing behind"
// is actually enforced rather than merely intended.
func (r *Run) Defer(what string, fn func() error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cleanups = append(r.cleanups, cleanup{what: what, fn: fn})
}

// WriteRaw stores a wrapped scanner's unmodified output under raw/, so a
// finding can always be traced back to what the underlying tool actually said.
func (r *Run) WriteRaw(name string, data []byte) (string, error) {
	path := r.Path(DirRaw, name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", fmt.Errorf("writing raw output %s: %w", name, err)
	}
	r.Log("raw.written", map[string]any{"name": name, "bytes": len(data)})
	return path, nil
}

// WriteRepro stores a replayable artifact for one finding.
func (r *Run) WriteRepro(findingID string, ext string, data []byte) (string, error) {
	name := findingID + ext
	if err := os.WriteFile(r.Path(DirRepro, name), data, 0o644); err != nil {
		return "", fmt.Errorf("writing reproduction artifact for %s: %w", findingID, err)
	}
	return r.RelPath(DirRepro, name), nil
}

// WriteSurface stores the surface mapper's model of the app.
func (r *Run) WriteSurface(v any) error {
	return r.writeJSON(r.Path(FileSurface), v)
}

// WriteFindings writes findings.json, the deliverable of a run and the
// contract consumed by Vibe Giver.
//
// Every finding is validated first. A finding that violates the contract fails
// the write rather than being emitted, because a consumer that cannot trust
// the schema has to re-derive everything itself.
func (r *Run) WriteFindings(fs []finding.Finding) error {
	if err := finding.ValidateAll(fs); err != nil {
		return fmt.Errorf("refusing to write findings.json with contract violations: %w", err)
	}

	doc := finding.Document{
		SchemaVersion: finding.SchemaVersion,
		RunID:         r.id,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		RepoPath:      r.meta.RepoPath,
		RepoRev:       r.meta.RepoRev,
		Target:        r.meta.Target,
		Counts:        finding.Summarize(fs),
		Findings:      fs,
	}

	r.mu.Lock()
	r.meta.Counts = doc.Counts
	r.mu.Unlock()

	if err := r.writeJSON(r.Path(FileFindings), doc); err != nil {
		return err
	}
	r.Log("findings.written", map[string]any{"total": doc.Counts.Total, "confirmed": doc.Counts.Confirmed})
	return nil
}

func (r *Run) writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding %s: %w", filepath.Base(path), err)
	}
	b = append(b, '\n')
	// Write to a temporary file and rename, so a crash cannot leave a
	// half-written findings.json that a consumer would read as truth.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", filepath.Base(path), err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("finalizing %s: %w", filepath.Base(path), err)
	}
	return nil
}

// SetMeta updates run metadata fields discovered during the run.
func (r *Run) SetMeta(fn func(*Meta)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fn(&r.meta)
}

// Meta returns a copy of the run metadata.
func (r *Run) Meta() Meta {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.meta
	m.AuthorizedTargets = append([]string(nil), r.meta.AuthorizedTargets...)
	return m
}

// Close runs every registered cleanup, writes run.json, and closes the log.
//
// Cleanups run in reverse registration order and a failing one does not stop
// the others: the guarantee that a run leaves nothing behind matters more than
// reporting the first problem.
func (r *Run) Close() error {
	r.mu.Lock()
	cleanups := r.cleanups
	r.cleanups = nil
	r.mu.Unlock()

	for i := len(cleanups) - 1; i >= 0; i-- {
		c := cleanups[i]
		if err := c.fn(); err != nil {
			r.Errorf("cleanup %q failed: %v", c.what, err)
			continue
		}
		r.Log("cleanup.done", map[string]any{"what": c.what})
	}

	r.mu.Lock()
	r.meta.EndedAt = time.Now().UTC().Format(time.RFC3339)
	r.meta.RequestCount = r.requests
	r.meta.Errors = append([]string(nil), r.errs...)
	meta := r.meta
	r.mu.Unlock()

	writeErr := r.writeJSON(r.Path(FileMeta), meta)

	r.Log("run.end", map[string]any{
		"run_id":   r.id,
		"requests": meta.RequestCount,
		"errors":   len(meta.Errors),
		"total":    meta.Counts.Total,
	})

	r.mu.Lock()
	lf := r.logFile
	r.logFile = nil
	r.mu.Unlock()
	if lf != nil {
		if err := lf.Close(); err != nil && writeErr == nil {
			writeErr = err
		}
	}
	return writeErr
}

// LoadFindings reads a findings document from a run directory.
func LoadFindings(dir string) (*finding.Document, error) {
	path := filepath.Join(dir, FileFindings)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var doc finding.Document
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if doc.SchemaVersion != finding.SchemaVersion {
		return nil, fmt.Errorf("%s has schema_version %q, but this build speaks %q",
			path, doc.SchemaVersion, finding.SchemaVersion)
	}
	return &doc, nil
}

// LoadMeta reads a run's metadata.
func LoadMeta(dir string) (*Meta, error) {
	b, err := os.ReadFile(filepath.Join(dir, FileMeta))
	if err != nil {
		return nil, err
	}
	var m Meta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parsing run metadata: %w", err)
	}
	return &m, nil
}

// List returns the run ids under baseDir, oldest first. Ids are timestamp
// prefixed, so lexical order is chronological order.
func List(baseDir string) ([]string, error) {
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(baseDir, e.Name(), FileFindings)); err != nil {
			continue
		}
		ids = append(ids, e.Name())
	}
	sort.Strings(ids)
	return ids, nil
}

// Previous returns the run id immediately before the given one, for the
// default run-to-run diff.
func Previous(baseDir, id string) (string, bool) {
	ids, err := List(baseDir)
	if err != nil {
		return "", false
	}
	for i := len(ids) - 1; i >= 0; i-- {
		if ids[i] < id {
			return ids[i], true
		}
	}
	return "", false
}
