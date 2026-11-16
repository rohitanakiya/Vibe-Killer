// Package finding defines the Vibe Killer findings contract: the typed model
// behind schema/finding.schema.json. This is the stable interface consumed by
// Vibe Giver, so changes here are schema changes and must bump SchemaVersion.
package finding

import "fmt"

// SchemaVersion is the version of schema/finding.schema.json this model matches.
const SchemaVersion = "1.0"

// DocumentSchemaVersion is the version of the findings.json envelope,
// Document, which is versioned separately from the findings it carries.
//
// The two began equal and are now deliberately apart. Adding the optional
// skipped array changed the envelope and no finding field, and the
// per-finding version is pinned by "const": "1.0" in
// schema/finding.schema.json -- so moving that value would invalidate every
// document ever written, to describe a change that did not touch a finding.
const DocumentSchemaVersion = "1.1"

// SupportedDocumentSchemaVersions are the envelope versions this build reads.
//
// Older run directories stay usable, which is what keeps `vibekiller diff`
// working across an upgrade. A 1.0 document simply has no skipped list, and
// the diff is explicit about what it cannot conclude from one.
var SupportedDocumentSchemaVersions = []string{"1.0", DocumentSchemaVersion}

// Severity ranks how bad a finding is if exploited.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// severityOrder gives each severity a comparable weight. Used for ranking and
// for the CI severity gate.
var severityOrder = map[Severity]int{
	SeverityInfo:     0,
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

// Weight returns the comparable weight of a severity, and false if the value
// is not a known severity.
func (s Severity) Weight() (int, bool) {
	w, ok := severityOrder[s]
	return w, ok
}

// AtLeast reports whether s is as severe as threshold.
func (s Severity) AtLeast(threshold Severity) bool {
	sw, ok := severityOrder[s]
	if !ok {
		return false
	}
	tw, ok := severityOrder[threshold]
	if !ok {
		return false
	}
	return sw >= tw
}

// ParseSeverity validates a severity string.
func ParseSeverity(s string) (Severity, error) {
	sev := Severity(s)
	if _, ok := severityOrder[sev]; !ok {
		return "", fmt.Errorf("unknown severity %q (want one of: info, low, medium, high, critical)", s)
	}
	return sev, nil
}

// Confidence records how sure Vibe Killer is that the finding is real.
//
// Confirmed is reserved for findings reproduced by an actual non-destructive
// check against the running instance. Nothing else may claim it.
type Confidence string

const (
	ConfidenceHeuristic Confidence = "heuristic"
	ConfidenceLikely    Confidence = "likely"
	ConfidenceConfirmed Confidence = "confirmed"
)

var confidenceOrder = map[Confidence]int{
	ConfidenceHeuristic: 0,
	ConfidenceLikely:    1,
	ConfidenceConfirmed: 2,
}

// Weight returns the comparable weight of a confidence level.
func (c Confidence) Weight() (int, bool) {
	w, ok := confidenceOrder[c]
	return w, ok
}

// Source names the engine that produced a finding.
type Source string

const (
	SourceSAST        Source = "sast"
	SourceDAST        Source = "dast"
	SourceRuntime     Source = "runtime"
	SourceDeps        Source = "deps"
	SourceSecrets     Source = "secrets"
	SourceBlastRadius Source = "blast-radius"
)

// Category is the OWASP-aligned bucket a finding belongs to.
type Category string

const (
	CategoryBrokenAccessControl Category = "broken-access-control"
	CategoryCryptoFailure       Category = "cryptographic-failure"
	CategoryInjection           Category = "injection"
	CategoryInsecureDesign      Category = "insecure-design"
	CategoryMisconfiguration    Category = "security-misconfiguration"
	CategoryVulnerableDep       Category = "vulnerable-dependency"
	CategoryAuthFailure         Category = "identification-and-authentication-failure"
	CategoryIntegrityFailure    Category = "software-and-data-integrity-failure"
	CategoryLoggingFailure      Category = "logging-and-monitoring-failure"
	CategorySSRF                Category = "server-side-request-forgery"
	CategorySecretsExposure     Category = "secrets-exposure"
	CategoryCrossService        Category = "cross-service-exposure"
)

// Status tracks a finding across runs.
type Status string

const (
	StatusOpen          Status = "open"
	StatusFixed         Status = "fixed"
	StatusRegressed     Status = "regressed"
	StatusAccepted      Status = "accepted"
	StatusFalsePositive Status = "false_positive"
)

// LocationType says what kind of thing a finding points at.
type LocationType string

const (
	LocationCode       LocationType = "code"
	LocationEndpoint   LocationType = "endpoint"
	LocationDependency LocationType = "dependency"
	LocationConfig     LocationType = "config"
)

// Location points at the thing that is wrong.
//
// RepoRev is informational only and is deliberately excluded from the stable
// finding_id, as are Line and EndLine: an unrelated edit above the vulnerable
// line must not make the same issue look new.
type Location struct {
	Type      LocationType `json:"type"`
	File      string       `json:"file,omitempty"`
	Line      int          `json:"line,omitempty"`
	EndLine   int          `json:"end_line,omitempty"`
	Symbol    string       `json:"symbol,omitempty"`
	Endpoint  string       `json:"endpoint,omitempty"`
	Package   string       `json:"package,omitempty"`
	Ecosystem string       `json:"ecosystem,omitempty"`
	Version   string       `json:"version,omitempty"`
	ConfigKey string       `json:"config_key,omitempty"`
	RepoRev   string       `json:"repo_rev,omitempty"`
}

// TaintStep is one hop in a source-to-sink data-flow path.
type TaintStep struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Symbol string `json:"symbol,omitempty"`
	Note   string `json:"note"`
}

// Request records exactly what a dynamic check sent, for auditability.
//
// Auth holds a seeded-user label such as "userA-token", never a token value:
// run artifacts are written to disk and must stay safe to attach to a ticket.
type Request struct {
	Method  string            `json:"method,omitempty"`
	Path    string            `json:"path,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
	Auth    string            `json:"auth,omitempty"`
}

// Evidence is why Vibe Killer believes the finding is real.
type Evidence struct {
	Summary   string      `json:"summary"`
	Request   *Request    `json:"request,omitempty"`
	Observed  string      `json:"observed,omitempty"`
	Expected  string      `json:"expected,omitempty"`
	Snippet   string      `json:"snippet,omitempty"`
	TaintPath []TaintStep `json:"taint_path,omitempty"`

	// EvidenceKey distinguishes two findings of the same rule at the same
	// location, for example two different CVEs on one package. It is part of
	// the stable finding_id.
	EvidenceKey string `json:"evidence_key,omitempty"`
}

// ReproKind is how a finding is re-verified.
type ReproKind string

const (
	ReproHTTP   ReproKind = "http"
	ReproScript ReproKind = "script"
	ReproStatic ReproKind = "static"
)

// Reproduction tells a human, or Vibe Giver, how to see the issue again.
type Reproduction struct {
	Kind         ReproKind `json:"kind"`
	Command      string    `json:"command,omitempty"`
	Steps        []string  `json:"steps,omitempty"`
	ArtifactPath string    `json:"artifact_path,omitempty"`
}

// BlastRadius describes cross-service exposure. Scope is always
// declared-targets-only: the analyzer never reaches past the operator's
// declared hosts.
type BlastRadius struct {
	ReachableFrom string   `json:"reachable_from"`
	Reached       []string `json:"reached"`
	Scope         string   `json:"scope"`
}

// ScopeDeclaredOnly is the only legal BlastRadius scope.
const ScopeDeclaredOnly = "declared-targets-only"

// Remediation is the handoff to whoever fixes the issue.
type Remediation struct {
	Guidance       string   `json:"guidance"`
	RootCauseHint  string   `json:"root_cause_hint,omitempty"`
	References     []string `json:"references,omitempty"`
	FixableByGiver bool     `json:"fixable_by_giver"`

	// HumanRequiredReason must be set whenever FixableByGiver is false, so the
	// Giver can explain the handoff rather than silently skipping the finding.
	HumanRequiredReason string `json:"human_required_reason,omitempty"`
}

// Finding is one security issue. It is the unit of the Killer to Giver contract.
type Finding struct {
	SchemaVersion string     `json:"schema_version"`
	FindingID     string     `json:"finding_id"`
	RuleID        string     `json:"rule_id"`
	Title         string     `json:"title"`
	Category      Category   `json:"category"`
	CWE           string     `json:"cwe,omitempty"`
	Severity      Severity   `json:"severity"`
	Confidence    Confidence `json:"confidence"`
	Source        Source     `json:"source"`

	Location     Location      `json:"location"`
	Evidence     Evidence      `json:"evidence"`
	Reproduction *Reproduction `json:"reproduction,omitempty"`
	BlastRadius  *BlastRadius  `json:"blast_radius,omitempty"`
	Remediation  Remediation   `json:"remediation"`

	Status Status `json:"status"`

	// Rank is the computed ordering score; see package rank.
	Rank float64 `json:"rank,omitempty"`

	// MergedFrom lists the engines whose findings were folded into this one.
	MergedFrom []Source `json:"merged_from,omitempty"`

	FirstSeenRun string `json:"first_seen_run,omitempty"`
	LastSeenRun  string `json:"last_seen_run,omitempty"`
}

// SkippedCheck records a check that did not run, so that a consumer of
// findings.json can tell "this layer found nothing" from "this layer never
// ran". Without it, zero findings is ambiguous in the one direction that
// matters, and a reader acting on the file -- `vibekiller diff` today, Vibe
// Giver later -- concludes the application is clean.
//
// It mirrors SARIF's invocations[].toolExecutionNotifications so one source
// feeds both serializers.
type SkippedCheck struct {
	CheckID string `json:"check_id"`
	Layer   string `json:"layer,omitempty"`
	Reason  string `json:"reason"`
}

// SourceForLayer maps a check's layer to the finding source that layer
// produces, which is how a skip is connected to the findings it suppressed.
//
// The mapping is 1:1 and verified against what the producers actually emit,
// rather than inferred from the names: the endpoint checks all emit dast and
// the exposure check emits blast-radius, neither of which matches its layer
// string. The second return value is false for an unknown layer, so a future
// layer fails to match rather than silently matching the wrong source.
func SourceForLayer(layer string) (Source, bool) {
	switch layer {
	case "static":
		return SourceSAST, true
	case "endpoint":
		return SourceDAST, true
	case "runtime":
		return SourceRuntime, true
	case "deps":
		return SourceDeps, true
	case "secrets":
		return SourceSecrets, true
	case "exposure":
		return SourceBlastRadius, true
	default:
		return "", false
	}
}

// Document is the top-level shape of runs/<id>/findings.json.
type Document struct {
	SchemaVersion string    `json:"schema_version"`
	RunID         string    `json:"run_id"`
	GeneratedAt   string    `json:"generated_at"`
	RepoPath      string    `json:"repo_path"`
	RepoRev       string    `json:"repo_rev,omitempty"`
	Target        string    `json:"target,omitempty"`
	Counts        Counts    `json:"counts"`
	Findings      []Finding `json:"findings"`

	// Skipped is every check that did not run, with the reason. It is
	// omitted when empty so a run in which everything ran looks exactly as
	// it did before this field existed.
	Skipped []SkippedCheck `json:"skipped,omitempty"`
}

// Counts summarizes a run for quick CI consumption.
type Counts struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	BySource   map[string]int `json:"by_source"`
	Confirmed  int            `json:"confirmed"`
}

// Summarize computes the Counts for a set of findings.
func Summarize(fs []Finding) Counts {
	c := Counts{
		BySeverity: map[string]int{},
		BySource:   map[string]int{},
	}
	for _, f := range fs {
		c.Total++
		c.BySeverity[string(f.Severity)]++
		c.BySource[string(f.Source)]++
		if f.Confidence == ConfidenceConfirmed {
			c.Confirmed++
		}
	}
	return c
}

// MaxSeverity returns the highest severity present, and false if fs is empty
// or carries no recognizable severity.
func MaxSeverity(fs []Finding) (Severity, bool) {
	best := -1
	var out Severity
	for _, f := range fs {
		if w, ok := f.Severity.Weight(); ok && w > best {
			best, out = w, f.Severity
		}
	}
	return out, best >= 0
}
