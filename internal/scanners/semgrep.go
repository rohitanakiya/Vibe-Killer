package scanners

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
	"github.com/rohitanakiya/Vibe-Killer/internal/tool"
)

// Semgrep wraps the Semgrep static analysis engine.
//
// Vibe Killer runs Semgrep with two rule sources: its registry security rules
// for the detected languages, and the first-party rule pack in rules/ that
// targets the patterns AI-generated code repeatedly ships.
type Semgrep struct {
	runner *tool.Runner

	// RulePacks are additional --config values, typically the bundled
	// first-party pack plus whatever the operator adds.
	RulePacks []string
}

// NewSemgrep builds the wrapper.
func NewSemgrep(runner *tool.Runner, rulePacks []string) *Semgrep {
	return &Semgrep{runner: runner, RulePacks: rulePacks}
}

// Available reports whether Semgrep can run.
func (s *Semgrep) Available() bool { return s.runner.Available() }

// Name identifies the scanner.
func (s *Semgrep) Name() string { return "semgrep" }

// semgrepOutput is the subset of Semgrep's JSON that matters here. Parsing a
// subset rather than the whole schema keeps the wrapper working across
// Semgrep releases that add fields.
type semgrepOutput struct {
	Results []semgrepResult `json:"results"`
	Errors  []semgrepError  `json:"errors"`
	Paths   struct {
		Scanned []string `json:"scanned"`
	} `json:"paths"`
}

type semgrepError struct {
	Message string `json:"message"`
	Level   string `json:"level"`
	Path    string `json:"path"`
}

type semgrepResult struct {
	CheckID string       `json:"check_id"`
	Path    string       `json:"path"`
	Start   semgrepPos   `json:"start"`
	End     semgrepPos   `json:"end"`
	Extra   semgrepExtra `json:"extra"`
}

type semgrepPos struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

type semgrepExtra struct {
	Message  string          `json:"message"`
	Severity string          `json:"severity"`
	Lines    string          `json:"lines"`
	Metadata semgrepMetadata `json:"metadata"`

	// DataflowTrace is kept raw: Semgrep encodes it as heterogeneous arrays
	// whose shape varies by rule type, so it is decoded best-effort.
	DataflowTrace json.RawMessage `json:"dataflow_trace"`
}

type semgrepMetadata struct {
	CWE        stringList `json:"cwe"`
	OWASP      stringList `json:"owasp"`
	References stringList `json:"references"`
	Category   string     `json:"category"`
	Confidence string     `json:"confidence"`
	Impact     string     `json:"impact"`

	// VibeKiller is the first-party rule pack's own metadata block, which
	// lets a bundled rule state the contract fields directly instead of
	// having them guessed from the message text.
	VibeKiller *vibeKillerMeta `json:"vibekiller"`
}

// vibeKillerMeta is what a rule in the first-party pack declares about itself.
type vibeKillerMeta struct {
	RuleID        string `json:"rule_id"`
	Category      string `json:"category"`
	Severity      string `json:"severity"`
	Confidence    string `json:"confidence"`
	Fixable       *bool  `json:"fixable_by_giver"`
	HumanRequired string `json:"human_required_reason"`
	RootCause     string `json:"root_cause_hint"`
	Guidance      string `json:"guidance"`

	// DynamicRule names an endpoint check that can try to confirm this static
	// finding against the running instance. This is the link that lets a
	// static hit be upgraded to confirmed later in the run.
	DynamicRule string `json:"dynamic_rule"`
}

// stringList tolerates a field that tools emit as either a string or an array
// of strings.
type stringList []string

func (sl *stringList) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*sl = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err == nil {
		*sl = many
		return nil
	}
	// An unexpected shape is not worth failing a whole scan over.
	*sl = nil
	return nil
}

// Run invokes Semgrep and returns normalized findings plus the raw output for
// the run's raw/ directory.
func (s *Semgrep) Run(ctx context.Context, sc ScanContext) ([]finding.Finding, []byte, error) {
	args := []string{
		"--json",
		"--quiet",
		"--no-rewrite-rule-ids",
		// Vibe Killer writes nothing outside the run directory, and Semgrep's
		// metrics upload would be an outbound connection the operator did not
		// ask for.
		"--metrics", "off",
		"--disable-version-check",
		"--timeout", "30",
	}

	configs := s.RulePacks
	if len(configs) == 0 {
		configs = []string{"p/security-audit"}
	}
	for _, c := range configs {
		args = append(args, "--config", c)
	}
	for _, ex := range sc.Exclude {
		if ex = normalizeExclude(ex); ex != "" {
			args = append(args, "--exclude", ex)
		}
	}
	args = append(args, ".")

	res, err := s.runner.Run(ctx, sc.RepoRoot, args...)
	if res == nil {
		return nil, nil, err
	}
	if err != nil {
		// Semgrep writes JSON even on a partial failure, so try to salvage
		// results before giving up on the whole engine.
		fs, parseErr := s.parse(res.Stdout, sc)
		if parseErr == nil && len(fs) > 0 {
			return fs, res.Stdout, nil
		}
		return nil, res.Stdout, err
	}

	fs, parseErr := s.parse(res.Stdout, sc)
	if parseErr != nil {
		return nil, res.Stdout, parseErr
	}
	return fs, res.Stdout, nil
}

// normalizeExclude rewrites an exclude pattern into the form Semgrep actually
// acts on.
//
// A `dir/**` pattern is the one every .gitignore-trained operator writes, and
// against Semgrep it is worse than writing nothing. Measured on
// fixtures/express-vulnerable, which has 81 packages installed:
//
//	(no --exclude)                      17 findings,  0 inside node_modules
//	--exclude node_modules/**           34 findings, 17 inside node_modules
//	--exclude node_modules              17 findings,  0 inside node_modules
//
// Semgrep skips node_modules by default, and naming it in a pattern that
// matches nothing switched that default off: the pack's own default exclude
// list was the reason a scan of any Node project read its whole dependency
// tree and reported third-party code under rule ids about the operator's own.
//
// A longer prefix fails the other way. This repository's committed config said
// `fixtures/*/node_modules/**`, and a scan of the repository with it returned
// zero findings -- the whole fixtures tree was pruned. The self-scan was empty
// and nothing said so.
//
// Dropping the trailing /** or /* fixes both, and every other spelling tested
// (`node_modules`, `node_modules/`, `node_modules/*`, `**/node_modules`,
// `./node_modules/**`) already behaved correctly, so the rewrite is only ever
// turning a broken pattern into a working one. A pattern with no slash matches
// that path component at any depth, which is what the operator meant.
// Backslashes are converted unconditionally rather than through
// filepath.ToSlash, which is a no-op off Windows. The config file is committed
// and the same value is read on whatever platform runs the scan, so a pattern
// an operator wrote on Windows has to mean the same thing in Linux CI. Semgrep
// matches these globs with forward slashes everywhere.
func normalizeExclude(pattern string) string {
	p := strings.ReplaceAll(strings.TrimSpace(pattern), `\`, "/")
	p = strings.TrimPrefix(p, "./")

	// Repeatedly, so that `dir/**/*` collapses too.
	for {
		shorter := strings.TrimSuffix(strings.TrimSuffix(p, "/**"), "/*")
		if shorter == p {
			break
		}
		p = shorter
	}
	return strings.TrimSuffix(p, "/")
}

// parse converts Semgrep JSON into findings.
func (s *Semgrep) parse(data []byte, sc ScanContext) ([]finding.Finding, error) {
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, nil
	}

	var out semgrepOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("parsing semgrep output: %w", err)
	}

	var fs []finding.Finding
	for _, r := range out.Results {
		f, ok := s.toFinding(r, sc)
		if ok {
			fs = append(fs, f)
		}
	}
	return fs, nil
}

func (s *Semgrep) toFinding(r semgrepResult, sc ScanContext) (finding.Finding, bool) {
	md := r.Extra.Metadata
	vk := md.VibeKiller

	// Semgrep's registry rules are not all security rules. Without a
	// first-party metadata block, require the rule to be tagged as a security
	// rule, so that a style lint does not arrive as a vulnerability.
	if vk == nil && md.Category != "" && !strings.EqualFold(md.Category, "security") {
		return finding.Finding{}, false
	}

	ruleID := normalizeRuleID(r.CheckID)
	if vk != nil && vk.RuleID != "" {
		ruleID = vk.RuleID
	}

	severity := mapSemgrepSeverity(r.Extra.Severity)
	if vk != nil && vk.Severity != "" {
		if s, err := finding.ParseSeverity(vk.Severity); err == nil {
			severity = s
		}
	}

	// Static analysis can say a pattern exists, not that it is exploitable in
	// a running app. A static finding therefore tops out at likely; only an
	// endpoint check that reproduces it may mark it confirmed.
	confidence := mapSemgrepConfidence(md.Confidence)
	if vk != nil && vk.Confidence != "" {
		switch finding.Confidence(vk.Confidence) {
		case finding.ConfidenceHeuristic, finding.ConfidenceLikely:
			confidence = finding.Confidence(vk.Confidence)
		}
	}

	category := inferCategory(ruleID, md.OWASP, md.CWE)
	if vk != nil && vk.Category != "" {
		category = finding.Category(vk.Category)
	}

	fixable := true
	humanReason := ""
	if vk != nil {
		if vk.Fixable != nil {
			fixable = *vk.Fixable
		}
		humanReason = vk.HumanRequired
	}
	if category == finding.CategorySecretsExposure {
		// A credential in source cannot be fixed by editing code: it is
		// already disclosed and has to be rotated.
		fixable = false
		if humanReason == "" {
			humanReason = "the credential is already disclosed and must be rotated by a human; removing it from the source is not sufficient"
		}
	}
	if !fixable && humanReason == "" {
		humanReason = "this finding needs a human decision rather than a code edit"
	}

	guidance := strings.TrimSpace(r.Extra.Message)
	if vk != nil && vk.Guidance != "" {
		guidance = vk.Guidance
	}
	if guidance == "" {
		guidance = "Review the flagged code and remove the unsafe pattern."
	}

	rootCause := ""
	if vk != nil {
		rootCause = vk.RootCause
	}

	file := relPath(sc.RepoRoot, r.Path)
	loc := finding.Location{
		Type:    finding.LocationCode,
		File:    file,
		Line:    r.Start.Line,
		EndLine: r.End.Line,
	}
	sc.setLocationRev(&loc)

	f := finding.Finding{
		RuleID:     ruleID,
		Title:      titleFrom(r.Extra.Message, ruleID),
		Category:   category,
		CWE:        firstCWE(md.CWE),
		Severity:   severity,
		Confidence: confidence,
		Source:     finding.SourceSAST,
		Location:   loc,
		Evidence: finding.Evidence{
			Summary:   truncate(r.Extra.Message, 1000),
			Snippet:   truncate(r.Extra.Lines, 400),
			TaintPath: parseDataflowTrace(r.Extra.DataflowTrace, sc),
			// Two different rules can fire on the same line; the check id
			// keeps their identities apart.
			EvidenceKey: "semgrep:" + r.CheckID,
		},
		Reproduction: &finding.Reproduction{
			Kind: finding.ReproStatic,
			Steps: []string{
				fmt.Sprintf("Open %s at line %d.", file, r.Start.Line),
				"The flagged pattern is the one described in the evidence summary.",
			},
		},
		Remediation: finding.Remediation{
			Guidance:            guidance,
			RootCauseHint:       rootCause,
			References:          md.References,
			FixableByGiver:      fixable,
			HumanRequiredReason: humanReason,
		},
		Status: finding.StatusOpen,
	}
	f.AssignID()
	return f, true
}

// normalizeRuleID turns a Semgrep check id into the contract's rule_id shape:
// lowercase dotted or dashed segments.
func normalizeRuleID(checkID string) string {
	id := strings.ToLower(strings.TrimSpace(checkID))
	if id == "" {
		return "semgrep.unknown"
	}

	// Registry ids are path-like; the trailing segments carry the meaning.
	id = strings.ReplaceAll(id, "/", ".")

	var b strings.Builder
	lastSep := true
	for _, r := range id {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			lastSep = false
		case r == '.' || r == '-':
			if !lastSep {
				b.WriteRune(r)
				lastSep = true
			}
		case r == '_' || r == ' ':
			if !lastSep {
				b.WriteByte('-')
				lastSep = true
			}
		}
	}
	out := strings.Trim(b.String(), ".-")
	if out == "" {
		return "semgrep.unknown"
	}
	return out
}

// titleFrom derives a one-line title from a rule message.
func titleFrom(message, ruleID string) string {
	msg := strings.TrimSpace(message)
	if msg == "" {
		return ruleID
	}
	// Take the first sentence, which is where these messages put the claim.
	if i := strings.IndexAny(msg, ".\n"); i > 20 {
		msg = msg[:i]
	}
	return truncate(msg, 160)
}

func mapSemgrepSeverity(s string) finding.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "ERROR", "CRITICAL":
		return finding.SeverityHigh
	case "WARNING":
		return finding.SeverityMedium
	case "INFO":
		return finding.SeverityLow
	default:
		return finding.SeverityMedium
	}
}

func mapSemgrepConfidence(s string) finding.Confidence {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "HIGH":
		return finding.ConfidenceLikely
	case "MEDIUM", "LOW":
		return finding.ConfidenceHeuristic
	default:
		return finding.ConfidenceHeuristic
	}
}

// categoryHints maps substrings in a rule id to a contract category. Checked
// in order, so the more specific entries come first.
var categoryHints = []struct {
	needle   string
	category finding.Category
}{
	{"idor", finding.CategoryBrokenAccessControl},
	{"authz", finding.CategoryBrokenAccessControl},
	{"access-control", finding.CategoryBrokenAccessControl},
	{"missing-auth", finding.CategoryBrokenAccessControl},
	{"ssrf", finding.CategorySSRF},
	{"request-forgery", finding.CategorySSRF},
	{"sqli", finding.CategoryInjection},
	{"sql-injection", finding.CategoryInjection},
	{"nosql", finding.CategoryInjection},
	{"command-injection", finding.CategoryInjection},
	{"code-injection", finding.CategoryInjection},
	{"injection", finding.CategoryInjection},
	{"path-traversal", finding.CategoryBrokenAccessControl},
	{"traversal", finding.CategoryBrokenAccessControl},
	{"hardcoded", finding.CategorySecretsExposure},
	{"secret", finding.CategorySecretsExposure},
	{"credential", finding.CategorySecretsExposure},
	{"api-key", finding.CategorySecretsExposure},
	{"jwt", finding.CategoryAuthFailure},
	{"auth", finding.CategoryAuthFailure},
	{"password", finding.CategoryAuthFailure},
	{"session", finding.CategoryAuthFailure},
	{"crypto", finding.CategoryCryptoFailure},
	{"cipher", finding.CategoryCryptoFailure},
	{"hash", finding.CategoryCryptoFailure},
	{"tls", finding.CategoryCryptoFailure},
	{"random", finding.CategoryCryptoFailure},
	{"cors", finding.CategoryMisconfiguration},
	{"debug", finding.CategoryMisconfiguration},
	{"header", finding.CategoryMisconfiguration},
	{"deserial", finding.CategoryIntegrityFailure},
	{"xss", finding.CategoryInsecureDesign},
	{"log", finding.CategoryLoggingFailure},
}

// owaspHints maps an OWASP Top 10 identifier to a category, used when the rule
// id itself is uninformative.
var owaspHints = []struct {
	needle   string
	category finding.Category
}{
	{"a01", finding.CategoryBrokenAccessControl},
	{"a02", finding.CategoryCryptoFailure},
	{"a03", finding.CategoryInjection},
	{"a04", finding.CategoryInsecureDesign},
	{"a05", finding.CategoryMisconfiguration},
	{"a06", finding.CategoryVulnerableDep},
	{"a07", finding.CategoryAuthFailure},
	{"a08", finding.CategoryIntegrityFailure},
	{"a09", finding.CategoryLoggingFailure},
	{"a10", finding.CategorySSRF},
}

// inferCategory picks a contract category for a third-party rule that does not
// carry first-party metadata.
//
// The order matters. An OWASP tag and a CWE are statements the rule's author
// made deliberately; a substring of the rule's name is a guess. Guessing first
// gets this wrong in exactly the cases that look obvious, for example
// "express-cookie-session-no-httponly", whose name contains "session" but
// which its author tagged as a misconfiguration.
func inferCategory(ruleID string, owasp, cwe []string) finding.Category {
	joined := strings.ToLower(strings.Join(owasp, " "))
	for _, h := range owaspHints {
		if strings.Contains(joined, h.needle) {
			return h.category
		}
	}

	switch firstCWE(cwe) {
	case "CWE-89", "CWE-78", "CWE-94", "CWE-943":
		return finding.CategoryInjection
	case "CWE-639", "CWE-862", "CWE-863", "CWE-22":
		return finding.CategoryBrokenAccessControl
	case "CWE-798", "CWE-259", "CWE-321":
		return finding.CategorySecretsExposure
	case "CWE-918":
		return finding.CategorySSRF
	case "CWE-287", "CWE-347", "CWE-384":
		return finding.CategoryAuthFailure
	case "CWE-327", "CWE-328", "CWE-330", "CWE-338":
		return finding.CategoryCryptoFailure
	case "CWE-502":
		return finding.CategoryIntegrityFailure
	}

	// Only now fall back to reading the rule's name.
	id := strings.ToLower(ruleID)
	for _, h := range categoryHints {
		if strings.Contains(id, h.needle) {
			return h.category
		}
	}

	return finding.CategoryInsecureDesign
}

// parseDataflowTrace extracts a source-to-sink path from Semgrep's taint
// output.
//
// Semgrep encodes each location as a two-element array whose first element is
// a tag string and whose second holds the position, which is awkward to type.
// This decodes it best-effort: a trace that cannot be read costs the finding
// its path, not its existence.
func parseDataflowTrace(raw json.RawMessage, sc ScanContext) []finding.TaintStep {
	if len(raw) == 0 {
		return nil
	}

	var trace struct {
		TaintSource      json.RawMessage   `json:"taint_source"`
		IntermediateVars []json.RawMessage `json:"intermediate_vars"`
		TaintSink        json.RawMessage   `json:"taint_sink"`
	}
	if err := json.Unmarshal(raw, &trace); err != nil {
		return nil
	}

	var steps []finding.TaintStep
	if s, ok := decodeTraceLocation(trace.TaintSource, sc); ok {
		s.Note = "user-controlled input enters here"
		steps = append(steps, s)
	}
	for _, iv := range trace.IntermediateVars {
		if s, ok := decodeTraceLocation(iv, sc); ok {
			s.Note = "value flows through here"
			steps = append(steps, s)
		}
	}
	if s, ok := decodeTraceLocation(trace.TaintSink, sc); ok {
		s.Note = "reaches the sink here"
		steps = append(steps, s)
	}
	return steps
}

// traceLocation is the position shape Semgrep uses inside a dataflow trace.
type traceLocation struct {
	Path     string     `json:"path"`
	Start    semgrepPos `json:"start"`
	Location *struct {
		Path  string     `json:"path"`
		Start semgrepPos `json:"start"`
	} `json:"location"`
}

// decodeTraceLocation handles the shapes Semgrep has used for a trace node: a
// bare object, an object with a nested location, or a tagged two-element
// array.
func decodeTraceLocation(raw json.RawMessage, sc ScanContext) (finding.TaintStep, bool) {
	if len(raw) == 0 {
		return finding.TaintStep{}, false
	}

	build := func(path string, line int) (finding.TaintStep, bool) {
		if path == "" || line <= 0 {
			return finding.TaintStep{}, false
		}
		return finding.TaintStep{File: relPath(sc.RepoRoot, path), Line: line}, true
	}

	var direct traceLocation
	if err := json.Unmarshal(raw, &direct); err == nil {
		if direct.Location != nil {
			if s, ok := build(direct.Location.Path, direct.Location.Start.Line); ok {
				return s, true
			}
		}
		if s, ok := build(direct.Path, direct.Start.Line); ok {
			return s, true
		}
	}

	// Tagged array form: ["CliLoc", [ {location}, "content" ]].
	var tagged []json.RawMessage
	if err := json.Unmarshal(raw, &tagged); err == nil {
		for _, el := range tagged {
			if s, ok := decodeTraceLocation(el, sc); ok {
				return s, true
			}
		}
	}

	return finding.TaintStep{}, false
}
