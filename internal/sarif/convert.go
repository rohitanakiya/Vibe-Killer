package sarif

import (
	"fmt"
	"path"
	"strings"

	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
	"github.com/rohitanakiya/Vibe-Killer/internal/surface"
)

// GitHub's documented limits. Vibe Killer runs are nowhere near these, but a
// file that breaches one is rejected whole, so the cost of clamping is a
// truncated report and the cost of not clamping is no report at all.
const (
	maxResults  = 25000
	maxRules    = 25000
	maxTextLen  = 1024
	maxNameLen  = 255
	srcRootBase = "%SRCROOT%"
)

// Options configures a conversion.
type Options struct {
	// ToolVersion is stamped on the driver so an alert can be traced back to
	// the build that raised it.
	ToolVersion string

	// InformationURI is the tool's home page, shown beside the alert.
	InformationURI string

	// Surface, when present, is what lets an endpoint finding point at the
	// handler serving the route rather than at nothing. Without it those
	// findings still convert, with a less useful location.
	Surface *surface.Surface

	// Category becomes the automationDetails category. GitHub parses
	// automationDetails.id as "category/run-id" and uses the category to tell
	// one tool's uploads apart, so two Vibe Killer runs on one commit need
	// different values here or the second overwrites the first.
	Category string

	// FallbackPath is the artifact a finding points at when it has no file of
	// its own and none can be resolved -- a dynamic finding on a route that
	// was never matched to a handler. The alert still carries the endpoint in
	// its message and its logical location; this only decides where GitHub
	// tries to anchor it.
	FallbackPath string
}

// Convert renders a findings document as a SARIF log.
//
// The document is the whole input: results come from its findings, and the run
// notifications come from its skipped and failed arrays. That is what putting
// coverage into the contract bought -- a consumer reading only findings cannot
// tell an absent layer from a clean one, and SARIF has a place to say which it
// was.
func Convert(doc *finding.Document, opts Options) *Log {
	if opts.Category == "" {
		opts.Category = "vibekiller"
	}
	if opts.FallbackPath == "" {
		opts.FallbackPath = "vibekiller.config.yaml"
	}

	c := &converter{opts: opts, routes: indexRoutes(opts.Surface)}

	findings := doc.Findings
	if len(findings) > maxResults {
		findings = findings[:maxResults]
	}

	rules, index := c.rules(findings)
	results := make([]Result, 0, len(findings))
	for _, f := range findings {
		results = append(results, c.result(f, index[f.RuleID]))
	}

	run := Run{
		Tool: Tool{Driver: Driver{
			Name:           "Vibe Killer",
			Version:        opts.ToolVersion,
			InformationURI: opts.InformationURI,
			Rules:          rules,
		}},
		Results:    results,
		ColumnKind: "utf16CodeUnits",
		OriginalURIBaseIDs: map[string]ArtifactLocation{
			srcRootBase: {URI: "file:///"},
		},
	}

	if doc.RunID != "" {
		run.AutomationDetails = &AutomationDetails{ID: opts.Category + "/" + doc.RunID}
	}
	if inv, ok := c.invocation(doc); ok {
		run.Invocations = []Invocation{inv}
	}

	return &Log{Schema: SchemaURI, Version: Version, Runs: []Run{run}}
}

type converter struct {
	opts   Options
	routes map[string]surface.Route
}

// --- rules ----------------------------------------------------------------

// rules builds one descriptor per distinct rule id, in first-seen order so the
// output is stable across runs with the same findings.
//
// Rule-level text is derived from the rule, not from one of its findings. A
// finding's title is instance detail -- "django 5.0.1: SQL injection via
// _connector" -- and using it as the rule's description would name the whole
// rule after whichever CVE happened to come first. Instance detail belongs in
// result.message, which is where it goes.
func (c *converter) rules(findings []finding.Finding) ([]ReportingDescriptor, map[string]int) {
	index := map[string]int{}
	strongest := map[string]float64{}

	// Not a nil slice, and not a stylistic preference: a nil slice marshals
	// to null, GitHub requires rules to be an array, and a run that found
	// nothing is exactly when the rule list is empty. So a clean scan -- the
	// result everyone is hoping for, and the one most likely to be uploaded
	// without anyone looking -- produced a document that would be rejected.
	// Every local check of this writer happened to run against a scan with
	// findings, which is why only the no-scanner path in CI exposed it.
	out := []ReportingDescriptor{}

	for _, f := range findings {
		sev := securitySeverity(f.Severity)

		if i, seen := index[f.RuleID]; seen {
			// Keep the strongest severity the rule fired at, so a rule that
			// produced one critical finding is not defaulted to the level of
			// whichever finding came first.
			if sev > strongest[f.RuleID] {
				strongest[f.RuleID] = sev
				out[i].DefaultConfig = &Configuration{Level: level(f.Severity)}
				if out[i].Properties != nil {
					out[i].Properties.SecuritySeverity = fmt.Sprintf("%.1f", sev)
					out[i].Properties.ProblemSeverity = problemSeverity(f.Severity)
				}
			}
			continue
		}
		if len(out) >= maxRules {
			continue
		}

		index[f.RuleID] = len(out)
		strongest[f.RuleID] = sev

		out = append(out, ReportingDescriptor{
			ID:               f.RuleID,
			Name:             truncate(f.RuleID, maxNameLen),
			ShortDescription: Message{Text: truncate(humanize(f.RuleID), maxTextLen)},
			FullDescription:  Message{Text: truncate(fullDescription(f), maxTextLen)},
			Help:             help(f),
			DefaultConfig:    &Configuration{Level: level(f.Severity)},
			Properties: &RuleProps{
				Tags:             tags(f),
				Precision:        precision(f.Confidence),
				SecuritySeverity: fmt.Sprintf("%.1f", sev),
				ProblemSeverity:  problemSeverity(f.Severity),
			},
		})
	}
	return out, index
}

// humanize turns a rule id into a label: "misconfig.missing-security-headers"
// becomes "misconfig: missing security headers".
//
// It is deliberately mechanical. A hand-written catalogue would read better
// and would drift out of step with the rule pack, which ships rules this
// package never sees -- a wrong label is worse than a plain one.
func humanize(ruleID string) string {
	parts := strings.SplitN(ruleID, ".", 2)
	if len(parts) != 2 {
		return strings.ReplaceAll(ruleID, "-", " ")
	}
	return parts[0] + ": " + strings.ReplaceAll(parts[1], "-", " ")
}

func fullDescription(f finding.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s finding in the %s category", strings.ToUpper(string(f.Source)), f.Category)
	if f.CWE != "" {
		fmt.Fprintf(&b, " (%s)", f.CWE)
	}
	b.WriteString(". ")
	if hint := f.Remediation.RootCauseHint; hint != "" {
		b.WriteString(hint)
	} else {
		b.WriteString(f.Remediation.Guidance)
	}
	return strings.TrimSpace(b.String())
}

// help is required by GitHub on every rule, and the remediation guidance is
// the honest answer to "what do I do about this", so it is what goes here.
func help(f finding.Finding) Message {
	text := f.Remediation.Guidance
	if text == "" {
		text = "See the Vibe Killer report in the run directory for the evidence behind this finding."
	}

	md := text
	if len(f.Remediation.References) > 0 {
		md += "\n\nReferences:\n"
		for _, r := range f.Remediation.References {
			md += "\n- " + r
		}
	}
	if !f.Remediation.FixableByGiver && f.Remediation.HumanRequiredReason != "" {
		md += "\n\n**Needs a person:** " + f.Remediation.HumanRequiredReason
	}
	return Message{Text: truncate(text, maxTextLen), Markdown: md}
}

func tags(f finding.Finding) []string {
	// "security" is load-bearing rather than decorative: GitHub applies
	// security-severity only to rules tagged with it.
	out := []string{"security", string(f.Category), string(f.Source)}
	if f.CWE != "" {
		out = append(out, "external/cwe/"+strings.ToLower(f.CWE))
	}
	return out
}

// --- results --------------------------------------------------------------

func (c *converter) result(f finding.Finding, ruleIndex int) Result {
	r := Result{
		RuleID:    f.RuleID,
		RuleIndex: ruleIndex,
		Level:     level(f.Severity),
		Message:   Message{Text: message(f)},
		Locations: []Location{c.location(f)},
		PartialFingerprints: map[string]string{
			// GitHub reads only primaryLocationLineHash, and that name is
			// GitHub's rather than a description of this value. What goes in
			// it is the finding_id, which is a better fingerprint than a line
			// hash precisely because it excludes line numbers: an edit above
			// the vulnerable line will not close this alert and open a
			// duplicate.
			"primaryLocationLineHash": f.FindingID,
			"vibekillerFindingId":     f.FindingID,
		},
		Properties: map[string]any{
			"confidence": string(f.Confidence),
			"status":     string(f.Status),
			"source":     string(f.Source),
		},
	}
	if f.Reproduction != nil {
		r.Properties["reproducible"] = true
	}
	if f.Location.Endpoint != "" {
		r.Properties["endpoint"] = f.Location.Endpoint
	}
	return r
}

// message is what a reviewer reads first. The evidence summary is appended
// because this tool's claim is that it proved the finding, and the proof is
// more persuasive than the title.
func message(f finding.Finding) string {
	text := f.Title
	if s := strings.TrimSpace(f.Evidence.Summary); s != "" && s != text {
		text += " — " + s
	}
	if f.Confidence == finding.ConfidenceConfirmed {
		text += " (confirmed by re-running the proof)"
	}
	return text
}

// --- locations ------------------------------------------------------------

func (c *converter) location(f finding.Finding) Location {
	loc := f.Location

	switch loc.Type {
	case finding.LocationDependency:
		l := Location{PhysicalLocation: c.physical(loc.File, loc.Line, loc.EndLine)}
		if loc.Package != "" {
			fq := loc.Package
			if loc.Version != "" {
				fq += "@" + loc.Version
			}
			if loc.Ecosystem != "" {
				fq = loc.Ecosystem + ":" + fq
			}
			l.LogicalLocations = []LogicalLocation{{
				Name:               loc.Package,
				Kind:               "package",
				FullyQualifiedName: fq,
			}}
		}
		return l

	case finding.LocationEndpoint:
		return c.endpointLocation(f)

	case finding.LocationConfig:
		l := Location{PhysicalLocation: c.physical(loc.File, loc.Line, loc.EndLine)}
		if loc.ConfigKey != "" {
			l.LogicalLocations = []LogicalLocation{{Name: loc.ConfigKey, Kind: "configuration"}}
		}
		return l

	default: // LocationCode
		l := Location{PhysicalLocation: c.physical(loc.File, loc.Line, loc.EndLine)}
		if loc.Symbol != "" {
			l.LogicalLocations = []LogicalLocation{{Name: loc.Symbol, Kind: "function"}}
		}
		return l
	}
}

// endpointLocation is why Options carries a Surface.
//
// A dynamic finding is about a route, and a route is not a file -- but GitHub
// needs a physical location or it will not display the result at all.
// Resolving the route back to the handler that serves it turns an alert with
// no code context into one annotated on the line a reviewer has to change,
// which for a tool whose output is meant to land on a pull request is most of
// the value.
func (c *converter) endpointLocation(f finding.Finding) Location {
	logical := []LogicalLocation{{Name: f.Location.Endpoint, Kind: "route"}}

	if r, ok := c.routes[routeKey(f.Location.Endpoint)]; ok && r.File != "" {
		return Location{
			PhysicalLocation: c.physical(r.File, r.Line, 0),
			LogicalLocations: logical,
			Message:          &Message{Text: "handler for " + f.Location.Endpoint},
		}
	}
	if f.Location.File != "" {
		return Location{
			PhysicalLocation: c.physical(f.Location.File, f.Location.Line, f.Location.EndLine),
			LogicalLocations: logical,
		}
	}
	return Location{
		PhysicalLocation: c.physical(c.opts.FallbackPath, 0, 0),
		LogicalLocations: logical,
		Message:          &Message{Text: "no handler was resolved for " + f.Location.Endpoint},
	}
}

// physical normalizes a path for SARIF and satisfies GitHub's region rules.
//
// Paths become forward-slash separated because this tool is developed on
// Windows and the scanners it wraps report paths in whatever form their
// platform uses, while a SARIF uri is always slash-separated. A leading "./"
// or "/" is stripped so the uri stays relative to the repository root, which
// is what GitHub resolves against; an absolute path whose scheme disagrees
// with the source root gets the whole upload rejected.
//
// startLine and startColumn are both required and both 1-based, so a finding
// with no line information is anchored at 1:1 rather than left regionless: a
// result without a region is a result GitHub will not show.
func (c *converter) physical(file string, line, endLine int) *PhysicalLocation {
	uri := strings.ReplaceAll(file, "\\", "/")
	uri = strings.TrimPrefix(uri, "./")
	uri = strings.TrimPrefix(uri, "/")
	if uri != "" {
		uri = path.Clean(uri)
	}
	if uri == "." || uri == "" {
		uri = c.opts.FallbackPath
	}

	if line < 1 {
		line = 1
	}
	region := &Region{StartLine: line, StartColumn: 1}
	if endLine > line {
		region.EndLine = endLine
	}

	return &PhysicalLocation{
		ArtifactLocation: ArtifactLocation{URI: uri, URIBaseID: srcRootBase},
		Region:           region,
	}
}

func indexRoutes(s *surface.Surface) map[string]surface.Route {
	if s == nil {
		return nil
	}
	out := make(map[string]surface.Route, len(s.Routes))
	for _, r := range s.Routes {
		out[routeKey(r.Method+" "+r.Path)] = r
		// Index the path alone too, so a finding recorded against a different
		// method on the same path still resolves to the right file.
		if _, ok := out[routeKey(r.Path)]; !ok {
			out[routeKey(r.Path)] = r
		}
	}
	return out
}

func routeKey(s string) string { return strings.ToUpper(strings.TrimSpace(s)) }

// --- invocation / coverage ------------------------------------------------

// invocation carries the coverage picture as tool execution notifications,
// SARIF's place for statements about the run rather than about the code.
//
// The level is the discriminator that let skipped and failed stay in separate
// arrays in findings.json without needing a field to tell them apart: a skip
// is a note, because it is usually a deliberate narrowing, while a failure is
// an error, because something broke and the operator should act.
// executionSuccessful is false when anything failed, which is the plainest
// available statement that this run does not support a clean verdict.
//
// GitHub's documentation does not say it ingests any of this, so it is written
// for correctness and for other consumers rather than in the expectation of a
// GitHub UI. The same facts are in findings.json, which is what Vibe Giver
// will read.
func (c *converter) invocation(doc *finding.Document) (Invocation, bool) {
	if len(doc.Skipped) == 0 && len(doc.Failed) == 0 {
		return Invocation{}, false
	}

	inv := Invocation{
		ExecutionSuccessful: len(doc.Failed) == 0,
		StartTimeUTC:        doc.GeneratedAt,
	}
	for _, s := range doc.Skipped {
		inv.ToolExecutionNotifications = append(inv.ToolExecutionNotifications, Notification{
			Descriptor:     &DescriptorReference{ID: "vibekiller.check-skipped"},
			AssociatedRule: &DescriptorReference{ID: s.CheckID},
			Level:          LevelNote,
			Message:        Message{Text: fmt.Sprintf("%s did not run: %s", s.CheckID, s.Reason)},
		})
	}
	for _, fl := range doc.Failed {
		inv.ToolExecutionNotifications = append(inv.ToolExecutionNotifications, Notification{
			Descriptor:     &DescriptorReference{ID: "vibekiller.check-failed"},
			AssociatedRule: &DescriptorReference{ID: fl.CheckID},
			Level:          LevelError,
			Message:        Message{Text: fmt.Sprintf("%s failed, so it established nothing: %s", fl.CheckID, fl.Error)},
		})
	}
	return inv, true
}

// --- severity mapping -----------------------------------------------------

func level(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical, finding.SeverityHigh:
		return LevelError
	case finding.SeverityMedium:
		return LevelWarning
	default:
		return LevelNote
	}
}

// securitySeverity returns a value inside GitHub's documented bands: above 9.0
// is critical, 7.0 to 8.9 high, 4.0 to 6.9 medium, 0.1 to 3.9 low. Zero or
// out of range means GitHub records no security severity at all, which is why
// info sits inside the low band rather than at 0.
func securitySeverity(s finding.Severity) float64 {
	switch s {
	case finding.SeverityCritical:
		return 9.5
	case finding.SeverityHigh:
		return 8.0
	case finding.SeverityMedium:
		return 5.5
	case finding.SeverityLow:
		return 3.0
	default:
		return 1.0
	}
}

func problemSeverity(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical, finding.SeverityHigh:
		return "error"
	case finding.SeverityMedium:
		return "warning"
	default:
		return "recommendation"
	}
}

func precision(c finding.Confidence) string {
	switch c {
	case finding.ConfidenceConfirmed:
		return "very-high"
	case finding.ConfidenceLikely:
		return "high"
	default:
		return "medium"
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}
