// Package sarif renders a Vibe Killer run as SARIF 2.1.0, the interchange
// format GitHub code scanning ingests.
//
// Only the parts of the format this tool emits are modelled. A full SARIF
// object model is large, most of it is optional, and a partial struct set that
// is wrong in no field beats a complete one that is approximately right in
// many -- GitHub rejects an upload outright on several of these, so the
// required fields are non-pointer and always written.
//
// The field set and the limits enforced in convert.go come from GitHub's own
// SARIF support documentation rather than from the SARIF specification alone,
// because GitHub requires properties the spec leaves optional (every rule
// needs a help text; every result needs a location) and caps sizes the spec
// does not.
package sarif

// Version and SchemaURI are fixed. Code scanning supports exactly SARIF
// 2.1.0, and rejects anything else.
const (
	Version   = "2.1.0"
	SchemaURI = "https://json.schemastore.org/sarif-2.1.0.json"
)

// Log is the top-level SARIF document.
type Log struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

// Run is one tool's analysis. GitHub allows at most 20 per file and requires
// that each carries results from a single tool.
type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`

	// Invocations carries the coverage notifications. GitHub's documentation
	// does not say it ingests these, so they are written for correctness and
	// for other consumers rather than in the expectation of a GitHub UI.
	Invocations []Invocation `json:"invocations,omitempty"`

	AutomationDetails *AutomationDetails `json:"automationDetails,omitempty"`

	// OriginalURIBaseIDs is not required by GitHub, but relative URI
	// references are not valid SARIF without a base to resolve against.
	OriginalURIBaseIDs map[string]ArtifactLocation `json:"originalUriBaseIds,omitempty"`

	ColumnKind string `json:"columnKind,omitempty"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Driver struct {
	Name            string                `json:"name"`
	Version         string                `json:"version,omitempty"`
	SemanticVersion string                `json:"semanticVersion,omitempty"`
	InformationURI  string                `json:"informationUri,omitempty"`
	Rules           []ReportingDescriptor `json:"rules"`
}

// ReportingDescriptor is a rule. GitHub requires id, shortDescription,
// fullDescription and help on every one of them.
type ReportingDescriptor struct {
	ID               string         `json:"id"`
	Name             string         `json:"name,omitempty"`
	ShortDescription Message        `json:"shortDescription"`
	FullDescription  Message        `json:"fullDescription"`
	Help             Message        `json:"help"`
	DefaultConfig    *Configuration `json:"defaultConfiguration,omitempty"`
	Properties       *RuleProps     `json:"properties,omitempty"`
}

type Configuration struct {
	Level string `json:"level"`
}

// RuleProps carries the properties GitHub reads. security-severity is a
// string on purpose: the documented form is a decimal string, and a float
// would serialize as "8" where "8.0" is wanted.
type RuleProps struct {
	Tags             []string `json:"tags,omitempty"`
	Precision        string   `json:"precision,omitempty"`
	SecuritySeverity string   `json:"security-severity,omitempty"`
	ProblemSeverity  string   `json:"problem.severity,omitempty"`
}

type Message struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type Result struct {
	RuleID    string  `json:"ruleId"`
	RuleIndex int     `json:"ruleIndex"`
	Level     string  `json:"level,omitempty"`
	Message   Message `json:"message"`

	// Locations is required: code scanning will not display a result without
	// at least one, and only the first is used.
	Locations []Location `json:"locations"`

	// PartialFingerprints is how an alert survives across runs. GitHub reads
	// only primaryLocationLineHash.
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`

	Properties map[string]any `json:"properties,omitempty"`
}

type Location struct {
	PhysicalLocation *PhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []LogicalLocation `json:"logicalLocations,omitempty"`
	Message          *Message          `json:"message,omitempty"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           *Region          `json:"region,omitempty"`
}

type ArtifactLocation struct {
	URI       string `json:"uri,omitempty"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

// Region is 1-based. GitHub requires startLine and startColumn; endLine is
// written only when it adds something.
type Region struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
	EndLine     int `json:"endLine,omitempty"`
}

// LogicalLocation names a non-file location -- a route, a package -- which is
// where a dynamic finding actually lives. GitHub needs a physicalLocation
// regardless, so this is additional rather than alternative.
type LogicalLocation struct {
	Name               string `json:"name"`
	Kind               string `json:"kind,omitempty"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
}

type Invocation struct {
	ExecutionSuccessful        bool           `json:"executionSuccessful"`
	StartTimeUTC               string         `json:"startTimeUtc,omitempty"`
	ToolExecutionNotifications []Notification `json:"toolExecutionNotifications,omitempty"`
}

// Notification is how SARIF says something about the run itself rather than
// about the code: a check that was skipped, or one that broke.
type Notification struct {
	Descriptor     *DescriptorReference `json:"descriptor,omitempty"`
	AssociatedRule *DescriptorReference `json:"associatedRule,omitempty"`
	Level          string               `json:"level,omitempty"`
	Message        Message              `json:"message"`
}

type DescriptorReference struct {
	ID string `json:"id"`
}

// AutomationDetails.ID is parsed by GitHub as "category/run-id", where the
// category is everything before the last slash. Distinct categories are what
// allow more than one SARIF file per commit.
type AutomationDetails struct {
	ID string `json:"id"`
}

// Notification levels. SARIF defines these; they are spelled out here so the
// mapping in convert.go reads as a decision rather than a literal.
const (
	LevelNote    = "note"
	LevelWarning = "warning"
	LevelError   = "error"
)
