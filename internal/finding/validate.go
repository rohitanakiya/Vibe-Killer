package finding

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	ruleIDPattern    = regexp.MustCompile(`^[a-z0-9]+(?:[-.][a-z0-9]+)*$`)
	findingIDPattern = regexp.MustCompile(`^vk-[0-9a-f]{12}$`)
	cwePattern       = regexp.MustCompile(`^CWE-[0-9]+$`)
)

var validCategories = map[Category]bool{
	CategoryBrokenAccessControl: true,
	CategoryCryptoFailure:       true,
	CategoryInjection:           true,
	CategoryInsecureDesign:      true,
	CategoryMisconfiguration:    true,
	CategoryVulnerableDep:       true,
	CategoryAuthFailure:         true,
	CategoryIntegrityFailure:    true,
	CategoryLoggingFailure:      true,
	CategorySSRF:                true,
	CategorySecretsExposure:     true,
	CategoryCrossService:        true,
}

var validSources = map[Source]bool{
	SourceSAST:        true,
	SourceDAST:        true,
	SourceRuntime:     true,
	SourceDeps:        true,
	SourceSecrets:     true,
	SourceBlastRadius: true,
}

var validStatuses = map[Status]bool{
	StatusOpen:          true,
	StatusFixed:         true,
	StatusRegressed:     true,
	StatusAccepted:      true,
	StatusFalsePositive: true,
}

var validLocationTypes = map[LocationType]bool{
	LocationCode:       true,
	LocationEndpoint:   true,
	LocationDependency: true,
	LocationConfig:     true,
}

var validReproKinds = map[ReproKind]bool{
	ReproHTTP:   true,
	ReproScript: true,
	ReproStatic: true,
}

// Validate enforces the invariants that schema/finding.schema.json states,
// in code, so that a malformed finding never reaches findings.json.
//
// Three of these are contract rules rather than mere type checks, and they
// exist to keep the Giver honest:
//
//   - confirmed confidence requires a reproduction, so "confirmed" always
//     means something was actually re-run, not merely believed;
//   - a secrets finding is never auto-fixable, because only a human can
//     rotate a leaked credential;
//   - a blast-radius finding is always scoped to declared targets.
func (f *Finding) Validate() error {
	var errs []error
	bad := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}

	if f.SchemaVersion != SchemaVersion {
		bad("schema_version is %q, want %q", f.SchemaVersion, SchemaVersion)
	}
	if !findingIDPattern.MatchString(f.FindingID) {
		bad("finding_id %q is not vk- followed by 12 hex characters", f.FindingID)
	} else if want := ComputeID(f.RuleID, f.Location, f.Evidence.EvidenceKey); want != f.FindingID {
		bad("finding_id %q is not the stable hash of its own content (want %q)", f.FindingID, want)
	}
	if !ruleIDPattern.MatchString(f.RuleID) {
		bad("rule_id %q must be lowercase dotted or dashed segments", f.RuleID)
	}
	if strings.TrimSpace(f.Title) == "" {
		bad("title is empty")
	}
	if !validCategories[f.Category] {
		bad("category %q is not a known category", f.Category)
	}
	if f.CWE != "" && !cwePattern.MatchString(f.CWE) {
		bad("cwe %q must look like CWE-123", f.CWE)
	}
	if _, ok := f.Severity.Weight(); !ok {
		bad("severity %q is not a known severity", f.Severity)
	}
	if _, ok := f.Confidence.Weight(); !ok {
		bad("confidence %q is not a known confidence", f.Confidence)
	}
	if !validSources[f.Source] {
		bad("source %q is not a known source", f.Source)
	}
	if !validStatuses[f.Status] {
		bad("status %q is not a known status", f.Status)
	}
	if !validLocationTypes[f.Location.Type] {
		bad("location.type %q is not a known location type", f.Location.Type)
	}
	if strings.TrimSpace(f.Evidence.Summary) == "" {
		bad("evidence.summary is empty: every finding must say why it is believed")
	}
	if strings.TrimSpace(f.Remediation.Guidance) == "" {
		bad("remediation.guidance is empty")
	}

	switch f.Location.Type {
	case LocationCode:
		if f.Location.File == "" {
			bad("location.file is required for a code finding")
		}
	case LocationEndpoint:
		if f.Location.Endpoint == "" {
			bad("location.endpoint is required for an endpoint finding")
		}
	case LocationDependency:
		if f.Location.Package == "" {
			bad("location.package is required for a dependency finding")
		}
	case LocationConfig:
		if f.Location.File == "" {
			bad("location.file is required for a config finding")
		}
	}

	if f.Reproduction != nil && !validReproKinds[f.Reproduction.Kind] {
		bad("reproduction.kind %q is not http, script or static", f.Reproduction.Kind)
	}

	// Contract rule: confirmed means reproduced.
	if f.Confidence == ConfidenceConfirmed && f.Reproduction == nil {
		bad("confidence is confirmed but there is no reproduction: only a finding that was actually re-run non-destructively may claim confirmed")
	}

	// Contract rule: a leaked credential needs a human to rotate it.
	if f.Source == SourceSecrets {
		if f.Remediation.FixableByGiver {
			bad("a secrets finding must set remediation.fixable_by_giver=false: a credential has to be rotated by a human")
		}
		if strings.TrimSpace(f.Remediation.HumanRequiredReason) == "" {
			bad("a secrets finding must explain remediation.human_required_reason")
		}
	}

	// Contract rule: anything not auto-fixable must say why.
	if !f.Remediation.FixableByGiver && strings.TrimSpace(f.Remediation.HumanRequiredReason) == "" {
		bad("remediation.fixable_by_giver is false but human_required_reason is empty")
	}

	// Contract rule: cross-service findings stay inside declared scope.
	if f.Source == SourceBlastRadius && f.BlastRadius == nil {
		bad("a blast-radius finding must carry a blast_radius block")
	}
	if f.BlastRadius != nil {
		if f.BlastRadius.Scope != ScopeDeclaredOnly {
			bad("blast_radius.scope is %q, and the only legal value is %q", f.BlastRadius.Scope, ScopeDeclaredOnly)
		}
		if f.BlastRadius.ReachableFrom == "" {
			bad("blast_radius.reachable_from is empty")
		}
	}

	// Run artifacts get attached to tickets, so a recorded request must not
	// carry a bearer token. Checks record the seeded-user label instead.
	if r := f.Evidence.Request; r != nil {
		for name, value := range r.Headers {
			if isSecretHeader(name) && value != "" && !isRedacted(value) {
				bad("evidence.request.headers[%s] looks like a live credential; record the seeded-user label instead", name)
			}
		}
	}

	return errors.Join(errs...)
}

// secretHeaders are headers whose values must never be written to a run
// directory verbatim.
var secretHeaders = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"cookie":              true,
	"set-cookie":          true,
	"x-api-key":           true,
	"x-auth-token":        true,
	"x-access-token":      true,
	"api-key":             true,
}

func isSecretHeader(name string) bool {
	return secretHeaders[strings.ToLower(strings.TrimSpace(name))]
}

// RedactedMarker is what replaces a credential value in recorded evidence.
const RedactedMarker = "<redacted>"

func isRedacted(v string) bool {
	v = strings.TrimSpace(v)
	return v == RedactedMarker || strings.Contains(v, RedactedMarker)
}

// RedactHeaders returns a copy of headers with credential values replaced by
// RedactedMarker. Checks run recorded requests through this before storing
// them as evidence.
func RedactHeaders(headers map[string]string) map[string]string {
	if headers == nil {
		return nil
	}
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		if isSecretHeader(k) && v != "" {
			out[k] = RedactedMarker
			continue
		}
		out[k] = v
	}
	return out
}

// ValidateAll validates a batch, reporting every offending finding by index so
// a failing check is easy to locate.
func ValidateAll(fs []Finding) error {
	var errs []error
	for i := range fs {
		if err := fs[i].Validate(); err != nil {
			errs = append(errs, fmt.Errorf("finding %d (%s/%s): %w", i, fs[i].RuleID, fs[i].FindingID, err))
		}
	}
	return errors.Join(errs...)
}
