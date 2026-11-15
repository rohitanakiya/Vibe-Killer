// Package merge de-duplicates and ranks findings.
//
// The same weakness is often seen by more than one engine: a static rule spots
// the missing ownership check in the source, and an endpoint check then proves
// it against the running instance. Reported separately they look like two
// problems and the operator has to work out that they are one. Merged, they
// are a single finding whose confidence is raised to confirmed because the
// dynamic half actually reproduced it.
//
// Ranking then orders what is left by how much it deserves attention, rather
// than by severity alone: a heuristic critical is usually worth less than a
// confirmed high.
package merge

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
)

// Linker maps a dynamic check's rule id to the static rule it confirms.
//
// This comes from the rule pack's dynamic_rule metadata, which is how a static
// rule declares that an endpoint check exists to confirm it. Without the link,
// two findings about one weakness cannot be recognized as related, because
// their rule ids and location types both differ.
type Linker map[string]string

// canonical returns the rule id a finding should be grouped under.
func (l Linker) canonical(ruleID string) string {
	if l == nil {
		return ruleID
	}
	if static, ok := l[ruleID]; ok && static != "" {
		return static
	}
	return ruleID
}

// sourceStability orders sources by how stable their identity is between runs.
//
// The merged finding inherits its finding_id from the most stable contributor.
// A static finding is anchored to a file and a symbol, which persist as long
// as the code does; a dynamic finding exists only while the instance is
// running and reachable. Taking identity from the static half means the
// finding keeps its id on a later static-only run instead of looking new.
var sourceStability = map[finding.Source]int{
	finding.SourceSAST:        0,
	finding.SourceDeps:        1,
	finding.SourceSecrets:     2,
	finding.SourceDAST:        3,
	finding.SourceRuntime:     4,
	finding.SourceBlastRadius: 5,
}

func stability(s finding.Source) int {
	if v, ok := sourceStability[s]; ok {
		return v
	}
	return 9
}

// Dedupe merges findings that describe the same underlying issue.
//
// Two findings are grouped when they share a canonical rule and either an
// endpoint or a file-and-symbol location. Grouping is transitive, so a static
// finding and a dynamic finding that each overlap a runtime finding all end up
// together.
func Dedupe(fs []finding.Finding, linker Linker) []finding.Finding {
	if len(fs) <= 1 {
		return fs
	}

	// Exact duplicates first: the same check reporting twice, or two engines
	// producing a byte-identical finding.
	seen := map[string]int{}
	var unique []finding.Finding
	for _, f := range fs {
		if idx, dup := seen[f.FindingID]; dup {
			unique[idx] = mergePair(unique[idx], f)
			continue
		}
		seen[f.FindingID] = len(unique)
		unique = append(unique, f)
	}

	// Union-find over the identity keys.
	parent := make([]int, len(unique))
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(i int) int {
		for parent[i] != i {
			parent[i] = parent[parent[i]]
			i = parent[i]
		}
		return i
	}
	union := func(a, b int) {
		ra, rb := find(a), find(b)
		if ra != rb {
			parent[rb] = ra
		}
	}

	byKey := map[string]int{}
	for i, f := range unique {
		for _, key := range identityKeys(f, linker) {
			if j, ok := byKey[key]; ok {
				union(j, i)
				continue
			}
			byKey[key] = i
		}
	}

	groups := map[int][]finding.Finding{}
	var order []int
	for i, f := range unique {
		root := find(i)
		if _, ok := groups[root]; !ok {
			order = append(order, root)
		}
		groups[root] = append(groups[root], f)
	}

	out := make([]finding.Finding, 0, len(order))
	for _, root := range order {
		out = append(out, mergeGroup(groups[root]))
	}
	return out
}

// identityKeys returns the keys a finding can be grouped by. A finding with
// both an endpoint and a code location yields both, which is what bridges the
// static and dynamic views of one weakness.
func identityKeys(f finding.Finding, linker Linker) []string {
	rule := linker.canonical(f.RuleID)
	var keys []string

	if ep := strings.TrimSpace(f.Location.Endpoint); ep != "" {
		keys = append(keys, "ep|"+rule+"|"+finding.NormalizeEndpoint(ep))
	}
	if f.Location.File != "" && f.Location.Symbol != "" {
		keys = append(keys, "sym|"+rule+"|"+strings.ToLower(f.Location.File)+"|"+strings.ToLower(f.Location.Symbol))
	}
	// A dependency finding is identified by package and advisory, never by a
	// code location, so it never merges with a code finding by accident.
	if f.Location.Type == finding.LocationDependency {
		keys = []string{"dep|" + rule + "|" + strings.ToLower(f.Location.Package) + "|" + f.Evidence.EvidenceKey}
	}
	// A secrets finding is identified by its credential fingerprint. Two
	// different credentials in one file must stay separate.
	if f.Source == finding.SourceSecrets {
		keys = []string{"secret|" + rule + "|" + strings.ToLower(f.Location.File) + "|" + f.Evidence.EvidenceKey}
	}

	if len(keys) == 0 {
		// Nothing to group on; keep the finding distinct by its own id.
		keys = append(keys, "id|"+f.FindingID)
	}
	return keys
}

// mergeGroup folds a group of findings about one issue into a single finding.
func mergeGroup(group []finding.Finding) finding.Finding {
	if len(group) == 1 {
		return group[0]
	}

	// Identity comes from the most stable contributor; content comes from the
	// most convincing one.
	sort.SliceStable(group, func(i, j int) bool {
		return stability(group[i].Source) < stability(group[j].Source)
	})
	primary := group[0]

	out := primary
	var sources []finding.Source
	seenSource := map[finding.Source]bool{}

	for _, f := range group {
		if !seenSource[f.Source] {
			seenSource[f.Source] = true
			sources = append(sources, f.Source)
		}
	}

	for _, f := range group[1:] {
		out = mergePair(out, f)
	}

	// Keep the identity of the stable contributor even though content may have
	// come from elsewhere.
	out.FindingID = primary.FindingID
	out.RuleID = primary.RuleID

	sort.Slice(sources, func(i, j int) bool { return stability(sources[i]) < stability(sources[j]) })
	out.MergedFrom = sources

	return out
}

// mergePair folds b into a.
func mergePair(a, b finding.Finding) finding.Finding {
	out := a

	// Severity: the worst assessment wins. If one engine thinks this is
	// critical, the finding is critical.
	if bw, ok := b.Severity.Weight(); ok {
		if aw, ok2 := a.Severity.Weight(); !ok2 || bw > aw {
			out.Severity = b.Severity
		}
	}

	// Confidence: the strongest evidence wins. This is the whole point of
	// merging. A static pattern match that an endpoint check then reproduced
	// is confirmed, and must carry the reproduction that justifies the claim.
	aConf, _ := a.Confidence.Weight()
	bConf, _ := b.Confidence.Weight()
	if bConf > aConf {
		out.Confidence = b.Confidence
		if b.Reproduction != nil {
			out.Reproduction = b.Reproduction
		}
		// Live evidence replaces inferred evidence, but the static summary is
		// kept alongside it because it explains the cause rather than the
		// symptom.
		if b.Evidence.Summary != "" {
			merged := b.Evidence
			merged.EvidenceKey = out.Evidence.EvidenceKey
			if a.Evidence.Snippet != "" && merged.Snippet == "" {
				merged.Snippet = a.Evidence.Snippet
			}
			if len(a.Evidence.TaintPath) > 0 && len(merged.TaintPath) == 0 {
				merged.TaintPath = a.Evidence.TaintPath
			}
			if a.Evidence.Summary != "" {
				merged.Summary = b.Evidence.Summary + " Static analysis also flagged this: " + a.Evidence.Summary
			}
			out.Evidence = merged
		}
	} else {
		// b is no more convincing, but it may still fill gaps.
		if out.Evidence.Snippet == "" {
			out.Evidence.Snippet = b.Evidence.Snippet
		}
		if len(out.Evidence.TaintPath) == 0 {
			out.Evidence.TaintPath = b.Evidence.TaintPath
		}
		if out.Reproduction == nil {
			out.Reproduction = b.Reproduction
		}
	}

	// Location: take the union, since the static half knows the file and the
	// dynamic half knows the endpoint.
	out.Location = mergeLocation(out.Location, b.Location)

	if out.CWE == "" {
		out.CWE = b.CWE
	}
	if out.BlastRadius == nil {
		out.BlastRadius = b.BlastRadius
	}

	// Remediation: a finding that any engine says needs a human, needs a
	// human. Collapsing that to "fixable" would hand the Giver a credential
	// to rotate.
	if !b.Remediation.FixableByGiver {
		out.Remediation.FixableByGiver = false
		if out.Remediation.HumanRequiredReason == "" {
			out.Remediation.HumanRequiredReason = b.Remediation.HumanRequiredReason
		}
	}
	if out.Remediation.RootCauseHint == "" {
		out.Remediation.RootCauseHint = b.Remediation.RootCauseHint
	}
	out.Remediation.References = mergeStrings(out.Remediation.References, b.Remediation.References)

	return out
}

func mergeLocation(a, b finding.Location) finding.Location {
	out := a
	if out.File == "" {
		out.File = b.File
	}
	if out.Line == 0 {
		out.Line = b.Line
	}
	if out.EndLine == 0 {
		out.EndLine = b.EndLine
	}
	if out.Symbol == "" {
		out.Symbol = b.Symbol
	}
	if out.Endpoint == "" {
		out.Endpoint = b.Endpoint
	}
	if out.Package == "" {
		out.Package = b.Package
	}
	if out.Ecosystem == "" {
		out.Ecosystem = b.Ecosystem
	}
	if out.Version == "" {
		out.Version = b.Version
	}
	if out.ConfigKey == "" {
		out.ConfigKey = b.ConfigKey
	}
	if out.RepoRev == "" {
		out.RepoRev = b.RepoRev
	}
	return out
}

func mergeStrings(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string{}, a...), b...) {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	if len(out) > 6 {
		out = out[:6]
	}
	return out
}

// severityScore maps a severity to a numeric weight for ranking.
var severityScore = map[finding.Severity]float64{
	finding.SeverityInfo:     1,
	finding.SeverityLow:      2,
	finding.SeverityMedium:   4,
	finding.SeverityHigh:     8,
	finding.SeverityCritical: 16,
}

// confidenceScore is the multiplier for how sure the finding is.
//
// The gap between likely and confirmed is deliberately wide. The tool's
// purpose is to surface issues someone can act on immediately, and a
// reproduced finding needs no triage before the fix starts.
var confidenceScore = map[finding.Confidence]float64{
	finding.ConfidenceHeuristic: 0.35,
	finding.ConfidenceLikely:    0.65,
	finding.ConfidenceConfirmed: 1.0,
}

// exploitability estimates how directly the weakness can be used.
//
// This is where a dependency advisory is discounted: the database is certain
// the version is affected, but nothing has shown that the application reaches
// the vulnerable code. A credential found in the repository gets the opposite
// treatment, since it is usable as-is.
func exploitability(f finding.Finding) float64 {
	switch f.Source {
	case finding.SourceDAST, finding.SourceRuntime:
		return 1.0
	case finding.SourceSecrets:
		return 0.9
	case finding.SourceDeps:
		return 0.5
	case finding.SourceBlastRadius:
		return 0.8
	}

	// A static finding with a full source-to-sink path has shown that input
	// actually reaches the sink, which is a stronger claim than a pattern
	// match on one line.
	if len(f.Evidence.TaintPath) > 0 {
		return 0.75
	}
	return 0.55
}

// Rank computes each finding's score and sorts the slice, worst first.
func Rank(fs []finding.Finding) []finding.Finding {
	out := append([]finding.Finding(nil), fs...)

	for i := range out {
		sev := severityScore[out[i].Severity]
		conf := confidenceScore[out[i].Confidence]
		out[i].Rank = round2(sev * conf * exploitability(out[i]))
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Rank != out[j].Rank {
			return out[i].Rank > out[j].Rank
		}
		// Deterministic tie-break, so two runs of the same repo order
		// identically and the report diffs cleanly.
		if out[i].Severity != out[j].Severity {
			iw, _ := out[i].Severity.Weight()
			jw, _ := out[j].Severity.Weight()
			return iw > jw
		}
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		return out[i].FindingID < out[j].FindingID
	})

	return out
}

func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}

// Process is the reporter's entry point: merge, then rank.
func Process(fs []finding.Finding, linker Linker) []finding.Finding {
	return Rank(Dedupe(fs, linker))
}

// Summary describes what merging did, for the run log.
type Summary struct {
	Before int
	After  int
	Merged int
}

func (s Summary) String() string {
	if s.Merged == 0 {
		return fmt.Sprintf("%d findings, none merged", s.After)
	}
	return fmt.Sprintf("%d findings after merging %d duplicate report(s) from %d raw", s.After, s.Merged, s.Before)
}

// ProcessWithSummary merges and ranks, and reports what changed.
func ProcessWithSummary(fs []finding.Finding, linker Linker) ([]finding.Finding, Summary) {
	out := Process(fs, linker)
	return out, Summary{Before: len(fs), After: len(out), Merged: len(fs) - len(out)}
}
