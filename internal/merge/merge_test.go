package merge

import (
	"testing"

	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
)

// linker mirrors what the rule pack declares: the dynamic check
// idor.sequential-id-access confirms the static rule
// idor.missing-ownership-check.
func linker() Linker {
	return Linker{"idor.sequential-id-access": "idor.missing-ownership-check"}
}

func staticIDOR() finding.Finding {
	f := finding.Finding{
		RuleID:     "idor.missing-ownership-check",
		Title:      "Route looks up a record without checking ownership",
		Category:   finding.CategoryBrokenAccessControl,
		CWE:        "CWE-639",
		Severity:   finding.SeverityHigh,
		Confidence: finding.ConfidenceLikely,
		Source:     finding.SourceSAST,
		Location: finding.Location{
			Type: finding.LocationCode,
			File: "src/routes/orders.js", Line: 42, Symbol: "getOrder",
		},
		Evidence: finding.Evidence{
			Summary: "The handler queries by a client-supplied id.",
			Snippet: "const order = orders.find((o) => o.id === Number(req.params.id))",
			TaintPath: []finding.TaintStep{
				{File: "src/routes/orders.js", Line: 41, Note: "input enters here"},
				{File: "src/routes/orders.js", Line: 42, Note: "reaches the sink here"},
			},
			EvidenceKey: "semgrep:idor",
		},
		Reproduction: &finding.Reproduction{Kind: finding.ReproStatic},
		Remediation: finding.Remediation{
			Guidance:       "Scope the query to the caller.",
			RootCauseHint:  "Authorization missing at the data layer.",
			FixableByGiver: true,
		},
		Status: finding.StatusOpen,
	}
	f.AssignID()
	return f
}

func dynamicIDOR() finding.Finding {
	f := finding.Finding{
		RuleID:     "idor.sequential-id-access",
		Title:      "userA can read userB's record",
		Category:   finding.CategoryBrokenAccessControl,
		CWE:        "CWE-639",
		Severity:   finding.SeverityHigh,
		Confidence: finding.ConfidenceConfirmed,
		Source:     finding.SourceDAST,
		Location: finding.Location{
			Type:     finding.LocationEndpoint,
			Endpoint: "GET /api/orders/{id}",
			File:     "src/routes/orders.js", Line: 42, Symbol: "getOrder",
		},
		Evidence: finding.Evidence{
			Summary:     "Request as userA returned userB's canary record.",
			Observed:    "200 OK with the canary",
			Expected:    "403 or 404",
			EvidenceKey: "canary:order:90001",
		},
		Reproduction: &finding.Reproduction{
			Kind: finding.ReproHTTP, ArtifactPath: "runs/x/repro/vk-abc.http",
		},
		Remediation: finding.Remediation{
			Guidance:       "Scope the query to the caller.",
			FixableByGiver: true,
		},
		Status: finding.StatusOpen,
	}
	f.AssignID()
	return f
}

// This is the behaviour the whole merge step exists for: the static rule found
// the cause and the endpoint check proved it, and the operator should see one
// finding that is confirmed, not two that each tell half the story.
func TestStaticAndDynamicFindingsMergeAndRaiseConfidence(t *testing.T) {
	in := []finding.Finding{staticIDOR(), dynamicIDOR()}

	out := Dedupe(in, linker())
	if len(out) != 1 {
		t.Fatalf("got %d findings, want them merged into one: %+v", len(out), out)
	}
	f := out[0]

	if f.Confidence != finding.ConfidenceConfirmed {
		t.Errorf("confidence = %q, want confirmed: the dynamic half reproduced it", f.Confidence)
	}
	// Identity comes from the static half, which is anchored to a file and a
	// symbol and therefore survives a later static-only run.
	if f.FindingID != staticIDOR().FindingID {
		t.Errorf("merged id = %q, want the static finding's id %q", f.FindingID, staticIDOR().FindingID)
	}
	if f.RuleID != "idor.missing-ownership-check" {
		t.Errorf("rule_id = %q", f.RuleID)
	}
	// The reproduction must be the one that can actually be re-run.
	if f.Reproduction == nil || f.Reproduction.Kind != finding.ReproHTTP {
		t.Errorf("reproduction = %+v, want the HTTP one", f.Reproduction)
	}
	// Both views survive: the live observation and the cause.
	if f.Evidence.Snippet == "" {
		t.Error("the static snippet was lost")
	}
	if len(f.Evidence.TaintPath) != 2 {
		t.Error("the taint path was lost")
	}
	if f.Evidence.Observed == "" {
		t.Error("the live observation was lost")
	}
	// The location must carry both halves.
	if f.Location.Endpoint == "" || f.Location.File == "" {
		t.Errorf("location lost a half: %+v", f.Location)
	}
	if len(f.MergedFrom) != 2 {
		t.Errorf("merged_from = %v, want both sources recorded", f.MergedFrom)
	}

	if err := f.Validate(); err != nil {
		t.Errorf("the merged finding breaks the contract: %v", err)
	}
}

// Without the link, the two findings have different rule ids and different
// location types, so nothing could recognize them as one issue.
func TestWithoutTheRuleLinkTheyStaySeparate(t *testing.T) {
	out := Dedupe([]finding.Finding{staticIDOR(), dynamicIDOR()}, nil)
	if len(out) != 2 {
		t.Errorf("got %d findings, want them kept separate with no linker: %+v", len(out), out)
	}
}

func TestExactDuplicatesCollapse(t *testing.T) {
	f := staticIDOR()
	out := Dedupe([]finding.Finding{f, f, f}, linker())
	if len(out) != 1 {
		t.Errorf("got %d, want 1", len(out))
	}
}

// A dependency advisory and a code finding must never merge, however their
// paths line up.
func TestDependencyFindingsStayDistinct(t *testing.T) {
	dep := func(pkg, advisory string) finding.Finding {
		f := finding.Finding{
			RuleID: "deps.known-vulnerability", Title: pkg,
			Category: finding.CategoryVulnerableDep, Severity: finding.SeverityHigh,
			Confidence: finding.ConfidenceLikely, Source: finding.SourceDeps,
			Location: finding.Location{
				Type: finding.LocationDependency, File: "package-lock.json",
				Package: pkg, Ecosystem: "npm", Version: "1.0.0",
			},
			Evidence:    finding.Evidence{Summary: "advisory", EvidenceKey: "osv:" + advisory},
			Remediation: finding.Remediation{Guidance: "upgrade", FixableByGiver: true},
			Status:      finding.StatusOpen,
		}
		f.AssignID()
		return f
	}

	in := []finding.Finding{
		dep("lodash", "GHSA-1"),
		dep("lodash", "GHSA-2"),
		dep("minimist", "GHSA-3"),
		staticIDOR(),
	}

	out := Dedupe(in, linker())
	if len(out) != 4 {
		t.Errorf("got %d findings, want 4 distinct ones: %+v", len(out), out)
	}
}

// Two different credentials in one file are two findings. Collapsing them
// would leave one unrotated.
func TestTwoSecretsInOneFileStayDistinct(t *testing.T) {
	secret := func(fp string) finding.Finding {
		f := finding.Finding{
			RuleID: "secrets.generic-api-key", Title: "credential",
			Category: finding.CategorySecretsExposure, Severity: finding.SeverityHigh,
			Confidence: finding.ConfidenceLikely, Source: finding.SourceSecrets,
			Location: finding.Location{Type: finding.LocationCode, File: "src/config.js", Line: 7},
			Evidence: finding.Evidence{Summary: "credential found", EvidenceKey: "gitleaks:" + fp},
			Remediation: finding.Remediation{
				Guidance: "rotate", FixableByGiver: false,
				HumanRequiredReason: "a person must rotate it",
			},
			Status: finding.StatusOpen,
		}
		f.AssignID()
		return f
	}

	out := Dedupe([]finding.Finding{secret("aaa"), secret("bbb")}, linker())
	if len(out) != 2 {
		t.Errorf("got %d, want both credentials reported: %+v", len(out), out)
	}
}

// If any engine says a human is required, the merged finding says so. Losing
// that would hand the Giver a credential to rotate.
func TestMergingNeverMakesAFindingAutoFixable(t *testing.T) {
	a := staticIDOR()
	a.Remediation.FixableByGiver = false
	a.Remediation.HumanRequiredReason = "the signing key is already disclosed and must be rotated"

	b := dynamicIDOR()
	b.Remediation.FixableByGiver = true

	out := Dedupe([]finding.Finding{a, b}, linker())
	if len(out) != 1 {
		t.Fatalf("got %d", len(out))
	}
	if out[0].Remediation.FixableByGiver {
		t.Error("the merged finding claims to be auto-fixable although one half said a human is required")
	}
	if out[0].Remediation.HumanRequiredReason == "" {
		t.Error("the reason a human is required was lost")
	}
}

func TestMergeTakesTheWorstSeverity(t *testing.T) {
	a := staticIDOR()
	a.Severity = finding.SeverityMedium
	b := dynamicIDOR()
	b.Severity = finding.SeverityCritical

	out := Dedupe([]finding.Finding{a, b}, linker())
	if len(out) != 1 {
		t.Fatalf("got %d", len(out))
	}
	if out[0].Severity != finding.SeverityCritical {
		t.Errorf("severity = %q, want critical", out[0].Severity)
	}
}

// --- ranking ---------------------------------------------------------------

// A confirmed high outranks a heuristic critical. The tool exists to surface
// what someone can act on now, and a reproduced finding needs no triage.
func TestConfirmedHighOutranksHeuristicCritical(t *testing.T) {
	confirmedHigh := dynamicIDOR()

	heuristicCritical := staticIDOR()
	heuristicCritical.Severity = finding.SeverityCritical
	heuristicCritical.Confidence = finding.ConfidenceHeuristic
	heuristicCritical.Evidence.TaintPath = nil
	heuristicCritical.RuleID = "injection.sql-string-built-from-input"
	heuristicCritical.AssignID()

	out := Rank([]finding.Finding{heuristicCritical, confirmedHigh})
	if out[0].Confidence != finding.ConfidenceConfirmed {
		t.Errorf("ranking put %s/%s first, want the confirmed finding",
			out[0].Severity, out[0].Confidence)
	}
	if out[0].Rank <= out[1].Rank {
		t.Errorf("rank scores are not ordered: %v then %v", out[0].Rank, out[1].Rank)
	}
}

// A dependency advisory is certain about the version and silent about whether
// the app reaches the vulnerable code, so it is discounted against a finding
// of the same severity that was observed.
func TestDependencyFindingsAreDiscountedAgainstObservedOnes(t *testing.T) {
	dep := finding.Finding{
		RuleID: "deps.known-vulnerability", Title: "dep", Severity: finding.SeverityHigh,
		Confidence: finding.ConfidenceLikely, Source: finding.SourceDeps,
		Category: finding.CategoryVulnerableDep,
		Location: finding.Location{Type: finding.LocationDependency, Package: "x"},
		Evidence: finding.Evidence{Summary: "s"}, Status: finding.StatusOpen,
		Remediation: finding.Remediation{Guidance: "g", FixableByGiver: true},
	}
	dep.AssignID()

	observed := dynamicIDOR()

	out := Rank([]finding.Finding{dep, observed})
	if out[0].Source != finding.SourceDAST {
		t.Errorf("the dependency advisory outranked a reproduced finding of the same severity")
	}
}

// A static finding with a full source-to-sink path has shown that input
// actually reaches the sink, which is a stronger claim than a single-line
// pattern match.
func TestTaintPathRaisesExploitability(t *testing.T) {
	withPath := staticIDOR()
	withoutPath := staticIDOR()
	withoutPath.Evidence.TaintPath = nil
	withoutPath.Location.Symbol = "otherHandler"
	withoutPath.AssignID()

	out := Rank([]finding.Finding{withoutPath, withPath})
	if out[0].Location.Symbol != "getOrder" {
		t.Error("the finding with a data-flow path did not rank higher")
	}
}

func TestRankingIsDeterministic(t *testing.T) {
	in := []finding.Finding{staticIDOR(), dynamicIDOR()}

	first := Rank(in)
	second := Rank(in)
	for i := range first {
		if first[i].FindingID != second[i].FindingID {
			t.Fatalf("ranking is not stable at position %d", i)
		}
	}
	// Ranking must not mutate its input, or a caller's slice would be
	// reordered behind its back.
	if in[0].RuleID != "idor.missing-ownership-check" {
		t.Error("Rank reordered its input slice")
	}
}

func TestProcessWithSummary(t *testing.T) {
	out, summary := ProcessWithSummary([]finding.Finding{staticIDOR(), dynamicIDOR()}, linker())
	if len(out) != 1 {
		t.Fatalf("got %d", len(out))
	}
	if summary.Before != 2 || summary.After != 1 || summary.Merged != 1 {
		t.Errorf("summary = %+v", summary)
	}
	if summary.String() == "" {
		t.Error("the summary has no description")
	}

	_, none := ProcessWithSummary([]finding.Finding{staticIDOR()}, linker())
	if none.Merged != 0 {
		t.Errorf("merged = %d, want 0", none.Merged)
	}
}

func TestDedupeHandlesEmptyAndSingle(t *testing.T) {
	if out := Dedupe(nil, linker()); len(out) != 0 {
		t.Errorf("got %d from nil", len(out))
	}
	if out := Dedupe([]finding.Finding{staticIDOR()}, linker()); len(out) != 1 {
		t.Errorf("got %d from one", len(out))
	}
}
