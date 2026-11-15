package finding

import (
	"encoding/json"
	"strings"
	"testing"
)

// validFinding returns a finding that passes Validate, for tests to mutate.
func validFinding() Finding {
	f := Finding{
		RuleID:     "idor.sequential-id-access",
		Title:      "Missing ownership check lets one user read another user's record",
		Category:   CategoryBrokenAccessControl,
		CWE:        "CWE-639",
		Severity:   SeverityHigh,
		Confidence: ConfidenceConfirmed,
		Source:     SourceDAST,
		Location: Location{
			Type:     LocationEndpoint,
			Endpoint: "GET /api/orders/{id}",
			File:     "src/routes/orders.js",
			Line:     42,
			Symbol:   "getOrder",
		},
		Evidence: Evidence{
			Summary:     "Request as seeded user A returned seeded user B's canary record.",
			Observed:    "200 OK, body contains user B's canary record",
			Expected:    "403 or 404",
			EvidenceKey: "canary:order:90001",
		},
		Reproduction: &Reproduction{Kind: ReproHTTP, Command: "vibekiller reproduce"},
		Remediation: Remediation{
			Guidance:       "Enforce a server-side ownership check at the data-access layer.",
			FixableByGiver: true,
		},
		Status: StatusOpen,
	}
	f.AssignID()
	return f
}

func TestAssignIDIsStableAndWellFormed(t *testing.T) {
	a := validFinding()
	b := validFinding()

	if a.FindingID != b.FindingID {
		t.Errorf("same issue produced different ids: %q vs %q", a.FindingID, b.FindingID)
	}
	if !findingIDPattern.MatchString(a.FindingID) {
		t.Errorf("finding_id %q does not match the contract pattern", a.FindingID)
	}
	if a.SchemaVersion != SchemaVersion {
		t.Errorf("AssignID left schema_version as %q", a.SchemaVersion)
	}
}

// The id must survive the edits that happen constantly in a live repo, or the
// run-to-run diff would flag unchanged code as new findings.
func TestIDIgnoresLineAndRevisionChurn(t *testing.T) {
	base := validFinding()

	tests := []struct {
		name   string
		mutate func(*Finding)
	}{
		{"line moved by an unrelated edit above", func(f *Finding) { f.Location.Line = 420 }},
		{"end line recorded", func(f *Finding) { f.Location.EndLine = 99 }},
		{"new commit", func(f *Finding) { f.Location.RepoRev = "deadbeefdeadbeefdeadbeefdeadbeef" }},
		{"severity re-rated", func(f *Finding) { f.Severity = SeverityCritical }},
		{"title reworded", func(f *Finding) { f.Title = "Something else entirely" }},
		{"concrete id probed differs", func(f *Finding) { f.Location.Endpoint = "GET /api/orders/90002" }},
		{"path separators flipped", func(f *Finding) { f.Location.File = "src\\routes\\orders.js" }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := base
			tc.mutate(&got)
			got.AssignID()
			if got.FindingID != base.FindingID {
				t.Errorf("id changed from %q to %q, but this is the same underlying issue", base.FindingID, got.FindingID)
			}
		})
	}
}

// Conversely, genuinely different issues must not collide.
func TestIDDistinguishesDifferentIssues(t *testing.T) {
	base := validFinding()

	tests := []struct {
		name   string
		mutate func(*Finding)
	}{
		{"different rule", func(f *Finding) { f.RuleID = "auth.missing-check" }},
		{"different route", func(f *Finding) { f.Location.Endpoint = "GET /api/invoices/{id}" }},
		{"different method", func(f *Finding) { f.Location.Endpoint = "DELETE /api/orders/{id}" }},
		{"different evidence key", func(f *Finding) { f.Evidence.EvidenceKey = "canary:order:90002:other" }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := base
			tc.mutate(&got)
			got.AssignID()
			if got.FindingID == base.FindingID {
				t.Errorf("distinct issues collided on id %q", got.FindingID)
			}
		})
	}
}

// Field-shuffling must not be able to forge a matching id.
func TestIDResistsFieldShuffling(t *testing.T) {
	a := Finding{RuleID: "a.b", Location: Location{Type: LocationCode, File: "x", Symbol: "y"}}
	b := Finding{RuleID: "a.b", Location: Location{Type: LocationCode, File: "xy", Symbol: ""}}
	a.AssignID()
	b.AssignID()
	if a.FindingID == b.FindingID {
		t.Error("components ran together: file+symbol boundaries are not separated in the hash")
	}
}

func TestNormalizeEndpoint(t *testing.T) {
	tests := []struct{ in, want string }{
		{"GET /api/orders/90001", "GET /api/orders/{id}"},
		{"get /API/Orders/90001", "GET /api/orders/{id}"},
		{"GET /api/orders/{id}", "GET /api/orders/{id}"},
		{"GET /api/orders/:id", "GET /api/orders/{id}"},
		{"GET /api/orders/<int:order_id>", "GET /api/orders/{id}"},
		{"GET /api/orders/550e8400-e29b-41d4-a716-446655440000", "GET /api/orders/{id}"},
		{"GET /api/orders/507f1f77bcf86cd799439011", "GET /api/orders/{id}"},
		{"GET /api/orders/90001?include=items", "GET /api/orders/{id}"},
		{"GET /api/orders/", "GET /api/orders"},
		{"/api/orders/7", "/api/orders/{id}"},
		{"", ""},
	}
	for _, tc := range tests {
		if got := NormalizeEndpoint(tc.in); got != tc.want {
			t.Errorf("NormalizeEndpoint(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestValidateAcceptsAWellFormedFinding(t *testing.T) {
	f := validFinding()
	if err := f.Validate(); err != nil {
		t.Fatalf("a well-formed finding was rejected: %v", err)
	}
}

func TestValidateEnforcesTheContract(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*Finding)
		wantInErr string
	}{
		{
			name:      "confirmed without a reproduction",
			mutate:    func(f *Finding) { f.Reproduction = nil },
			wantInErr: "confirmed",
		},
		{
			name: "secrets finding claiming to be auto-fixable",
			mutate: func(f *Finding) {
				f.Source = SourceSecrets
				f.Remediation.FixableByGiver = true
			},
			wantInErr: "rotated by a human",
		},
		{
			name: "secrets finding with no handoff reason",
			mutate: func(f *Finding) {
				f.Source = SourceSecrets
				f.Remediation.FixableByGiver = false
				f.Remediation.HumanRequiredReason = ""
			},
			wantInErr: "human_required_reason",
		},
		{
			name: "blast radius claiming wider scope",
			mutate: func(f *Finding) {
				f.Source = SourceBlastRadius
				f.BlastRadius = &BlastRadius{ReachableFrom: "service-A", Scope: "the-internet"}
			},
			wantInErr: "declared-targets-only",
		},
		{
			name:      "blast radius source with no blast radius block",
			mutate:    func(f *Finding) { f.Source = SourceBlastRadius },
			wantInErr: "must carry a blast_radius block",
		},
		{
			name: "a live token recorded in evidence",
			mutate: func(f *Finding) {
				f.Evidence.Request = &Request{
					Method:  "GET",
					Path:    "/api/orders/90001",
					Headers: map[string]string{"Authorization": "Bearer eyJhbGciOi.realtoken.value"},
				}
			},
			wantInErr: "live credential",
		},
		{
			name:      "unknown severity",
			mutate:    func(f *Finding) { f.Severity = "apocalyptic" },
			wantInErr: "severity",
		},
		{
			name:      "unknown category",
			mutate:    func(f *Finding) { f.Category = "vibes" },
			wantInErr: "category",
		},
		{
			name:      "empty evidence summary",
			mutate:    func(f *Finding) { f.Evidence.Summary = "" },
			wantInErr: "evidence.summary",
		},
		{
			name:      "malformed rule id",
			mutate:    func(f *Finding) { f.RuleID = "IDOR Sequential Access" },
			wantInErr: "rule_id",
		},
		{
			name:      "not auto-fixable without a reason",
			mutate:    func(f *Finding) { f.Remediation.FixableByGiver = false },
			wantInErr: "human_required_reason",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := validFinding()
			tc.mutate(&f)
			// Re-derive the id where the mutation changed identity inputs, so
			// the test fails on the rule under test, not on an id mismatch.
			f.AssignID()

			err := f.Validate()
			if err == nil {
				t.Fatalf("Validate accepted a finding that breaks the contract: %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantInErr) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.wantInErr)
			}
		})
	}
}

// A tampered id must be caught: findings.json is an interchange format and the
// consumer has to be able to trust that an id describes its own content.
func TestValidateRejectsATamperedID(t *testing.T) {
	f := validFinding()
	f.FindingID = "vk-000000000000"
	err := f.Validate()
	if err == nil || !strings.Contains(err.Error(), "stable hash") {
		t.Fatalf("expected a stable-hash mismatch error, got %v", err)
	}
}

func TestRedactHeaders(t *testing.T) {
	in := map[string]string{
		"Authorization": "Bearer secret-value",
		"Cookie":        "session=abc",
		"X-API-Key":     "k-123",
		"Accept":        "application/json",
	}
	out := RedactHeaders(in)

	for _, k := range []string{"Authorization", "Cookie", "X-API-Key"} {
		if out[k] != RedactedMarker {
			t.Errorf("header %s was not redacted: %q", k, out[k])
		}
	}
	if out["Accept"] != "application/json" {
		t.Errorf("a harmless header was altered: %q", out["Accept"])
	}
	if in["Authorization"] != "Bearer secret-value" {
		t.Error("RedactHeaders mutated its input")
	}
}

func TestSeverityThresholdGate(t *testing.T) {
	tests := []struct {
		sev, threshold Severity
		want           bool
	}{
		{SeverityCritical, SeverityHigh, true},
		{SeverityHigh, SeverityHigh, true},
		{SeverityMedium, SeverityHigh, false},
		{SeverityInfo, SeverityInfo, true},
		{SeverityLow, "nonsense", false},
	}
	for _, tc := range tests {
		if got := tc.sev.AtLeast(tc.threshold); got != tc.want {
			t.Errorf("%s.AtLeast(%s) = %v, want %v", tc.sev, tc.threshold, got, tc.want)
		}
	}
}

func TestSummarizeAndMaxSeverity(t *testing.T) {
	fs := []Finding{
		{Severity: SeverityHigh, Source: SourceSAST, Confidence: ConfidenceLikely},
		{Severity: SeverityCritical, Source: SourceDAST, Confidence: ConfidenceConfirmed},
		{Severity: SeverityHigh, Source: SourceDAST, Confidence: ConfidenceConfirmed},
	}

	c := Summarize(fs)
	if c.Total != 3 || c.BySeverity["high"] != 2 || c.BySource["dast"] != 2 || c.Confirmed != 2 {
		t.Errorf("unexpected counts: %+v", c)
	}

	if max, ok := MaxSeverity(fs); !ok || max != SeverityCritical {
		t.Errorf("MaxSeverity = %q (ok=%v), want critical", max, ok)
	}
	if _, ok := MaxSeverity(nil); ok {
		t.Error("MaxSeverity reported a severity for an empty set")
	}
}

// The on-disk shape is the contract, so lock the JSON field names down.
func TestFindingJSONFieldNames(t *testing.T) {
	b, err := json.Marshal(validFinding())
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{
		"schema_version", "finding_id", "rule_id", "title", "category", "cwe",
		"severity", "confidence", "source", "location", "evidence",
		"reproduction", "remediation", "status",
	} {
		if _, ok := generic[key]; !ok {
			t.Errorf("contract field %q is missing from the marshalled finding", key)
		}
	}

	// Optional blocks must stay absent rather than serialize as null.
	if _, ok := generic["blast_radius"]; ok {
		t.Error("blast_radius should be omitted when there is no cross-service exposure")
	}
}
