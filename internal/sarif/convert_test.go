package sarif

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
	"github.com/rohitanakiya/Vibe-Killer/internal/surface"
)

func codeFinding(ruleID string, sev finding.Severity) finding.Finding {
	f := finding.Finding{
		RuleID:     ruleID,
		Title:      "a problem in handlerA",
		Category:   finding.CategoryBrokenAccessControl,
		CWE:        "CWE-639",
		Severity:   sev,
		Confidence: finding.ConfidenceLikely,
		Source:     finding.SourceSAST,
		Location: finding.Location{
			Type: finding.LocationCode, File: "src/app.js", Line: 42, EndLine: 44, Symbol: "handlerA",
		},
		Evidence:    finding.Evidence{Summary: "owner check absent", EvidenceKey: ruleID},
		Remediation: finding.Remediation{Guidance: "scope the query by owner", FixableByGiver: true},
		Status:      finding.StatusOpen,
	}
	f.AssignID()
	return f
}

func endpointFinding(endpoint string) finding.Finding {
	f := finding.Finding{
		RuleID:     "authz.unprotected-endpoint",
		Title:      "anonymous request returned a seeded canary",
		Category:   finding.CategoryBrokenAccessControl,
		Severity:   finding.SeverityHigh,
		Confidence: finding.ConfidenceConfirmed,
		Source:     finding.SourceDAST,
		Location:   finding.Location{Type: finding.LocationEndpoint, Endpoint: endpoint},
		Evidence:   finding.Evidence{Summary: "read canary 4242", EvidenceKey: endpoint},
		// Confirmed findings must carry a reproduction; the contract enforces
		// it elsewhere and the converter reads it for a property.
		Reproduction: &finding.Reproduction{Kind: finding.ReproHTTP},
		Remediation:  finding.Remediation{Guidance: "require authentication", FixableByGiver: true},
		Status:       finding.StatusOpen,
	}
	f.AssignID()
	return f
}

func doc(findings ...finding.Finding) *finding.Document {
	return &finding.Document{
		SchemaVersion: finding.DocumentSchemaVersion,
		RunID:         "20260101-000000-abc",
		GeneratedAt:   "2026-01-01T00:00:00Z",
		RepoPath:      ".",
		Counts:        finding.Summarize(findings),
		Findings:      findings,
	}
}

// GitHub rejects an upload outright when a required property is missing, and a
// rejected upload is indistinguishable from a tool nobody integrated. These
// are the properties its documentation marks required, asserted over the
// serialized JSON rather than the structs, because a json tag typo would pass
// a struct-level check and still fail the upload.
func TestEveryRequiredPropertyIsPresentInTheJSON(t *testing.T) {
	log := Convert(doc(
		codeFinding("idor.sequential-id-access", finding.SeverityCritical),
		endpointFinding("GET /orders/{id}"),
	), Options{ToolVersion: "0.2.0", InformationURI: "https://example.invalid/vk"})

	raw, err := json.Marshal(log)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}

	if m["$schema"] != SchemaURI {
		t.Errorf("$schema = %v, want %q", m["$schema"], SchemaURI)
	}
	if m["version"] != "2.1.0" {
		t.Errorf("version = %v, want 2.1.0 (code scanning supports no other)", m["version"])
	}

	runs, _ := m["runs"].([]any)
	if len(runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(runs))
	}
	run := runs[0].(map[string]any)

	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	if driver["name"] == "" || driver["name"] == nil {
		t.Error("tool.driver.name is required")
	}

	rules, _ := driver["rules"].([]any)
	if len(rules) == 0 {
		t.Fatal("tool.driver.rules is required and must not be empty")
	}
	for i, r := range rules {
		rule := r.(map[string]any)
		for _, key := range []string{"id", "shortDescription", "fullDescription", "help"} {
			v, ok := rule[key]
			if !ok || v == nil {
				t.Errorf("rules[%d] is missing required %q", i, key)
				continue
			}
			if key != "id" {
				if text, _ := v.(map[string]any)["text"].(string); strings.TrimSpace(text) == "" {
					// "The empty string is not supported for required
					// properties."
					t.Errorf("rules[%d].%s.text is empty", i, key)
				}
			}
		}
	}

	results, _ := run["results"].([]any)
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2", len(results))
	}
	for i, r := range results {
		res := r.(map[string]any)
		if text, _ := res["message"].(map[string]any)["text"].(string); strings.TrimSpace(text) == "" {
			t.Errorf("results[%d].message.text is empty", i)
		}
		locs, _ := res["locations"].([]any)
		if len(locs) == 0 {
			t.Errorf("results[%d] has no locations; code scanning will not display it", i)
			continue
		}
		phys, ok := locs[0].(map[string]any)["physicalLocation"].(map[string]any)
		if !ok {
			t.Errorf("results[%d] has no physicalLocation", i)
			continue
		}
		uri, _ := phys["artifactLocation"].(map[string]any)["uri"].(string)
		if uri == "" {
			t.Errorf("results[%d] artifactLocation.uri is empty", i)
		}
		region, ok := phys["region"].(map[string]any)
		if !ok {
			t.Errorf("results[%d] has no region", i)
			continue
		}
		// Both are required, and both are 1-based, so 0 is not a legal value.
		if line, _ := region["startLine"].(float64); line < 1 {
			t.Errorf("results[%d] startLine = %v, want >= 1", i, line)
		}
		if col, _ := region["startColumn"].(float64); col < 1 {
			t.Errorf("results[%d] startColumn = %v, want >= 1", i, col)
		}
	}
}

// A uri must be relative to the repository root and slash-separated. This tool
// is developed on Windows, where the wrapped scanners report backslashes, so
// the normalization is not theoretical.
func TestPathsAreNormalizedForSARIF(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"windows separators", `internal\checks\authz.go`, "internal/checks/authz.go"},
		{"leading dot slash", "./src/app.js", "src/app.js"},
		{"leading slash", "/src/app.js", "src/app.js"},
		{"already clean", "src/app.js", "src/app.js"},
		{"redundant segments", "src/../src/app.js", "src/app.js"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := codeFinding("x.y", finding.SeverityLow)
			f.Location.File = tc.in
			log := Convert(doc(f), Options{})

			got := log.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI
			if got != tc.want {
				t.Errorf("uri = %q, want %q", got, tc.want)
			}
			if strings.HasPrefix(got, "/") {
				t.Errorf("uri %q is absolute; GitHub resolves relative to the repo root", got)
			}
			if strings.Contains(got, `\`) {
				t.Errorf("uri %q still contains a backslash", got)
			}
		})
	}
}

// The finding_id is a better fingerprint than a line hash because it excludes
// line numbers by design: an edit above a vulnerable line must not close the
// alert and open a duplicate. GitHub reads only primaryLocationLineHash, so
// that is the key it has to go in, whatever the name suggests.
func TestFingerprintIsTheStableFindingID(t *testing.T) {
	f := codeFinding("idor.a", finding.SeverityHigh)
	log := Convert(doc(f), Options{})

	fp := log.Runs[0].Results[0].PartialFingerprints
	if fp["primaryLocationLineHash"] != f.FindingID {
		t.Errorf("primaryLocationLineHash = %q, want the finding id %q", fp["primaryLocationLineHash"], f.FindingID)
	}

	// Moving the finding down the file must not change the fingerprint, or
	// every unrelated edit churns alerts.
	moved := f
	moved.Location.Line = 500
	moved.Location.EndLine = 502
	moved.AssignID()
	movedLog := Convert(doc(moved), Options{})

	if got := movedLog.Runs[0].Results[0].PartialFingerprints["primaryLocationLineHash"]; got != fp["primaryLocationLineHash"] {
		t.Errorf("fingerprint changed when only the line moved: %q then %q", fp["primaryLocationLineHash"], got)
	}
}

// An endpoint finding is about a route, not a file, but GitHub needs a
// physical location. Resolving the route to its handler is what puts the alert
// on a line a reviewer can act on.
func TestAnEndpointFindingResolvesToItsHandler(t *testing.T) {
	s := &surface.Surface{Routes: []surface.Route{
		{Method: "GET", Path: "/orders/{id}", Handler: "getOrder", File: "src/routes/orders.js", Line: 88},
	}}

	log := Convert(doc(endpointFinding("GET /orders/{id}")), Options{Surface: s})
	loc := log.Runs[0].Results[0].Locations[0]

	if got := loc.PhysicalLocation.ArtifactLocation.URI; got != "src/routes/orders.js" {
		t.Errorf("uri = %q, want the handler file", got)
	}
	if got := loc.PhysicalLocation.Region.StartLine; got != 88 {
		t.Errorf("startLine = %d, want the handler line 88", got)
	}
	if len(loc.LogicalLocations) != 1 || loc.LogicalLocations[0].Kind != "route" {
		t.Errorf("logical locations = %+v, want the route recorded", loc.LogicalLocations)
	}
}

// Without a surface, or for a route that was never extracted, the result must
// still be emitted and still carry the endpoint: dropping it would lose a real
// finding, and omitting the physical location risks the whole upload.
func TestAnUnresolvedEndpointStillConvertsWithTheRouteNamed(t *testing.T) {
	log := Convert(doc(endpointFinding("GET /unmapped")), Options{FallbackPath: "vibekiller.config.yaml"})

	res := log.Runs[0].Results[0]
	loc := res.Locations[0]

	if loc.PhysicalLocation == nil || loc.PhysicalLocation.ArtifactLocation.URI == "" {
		t.Fatal("no physical location was emitted")
	}
	if loc.PhysicalLocation.ArtifactLocation.URI != "vibekiller.config.yaml" {
		t.Errorf("uri = %q, want the fallback", loc.PhysicalLocation.ArtifactLocation.URI)
	}
	if len(loc.LogicalLocations) == 0 || loc.LogicalLocations[0].Name != "GET /unmapped" {
		t.Error("the endpoint is not recorded anywhere a reader would find it")
	}
	if res.Properties["endpoint"] != "GET /unmapped" {
		t.Errorf("properties.endpoint = %v, want the route", res.Properties["endpoint"])
	}
	if !strings.Contains(loc.Message.Text, "no handler was resolved") {
		t.Errorf("location message = %q, want it to admit the location is imprecise", loc.Message.Text)
	}
}

// Coverage is the reason the skipped and failed arrays were added to the
// contract, and SARIF has a place for exactly this. The level is what tells
// the two apart without a discriminator field.
func TestCoverageBecomesToolExecutionNotifications(t *testing.T) {
	d := doc(codeFinding("idor.a", finding.SeverityHigh))
	d.Skipped = []finding.SkippedCheck{{
		CheckID: "authz.unprotected-endpoint", Layer: "endpoint",
		Reason: "no running instance was given (pass --target)",
	}}
	d.Failed = []finding.FailedCheck{{
		CheckID: "engine.semgrep", Layer: "static", Error: "semgrep exited with status 7",
	}}

	log := Convert(d, Options{})
	invs := log.Runs[0].Invocations
	if len(invs) != 1 {
		t.Fatalf("invocations = %d, want 1", len(invs))
	}
	inv := invs[0]

	if inv.ExecutionSuccessful {
		t.Error("executionSuccessful = true, want false when a check failed")
	}
	if len(inv.ToolExecutionNotifications) != 2 {
		t.Fatalf("notifications = %d, want one per skip and failure", len(inv.ToolExecutionNotifications))
	}

	byRule := map[string]Notification{}
	for _, n := range inv.ToolExecutionNotifications {
		byRule[n.AssociatedRule.ID] = n
	}

	skip := byRule["authz.unprotected-endpoint"]
	if skip.Level != LevelNote {
		t.Errorf("a skip has level %q, want %q", skip.Level, LevelNote)
	}
	if !strings.Contains(skip.Message.Text, "--target") {
		t.Errorf("skip message = %q, want the reason carried through", skip.Message.Text)
	}

	fail := byRule["engine.semgrep"]
	if fail.Level != LevelError {
		t.Errorf("a failure has level %q, want %q", fail.Level, LevelError)
	}
	if !strings.Contains(fail.Message.Text, "status 7") {
		t.Errorf("failure message = %q, want the error carried through", fail.Message.Text)
	}
}

// A run where everything ran should not carry an empty invocation, so a clean
// SARIF file stays clean.
func TestNoInvocationWhenNothingWasMissed(t *testing.T) {
	if invs := Convert(doc(codeFinding("idor.a", finding.SeverityLow)), Options{}).Runs[0].Invocations; len(invs) != 0 {
		t.Errorf("invocations = %d, want none", len(invs))
	}
}

// GitHub parses automationDetails.id as "category/run-id" and uses the
// category to tell uploads apart. Without it, a second upload for the same
// commit overwrites the first.
func TestAutomationDetailsCarriesCategoryAndRunID(t *testing.T) {
	log := Convert(doc(codeFinding("idor.a", finding.SeverityLow)), Options{})
	if log.Runs[0].AutomationDetails == nil {
		t.Fatal("automationDetails is absent")
	}
	if got, want := log.Runs[0].AutomationDetails.ID, "vibekiller/20260101-000000-abc"; got != want {
		t.Errorf("automationDetails.id = %q, want %q", got, want)
	}

	custom := Convert(doc(codeFinding("idor.a", finding.SeverityLow)), Options{Category: "vibekiller-nightly"})
	if got := custom.Runs[0].AutomationDetails.ID; !strings.HasPrefix(got, "vibekiller-nightly/") {
		t.Errorf("automationDetails.id = %q, want the configured category", got)
	}
}

// security-severity only means anything inside GitHub's bands, and only on a
// rule tagged "security". Zero or out of range silently means "no severity".
func TestSeverityMapsIntoGitHubBands(t *testing.T) {
	cases := []struct {
		sev       finding.Severity
		wantLevel string
		wantScore string
	}{
		{finding.SeverityCritical, LevelError, "9.5"},
		{finding.SeverityHigh, LevelError, "8.0"},
		{finding.SeverityMedium, LevelWarning, "5.5"},
		{finding.SeverityLow, LevelNote, "3.0"},
		{finding.SeverityInfo, LevelNote, "1.0"},
	}
	for _, tc := range cases {
		t.Run(string(tc.sev), func(t *testing.T) {
			log := Convert(doc(codeFinding("idor.a", tc.sev)), Options{})
			if got := log.Runs[0].Results[0].Level; got != tc.wantLevel {
				t.Errorf("result level = %q, want %q", got, tc.wantLevel)
			}
			rule := log.Runs[0].Tool.Driver.Rules[0]
			if got := rule.Properties.SecuritySeverity; got != tc.wantScore {
				t.Errorf("security-severity = %q, want %q", got, tc.wantScore)
			}
			var tagged bool
			for _, tag := range rule.Properties.Tags {
				if tag == "security" {
					tagged = true
				}
			}
			if !tagged {
				t.Error(`the rule is not tagged "security", so GitHub ignores security-severity`)
			}
		})
	}
}

// One descriptor per rule, and it must describe the rule at its worst. A rule
// that fired once as critical defaulting to the level of whichever finding
// came first would understate it.
func TestARuleKeepsItsStrongestSeverity(t *testing.T) {
	log := Convert(doc(
		codeFinding("idor.a", finding.SeverityLow),
		codeFinding("idor.a", finding.SeverityCritical),
	), Options{})

	rules := log.Runs[0].Tool.Driver.Rules
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want one per distinct rule id", len(rules))
	}
	if got := rules[0].DefaultConfig.Level; got != LevelError {
		t.Errorf("defaultConfiguration.level = %q, want %q", got, LevelError)
	}
	if got := rules[0].Properties.SecuritySeverity; got != "9.5" {
		t.Errorf("security-severity = %q, want the critical band", got)
	}

	// ruleIndex must still address the single descriptor for both results.
	for i, res := range log.Runs[0].Results {
		if res.RuleIndex != 0 {
			t.Errorf("results[%d].ruleIndex = %d, want 0", i, res.RuleIndex)
		}
	}
}

// Rule text has documented maximums; exceeding them is another rejection.
func TestRuleTextIsClampedToGitHubLimits(t *testing.T) {
	f := codeFinding("idor.a", finding.SeverityHigh)
	f.Remediation.Guidance = strings.Repeat("x", maxTextLen*2)
	f.Remediation.RootCauseHint = strings.Repeat("y", maxTextLen*2)

	rule := Convert(doc(f), Options{}).Runs[0].Tool.Driver.Rules[0]

	if n := len(rule.FullDescription.Text); n > maxTextLen {
		t.Errorf("fullDescription.text is %d chars, over the %d limit", n, maxTextLen)
	}
	if n := len(rule.Help.Text); n > maxTextLen {
		t.Errorf("help.text is %d chars, over the %d limit", n, maxTextLen)
	}
	if n := len(rule.Name); n > maxNameLen {
		t.Errorf("name is %d chars, over the %d limit", n, maxNameLen)
	}
	// The markdown form is not clamped, which is deliberate: it has no
	// documented limit and is where the references live.
	if rule.Help.Markdown == "" {
		t.Error("help.markdown is empty")
	}
}

// A dependency finding points at the manifest and names the package, since
// there is no line in a lockfile worth annotating.
func TestADependencyFindingNamesThePackage(t *testing.T) {
	f := codeFinding("deps.known-vulnerability", finding.SeverityCritical)
	f.Source = finding.SourceDeps
	f.Location = finding.Location{
		Type: finding.LocationDependency, File: "requirements.txt",
		Package: "django", Ecosystem: "PyPI", Version: "5.0.1",
	}
	f.AssignID()

	loc := Convert(doc(f), Options{}).Runs[0].Results[0].Locations[0]

	if got := loc.PhysicalLocation.ArtifactLocation.URI; got != "requirements.txt" {
		t.Errorf("uri = %q, want the manifest", got)
	}
	if got := loc.PhysicalLocation.Region.StartLine; got != 1 {
		t.Errorf("startLine = %d, want 1 when the manifest has no line", got)
	}
	if len(loc.LogicalLocations) != 1 {
		t.Fatalf("logical locations = %+v", loc.LogicalLocations)
	}
	if got := loc.LogicalLocations[0].FullyQualifiedName; got != "PyPI:django@5.0.1" {
		t.Errorf("fullyQualifiedName = %q, want the ecosystem-qualified package", got)
	}
}

// A clean scan is the result everyone hopes for, and the one most likely to be
// uploaded without anyone reading it. It must still be a valid document.
//
// It was not: an empty rule list was a nil slice, which marshals to null,
// while GitHub requires rules to be an array. Asserting over the JSON rather
// than the structs is the point -- the Go value was an acceptable nil, and
// only the serialized form was wrong.
func TestAnEmptyRunIsStillValidSARIF(t *testing.T) {
	raw, err := json.Marshal(Convert(doc(), Options{ToolVersion: "0.2.0"}))
	if err != nil {
		t.Fatal(err)
	}

	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	run := m["runs"].([]any)[0].(map[string]any)
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)

	rules, ok := driver["rules"].([]any)
	if !ok {
		t.Fatalf("tool.driver.rules serialized as %T (%v), want an array", driver["rules"], driver["rules"])
	}
	if len(rules) != 0 {
		t.Errorf("rules = %d, want none", len(rules))
	}

	results, ok := run["results"].([]any)
	if !ok {
		t.Fatalf("results serialized as %T, want an array", run["results"])
	}
	if len(results) != 0 {
		t.Errorf("results = %d, want none", len(results))
	}

	// Nothing was skipped either, so there is no invocation to report.
	if _, present := run["invocations"]; present {
		t.Errorf("invocations is present on a run with no coverage gaps: %v", run["invocations"])
	}

	if !strings.Contains(string(raw), `"rules":[]`) {
		t.Errorf("rules did not serialize as an empty array:\n%s", raw)
	}
}
