package scanners

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
)

func testContext() ScanContext {
	return ScanContext{RepoRoot: "/repo", RepoRev: "abc123"}
}

// --- Semgrep ---------------------------------------------------------------

const semgrepSample = `{
  "results": [
    {
      "check_id": "rules.vibekiller.idor-missing-ownership-check",
      "path": "src/routes/orders.js",
      "start": {"line": 42, "col": 3},
      "end": {"line": 46, "col": 4},
      "extra": {
        "message": "Route handler looks up a record by a client-supplied id without checking ownership. Any authenticated user can read any record.",
        "severity": "ERROR",
        "lines": "  const order = await db.orders.findById(req.params.id)",
        "metadata": {
          "cwe": ["CWE-639: Authorization Bypass Through User-Controlled Key"],
          "owasp": ["A01:2021 - Broken Access Control"],
          "category": "security",
          "confidence": "HIGH",
          "references": ["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
          "vibekiller": {
            "rule_id": "idor.missing-ownership-check",
            "category": "broken-access-control",
            "severity": "high",
            "confidence": "likely",
            "fixable_by_giver": true,
            "root_cause_hint": "Authorization enforced in the UI but not at the data layer.",
            "guidance": "Scope the query to the authenticated user.",
            "dynamic_rule": "idor.sequential-id-access"
          }
        },
        "dataflow_trace": {
          "taint_source": ["CliLoc", [{"path": "src/routes/orders.js", "start": {"line": 41, "col": 20}}, "req.params.id"]],
          "intermediate_vars": [{"location": {"path": "src/routes/orders.js", "start": {"line": 42, "col": 9}}}],
          "taint_sink": ["CliLoc", [{"path": "src/db.js", "start": {"line": 88, "col": 5}}, "findById"]]
        }
      }
    },
    {
      "check_id": "python.lang.best-practice.unused-import",
      "path": "app.py",
      "start": {"line": 1, "col": 1},
      "end": {"line": 1, "col": 20},
      "extra": {
        "message": "Unused import",
        "severity": "INFO",
        "metadata": {"category": "best-practice"}
      }
    },
    {
      "check_id": "javascript.express.security.audit.express-cookie-session-no-httponly",
      "path": "src/app.js",
      "start": {"line": 10, "col": 1},
      "end": {"line": 10, "col": 40},
      "extra": {
        "message": "Cookie is missing the httpOnly flag.",
        "severity": "WARNING",
        "metadata": {
          "category": "security",
          "cwe": ["CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag"],
          "owasp": ["A05:2021 - Security Misconfiguration"]
        }
      }
    }
  ],
  "errors": [],
  "paths": {"scanned": ["src/routes/orders.js", "app.py", "src/app.js"]}
}`

func TestSemgrepParse(t *testing.T) {
	s := NewSemgrep(nil, nil)
	fs, err := s.parse([]byte(semgrepSample), testContext())
	if err != nil {
		t.Fatal(err)
	}

	// The best-practice lint must be dropped: a style warning is not a
	// vulnerability and would only inflate the count.
	if len(fs) != 2 {
		var ids []string
		for _, f := range fs {
			ids = append(ids, f.RuleID)
		}
		t.Fatalf("got %d findings (%v), want 2 security findings", len(fs), ids)
	}

	idor := fs[0]
	if idor.RuleID != "idor.missing-ownership-check" {
		t.Errorf("rule_id = %q; the first-party metadata block should override the check id", idor.RuleID)
	}
	if idor.Category != finding.CategoryBrokenAccessControl {
		t.Errorf("category = %q", idor.Category)
	}
	if idor.CWE != "CWE-639" {
		t.Errorf("cwe = %q, want the bare identifier CWE-639", idor.CWE)
	}
	if idor.Severity != finding.SeverityHigh {
		t.Errorf("severity = %q", idor.Severity)
	}
	if idor.Source != finding.SourceSAST {
		t.Errorf("source = %q", idor.Source)
	}
	if idor.Remediation.Guidance != "Scope the query to the authenticated user." {
		t.Errorf("guidance = %q", idor.Remediation.Guidance)
	}
	if idor.Location.File != "src/routes/orders.js" || idor.Location.Line != 42 {
		t.Errorf("location = %+v", idor.Location)
	}
	if idor.Location.RepoRev != "abc123" {
		t.Errorf("repo_rev was not stamped: %q", idor.Location.RepoRev)
	}

	// The taint path is the whole point of a data-flow rule: report the route,
	// not just the sink.
	if len(idor.Evidence.TaintPath) != 3 {
		t.Fatalf("taint path has %d steps, want source, intermediate and sink: %+v",
			len(idor.Evidence.TaintPath), idor.Evidence.TaintPath)
	}
	if idor.Evidence.TaintPath[0].Line != 41 {
		t.Errorf("taint source = %+v", idor.Evidence.TaintPath[0])
	}
	if idor.Evidence.TaintPath[2].File != "src/db.js" || idor.Evidence.TaintPath[2].Line != 88 {
		t.Errorf("taint sink = %+v", idor.Evidence.TaintPath[2])
	}

	// A third-party rule with no first-party metadata must still map onto the
	// contract.
	cookie := fs[1]
	if cookie.Category != finding.CategoryMisconfiguration {
		t.Errorf("third-party rule category = %q, want security-misconfiguration from its OWASP tag", cookie.Category)
	}
	if cookie.Severity != finding.SeverityMedium {
		t.Errorf("WARNING should map to medium, got %q", cookie.Severity)
	}

	if err := finding.ValidateAll(fs); err != nil {
		t.Errorf("parsed findings violate the contract: %v", err)
	}
}

// Static analysis cannot know whether a pattern is reachable at runtime, so no
// static finding may claim to have been reproduced.
func TestSemgrepNeverClaimsConfirmed(t *testing.T) {
	sample := strings.Replace(semgrepSample, `"confidence": "likely"`, `"confidence": "confirmed"`, 1)

	s := NewSemgrep(nil, nil)
	fs, err := s.parse([]byte(sample), testContext())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if f.Confidence == finding.ConfidenceConfirmed {
			t.Errorf("%s claims confirmed confidence from a static scan", f.RuleID)
		}
	}
}

func TestSemgrepHandlesEmptyAndBrokenOutput(t *testing.T) {
	s := NewSemgrep(nil, nil)

	for _, in := range []string{"", "   ", `{"results":[]}`} {
		fs, err := s.parse([]byte(in), testContext())
		if err != nil {
			t.Errorf("parse(%q) returned an error: %v", in, err)
		}
		if len(fs) != 0 {
			t.Errorf("parse(%q) produced findings", in)
		}
	}

	if _, err := s.parse([]byte(`{not json`), testContext()); err == nil {
		t.Error("malformed JSON was accepted")
	}
}

func TestNormalizeRuleID(t *testing.T) {
	tests := []struct{ in, want string }{
		{"rules.vibekiller.idor-check", "rules.vibekiller.idor-check"},
		{"javascript/express/security/audit/foo", "javascript.express.security.audit.foo"},
		{"Some Rule_Name", "some-rule-name"},
		{"...weird...", "weird"},
		{"", "semgrep.unknown"},
		{"!!!", "semgrep.unknown"},
	}
	for _, tc := range tests {
		got := normalizeRuleID(tc.in)
		if got != tc.want {
			t.Errorf("normalizeRuleID(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if got != "" && !ruleIDOK(got) {
			t.Errorf("normalizeRuleID(%q) = %q, which does not match the contract pattern", tc.in, got)
		}
	}
}

func ruleIDOK(s string) bool {
	f := finding.Finding{
		RuleID: s, Title: "t", Category: finding.CategoryInjection,
		Severity: finding.SeverityLow, Confidence: finding.ConfidenceHeuristic,
		Source: finding.SourceSAST, Status: finding.StatusOpen,
		Location:    finding.Location{Type: finding.LocationCode, File: "a"},
		Evidence:    finding.Evidence{Summary: "s"},
		Remediation: finding.Remediation{Guidance: "g", FixableByGiver: true},
	}
	f.AssignID()
	err := f.Validate()
	return err == nil || !strings.Contains(err.Error(), "rule_id")
}

// --- osv-scanner -----------------------------------------------------------

const osvSample = `{
  "results": [
    {
      "source": {"path": "/repo/package-lock.json", "type": "lockfile"},
      "packages": [
        {
          "package": {"name": "lodash", "version": "4.17.11", "ecosystem": "npm"},
          "vulnerabilities": [
            {
              "id": "GHSA-jf85-cpcp-j695",
              "aliases": ["CVE-2019-10744"],
              "summary": "Prototype Pollution in lodash",
              "severity": [{"type": "CVSS_V3", "score": "9.1"}],
              "database_specific": {"severity": "CRITICAL"},
              "affected": [{"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.12"}]}]}],
              "references": [{"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-jf85-cpcp-j695"}]
            },
            {
              "id": "CVE-2019-10744",
              "summary": "Prototype pollution, duplicate advisory",
              "database_specific": {"severity": "CRITICAL"}
            }
          ],
          "groups": [{"ids": ["GHSA-jf85-cpcp-j695", "CVE-2019-10744"], "max_severity": "9.1"}]
        },
        {
          "package": {"name": "minimist", "version": "1.2.0", "ecosystem": "npm"},
          "vulnerabilities": [
            {
              "id": "GHSA-vh95-rmgr-6w4m",
              "summary": "Prototype pollution in minimist",
              "database_specific": {"severity": "MODERATE"},
              "affected": [{"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}]}]
            }
          ],
          "groups": [{"ids": ["GHSA-vh95-rmgr-6w4m"]}]
        }
      ]
    }
  ]
}`

func TestOSVParse(t *testing.T) {
	o := NewOSV(nil)
	fs, err := o.parse([]byte(osvSample), testContext())
	if err != nil {
		t.Fatal(err)
	}

	// Two advisories on lodash are aliases of one another and describe one
	// upgrade, so they must collapse into a single finding.
	if len(fs) != 2 {
		var ids []string
		for _, f := range fs {
			ids = append(ids, f.Location.Package+":"+f.Evidence.EvidenceKey)
		}
		t.Fatalf("got %d findings (%v), want one per package", len(fs), ids)
	}

	lodash := fs[0]
	if lodash.Location.Package != "lodash" {
		t.Fatalf("findings are not in deterministic package order: %+v", fs)
	}
	if lodash.Severity != finding.SeverityCritical {
		t.Errorf("severity = %q, want critical", lodash.Severity)
	}
	if lodash.Location.Type != finding.LocationDependency {
		t.Errorf("location.type = %q", lodash.Location.Type)
	}
	if lodash.Location.Version != "4.17.11" || lodash.Location.Ecosystem != "npm" {
		t.Errorf("location = %+v", lodash.Location)
	}
	if lodash.Location.File != "package-lock.json" {
		t.Errorf("manifest path was not made repo-relative: %q", lodash.Location.File)
	}
	if !strings.Contains(lodash.Evidence.Expected, "4.17.12") {
		t.Errorf("expected should name the fixed version, got %q", lodash.Evidence.Expected)
	}
	if !strings.Contains(lodash.Remediation.Guidance, "4.17.12") {
		t.Errorf("guidance should name the fixed version, got %q", lodash.Remediation.Guidance)
	}
	if lodash.Confidence == finding.ConfidenceConfirmed {
		t.Error("a dependency advisory cannot be confirmed: reachability was never tested")
	}

	if fs[1].Severity != finding.SeverityMedium {
		t.Errorf("MODERATE should map to medium, got %q", fs[1].Severity)
	}

	if err := finding.ValidateAll(fs); err != nil {
		t.Errorf("parsed findings violate the contract: %v", err)
	}
}

func TestOSVSeverityFallsBackToCVSS(t *testing.T) {
	tests := []struct {
		score string
		want  finding.Severity
	}{
		{"9.8", finding.SeverityCritical},
		{"7.5", finding.SeverityHigh},
		{"5.0", finding.SeverityMedium},
		{"2.1", finding.SeverityLow},
		{"CVSS:3.1/AV:N/AC:L", finding.SeverityMedium}, // vector with no numeric score
	}
	for _, tc := range tests {
		v := osvVuln{Severity: []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		}{{Type: "CVSS_V3", Score: tc.score}}}
		if got := osvSeverity(v); got != tc.want {
			t.Errorf("osvSeverity(%q) = %q, want %q", tc.score, got, tc.want)
		}
	}
}

func TestMajorVersion(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"osv-scanner version 2.0.2", 2},
		{"1.9.1", 1},
		{"v8.21.0", 8},
		{"no numbers here", 0},
	}
	for _, tc := range tests {
		if got := majorVersion(tc.in); got != tc.want {
			t.Errorf("majorVersion(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// --- gitleaks --------------------------------------------------------------

const gitleaksSample = `[
  {
    "RuleID": "stripe-access-token",
    "Description": "Stripe Access Token",
    "File": "src/config.js",
    "StartLine": 7,
    "EndLine": 7,
    "Commit": "",
    "Entropy": 3.8,
    "Match": "stripeKey = \"REDACTED\"",
    "Fingerprint": "src/config.js:stripe-access-token:7",
    "Tags": []
  },
  {
    "RuleID": "stripe-access-token",
    "Description": "Stripe Access Token",
    "File": "src/config.js",
    "StartLine": 7,
    "EndLine": 7,
    "Commit": "9f1b2c3d4e5f60718293a4b5c6d7e8f901234567",
    "Author": "dev",
    "Date": "2026-01-02T03:04:05Z",
    "Entropy": 3.8,
    "Match": "stripeKey = \"REDACTED\"",
    "Fingerprint": "9f1b2c3d:src/config.js:stripe-access-token:7",
    "Tags": []
  },
  {
    "RuleID": "generic-api-key",
    "Description": "Generic API Key",
    "File": ".env.example",
    "StartLine": 3,
    "EndLine": 3,
    "Commit": "",
    "Entropy": 4.2,
    "Match": "API_KEY=REDACTED",
    "Fingerprint": ".env.example:generic-api-key:3",
    "Tags": []
  }
]`

func TestGitleaksParse(t *testing.T) {
	hits, err := parseGitleaks([]byte(gitleaksSample))
	if err != nil {
		t.Fatal(err)
	}

	g := NewGitleaks(nil)
	fs := g.toFindings(hits, testContext(), true)

	// The Stripe key appears in both the working tree and history; that is one
	// credential, so one finding.
	if len(fs) != 2 {
		t.Fatalf("got %d findings, want one per credential: %+v", len(fs), fs)
	}

	var stripe, generic *finding.Finding
	for i := range fs {
		switch fs[i].Location.File {
		case "src/config.js":
			stripe = &fs[i]
		case ".env.example":
			generic = &fs[i]
		}
	}
	if stripe == nil || generic == nil {
		t.Fatalf("expected both credentials, got %+v", fs)
	}

	// A credential in git history has been distributed to every clone, which
	// is strictly worse than one only in the working tree.
	if stripe.Severity != finding.SeverityCritical {
		t.Errorf("a credential in history should be critical, got %q", stripe.Severity)
	}
	if generic.Severity != finding.SeverityHigh {
		t.Errorf("a worktree-only credential should be high, got %q", generic.Severity)
	}
	if !strings.Contains(stripe.Evidence.Summary, "git history") {
		t.Errorf("the summary should say where it was found: %q", stripe.Evidence.Summary)
	}
	if !strings.Contains(stripe.Remediation.Guidance, "rotate") {
		t.Errorf("guidance should lead with rotation: %q", stripe.Remediation.Guidance)
	}

	// Contract rule: no secrets finding is ever auto-fixable.
	for _, f := range fs {
		if f.Remediation.FixableByGiver {
			t.Errorf("%s is marked auto-fixable; only a human can rotate a credential", f.FindingID)
		}
		if f.Remediation.HumanRequiredReason == "" {
			t.Errorf("%s gives no reason a human is required", f.FindingID)
		}
		if f.Source != finding.SourceSecrets {
			t.Errorf("%s has source %q", f.FindingID, f.Source)
		}
	}

	if err := finding.ValidateAll(fs); err != nil {
		t.Errorf("parsed findings violate the contract: %v", err)
	}
}

// findings.json gets attached to tickets and read by other tools. A credential
// value must never travel in it, no matter what the scanner reported.
func TestGitleaksFindingsCarryNoCredentialValue(t *testing.T) {
	// A report where gitleaks did NOT redact, i.e. the worst case.
	raw := `[{
    "RuleID": "aws-access-token",
    "Description": "AWS Access Key",
    "File": "deploy/setup.sh",
    "StartLine": 12,
    "EndLine": 12,
    "Commit": "",
    "Secret": "SUPER-SECRET-VALUE-DO-NOT-LEAK",
    "Match": "AWS_KEY=SUPER-SECRET-VALUE-DO-NOT-LEAK",
    "Entropy": 4.9,
    "Fingerprint": "deploy/setup.sh:aws-access-token:12"
  }]`

	hits, err := parseGitleaks([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}

	g := NewGitleaks(nil)
	fs := g.toFindings(hits, testContext(), false)
	if len(fs) != 1 {
		t.Fatalf("got %d findings", len(fs))
	}

	encoded, err := json.Marshal(fs[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "SUPER-SECRET-VALUE-DO-NOT-LEAK") {
		t.Fatalf("the credential value reached the finding:\n%s", encoded)
	}

	// The masked form should still let a human recognize which secret it is.
	if !strings.Contains(fs[0].Evidence.Observed, "*") {
		t.Errorf("observed evidence should carry a masked match, got %q", fs[0].Evidence.Observed)
	}
}

func TestMaskSecret(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", ""},
		{"abc", "***"},
		{"12345678", "********"},
		{"abcdefghijkl", "ab********kl"},
	}
	for _, tc := range tests {
		if got := maskSecret(tc.in); got != tc.want {
			t.Errorf("maskSecret(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestFingerprintIsStableAndNotReversible(t *testing.T) {
	a := fingerprint("rule", "file.js", "")
	b := fingerprint("rule", "file.js", "")
	if a != b {
		t.Error("fingerprint is not stable across calls")
	}
	if c := fingerprint("rule", "other.js", ""); a == c {
		t.Error("different inputs produced the same fingerprint")
	}
	if strings.Contains(a, "file.js") {
		t.Error("the fingerprint contains its input")
	}
	// Component boundaries must be separated, or "ab"+"c" and "a"+"bc" collide.
	if fingerprint("ab", "c") == fingerprint("a", "bc") {
		t.Error("fingerprint components are not delimited")
	}
}

func TestFirstCWE(t *testing.T) {
	tests := []struct {
		in   []string
		want string
	}{
		{[]string{"CWE-639: Authorization Bypass"}, "CWE-639"},
		{[]string{"no cwe here", "CWE-89: SQL Injection"}, "CWE-89"},
		{[]string{"CWE-"}, ""},
		{nil, ""},
	}
	for _, tc := range tests {
		if got := firstCWE(tc.in); got != tc.want {
			t.Errorf("firstCWE(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestRelPath(t *testing.T) {
	sc := testContext()
	tests := []struct {
		name, in, want string
	}{
		{"absolute inside the repo", "/repo/src/app.js", "src/app.js"},
		{"already relative", "src/app.js", "src/app.js"},
		{"empty", "", ""},
		// A scanner reports relative paths against the repo root, so these
		// have to resolve against it and come back cleaned. Resolving them
		// against the process working directory instead leaves the dot-dot in
		// place, and the finding then fails to de-duplicate against the same
		// issue reported by its real path.
		{"relative with a dot-dot detour", "node_modules/../server.js", "server.js"},
		{"relative with a dot segment", "./src/./app.js", "src/app.js"},
		{"absolute with a dot-dot detour", "/repo/node_modules/../server.js", "server.js"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := relPath(sc.RepoRoot, tc.in); got != tc.want {
				t.Errorf("relPath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// Two reports of one issue, one reached through a dot-dot detour, must
// produce one finding rather than two.
func TestPathsNormalizeSoDuplicatesCollapse(t *testing.T) {
	sc := testContext()

	direct := relPath(sc.RepoRoot, "server.js")
	detour := relPath(sc.RepoRoot, "node_modules/../server.js")

	if direct != detour {
		t.Errorf("the same file normalized two ways: %q and %q", direct, detour)
	}
}

func TestStringListToleratesBothShapes(t *testing.T) {
	var single struct {
		V stringList `json:"v"`
	}
	if err := json.Unmarshal([]byte(`{"v":"one"}`), &single); err != nil {
		t.Fatal(err)
	}
	if len(single.V) != 1 || single.V[0] != "one" {
		t.Errorf("string form parsed as %v", single.V)
	}

	var many struct {
		V stringList `json:"v"`
	}
	if err := json.Unmarshal([]byte(`{"v":["a","b"]}`), &many); err != nil {
		t.Fatal(err)
	}
	if len(many.V) != 2 {
		t.Errorf("array form parsed as %v", many.V)
	}

	// An unexpected shape must not fail the whole scan.
	var odd struct {
		V stringList `json:"v"`
	}
	if err := json.Unmarshal([]byte(`{"v":{"unexpected":true}}`), &odd); err != nil {
		t.Errorf("an unexpected shape should degrade to empty, not error: %v", err)
	}
}
