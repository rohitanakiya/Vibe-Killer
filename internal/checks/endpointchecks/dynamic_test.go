package endpointchecks

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
	"github.com/rohitanakiya/Vibe-Killer/internal/surface"
)

// --- probe guard -----------------------------------------------------------

// The guard is the mechanical backstop on what a probe may contain. Its job is
// to refuse anything that could have an effect, including values that a future
// edit assembles by accident.
func TestProbeGuardRefusesAnythingWithAnEffect(t *testing.T) {
	refused := []struct{ value, why string }{
		{"vk'; DROP TABLE orders--", "a statement keyword"},
		{"1 OR 1=1; DELETE FROM users", "a statement keyword"},
		{"x TRUNCATE y", "a statement keyword"},
		{"a UPDATE b", "a statement keyword"},
		{"vk' AND SLEEP(5)--", "a timing function"},
		{"$(whoami)", "a shell substitution"},
		{"vk`id`", "a backtick"},
		{"vk; ls", "a command separator"},
		{"vk && ls", "a command separator"},
		{"vk | cat", "a pipe"},
		{"vk -- comment", "a SQL comment"},
		{"vk /* comment */", "a SQL comment"},
		{strings.Repeat("a", 200), "excessive length"},
	}
	for _, tc := range refused {
		if err := assertInertProbe("test.rule", tc.value); err == nil {
			t.Errorf("the guard allowed a probe containing %s: %q", tc.why, tc.value)
		}
	}

	// The probes the checks actually send must pass, or the guard is useless.
	allowed := []string{
		benignValue,
		quoteProbe,
		"vk-probe-ab12cd34ef567890",
		traversalPrefix + "vk-probe-ab12cd34",
		"../../../vk-probe-deadbeef",
		"90001",
	}
	for _, v := range allowed {
		if err := assertInertProbe("test.rule", v); err != nil {
			t.Errorf("the guard refused a probe the checks rely on: %q (%v)", v, err)
		}
	}
}

func TestProbeGuardErrorNamesTheRuleAndValue(t *testing.T) {
	err := assertInertProbe("injection.sql-differential", "x; DROP TABLE t")
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if !strings.Contains(err.Error(), "injection.sql-differential") {
		t.Errorf("the error should name the rule: %v", err)
	}
	if !strings.Contains(err.Error(), "inert") {
		t.Errorf("the error should explain the requirement: %v", err)
	}
}

// --- SQL differential ------------------------------------------------------

// sqlServer answers with a driver parser error when the value it is given
// contains an unbalanced quote, which is what an application that concatenates
// does.
func sqlServer(t *testing.T, concatenates bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Path[strings.LastIndexByte(r.URL.Path, '/')+1:]

		if concatenates && strings.Contains(id, "'") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"ER_PARSE_ERROR: You have an error in your SQL syntax near '` + id + `'"}`))
			return
		}
		// Parameterized, or simply not found: a quote is just a character.
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not found"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestSQLDifferentialFiresWhenTheQuoteReachesTheParser(t *testing.T) {
	srv := sqlServer(t, true)
	env := testEnv(t, srv.URL, orderRoutes())

	fs, err := (&SQLDifferential{}).Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) == 0 {
		t.Fatal("the check did not fire when an unbalanced quote produced a parser error")
	}

	f := fs[0]
	if f.Confidence != finding.ConfidenceConfirmed {
		t.Errorf("confidence = %q, want confirmed", f.Confidence)
	}
	if f.Severity != finding.SeverityCritical {
		t.Errorf("severity = %q", f.Severity)
	}
	if !strings.Contains(f.Evidence.Summary, "MySQL") {
		t.Errorf("the summary should name the engine that complained: %q", f.Evidence.Summary)
	}
	// The finding must describe the missing boundary, not a demonstrated
	// destructive action.
	if !strings.Contains(f.Evidence.Summary, "boundary") {
		t.Errorf("the summary should explain what is actually wrong: %q", f.Evidence.Summary)
	}
	if err := f.Validate(); err != nil {
		t.Errorf("the finding breaks the contract: %v", err)
	}

	// The recorded probe must be the inert one.
	if !strings.Contains(f.Evidence.Request.Path, "vk-probe") {
		t.Errorf("the recorded probe is not the expected inert value: %q", f.Evidence.Request.Path)
	}
}

func TestSQLDifferentialStaysSilentWhenParameterized(t *testing.T) {
	srv := sqlServer(t, false)
	env := testEnv(t, srv.URL, orderRoutes())

	fs, err := (&SQLDifferential{}).Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("the check fired on an application that binds its parameters: %+v", fs)
	}
}

// A handler that already errors on an ordinary value is broken in some other
// way, and the quote probe would prove nothing about it.
func TestSQLDifferentialDrawsNoConclusionWhenTheBaselineAlreadyErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"ER_PARSE_ERROR: something is always wrong here"}`))
	}))
	t.Cleanup(srv.Close)

	env := testEnv(t, srv.URL, orderRoutes())

	fs, err := (&SQLDifferential{}).Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("a finding was raised although the baseline already errored: %+v", fs)
	}
}

func TestSQLDifferentialReproduceReflectsTheFix(t *testing.T) {
	vuln := sqlServer(t, true)
	env := testEnv(t, vuln.URL, orderRoutes())

	fs, err := (&SQLDifferential{}).Detect(context.Background(), env)
	if err != nil || len(fs) == 0 {
		t.Fatalf("setup: %d findings (%v)", len(fs), err)
	}

	res, err := (&SQLDifferential{}).Reproduce(context.Background(), env, fs[0])
	if err != nil {
		t.Fatal(err)
	}
	if !res.Reproduced {
		t.Errorf("should still reproduce against the unfixed server: %s", res.Detail)
	}

	fixed := sqlServer(t, false)
	fixedEnv := testEnv(t, fixed.URL, orderRoutes())

	res, err = (&SQLDifferential{}).Reproduce(context.Background(), fixedEnv, fs[0])
	if err != nil {
		t.Fatal(err)
	}
	if res.Reproduced {
		t.Errorf("reproduced against the fixed server: %s", res.Detail)
	}
}

func TestSQLErrorSignatureMatching(t *testing.T) {
	cases := map[string]string{
		`{"error":"ER_PARSE_ERROR near x"}`:                        "MySQL",
		`psycopg2.errors.SyntaxError: syntax error at or near "'"`: "PostgreSQL",
		`sqlite3.OperationalError: unrecognized token`:             "SQLite",
		`SQLSTATE[42000]: Syntax error`:                            "a PDO driver",
		`SequelizeDatabaseError: invalid input`:                    "Sequelize",
	}
	for body, wantEngine := range cases {
		engine, ok := matchSQLError(body)
		if !ok {
			t.Errorf("no SQL error detected in %q", body)
			continue
		}
		if engine != wantEngine {
			t.Errorf("engine for %q = %q, want %q", body, engine, wantEngine)
		}
	}

	// A generic error must not be read as a database error, or this check
	// would duplicate the verbose-error finding.
	for _, body := range []string{`{"error":"not found"}`, `{"error":"invalid id"}`, ""} {
		if _, ok := matchSQLError(body); ok {
			t.Errorf("a generic response was read as a database error: %q", body)
		}
	}
}

// --- SSRF canary -----------------------------------------------------------

// fetchingServer fetches whatever URL it is handed, which is the weakness.
func fetchingServer(t *testing.T, fetches bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		if target == "" {
			// Also accept a JSON body, as a POST import endpoint would.
			body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
			var payload map[string]string
			if json.Unmarshal(body, &payload) == nil {
				target = payload["url"]
			}
		}
		if target == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"url required"}`))
			return
		}

		if !fetches {
			// The fixed version checks the host before fetching.
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"host not allowed"}`))
			return
		}

		resp, err := http.Get(target)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"error":"fetch failed"}`))
			return
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_, _ = w.Write([]byte(`{"bytes":` + itoa(len(data)) + `}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func importRoutes() []surface.Route {
	return []surface.Route{{
		Method: "GET", Path: "/api/import", PathParams: nil,
		File: "src/routes/import.js", Line: 12, Handler: "importFeed",
	}}
}

func TestSSRFCanaryFiresWhenTheServerFetchesTheURL(t *testing.T) {
	srv := fetchingServer(t, true)
	env := testEnv(t, srv.URL, importRoutes())

	fs, err := (&SSRFCanary{}).Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) == 0 {
		t.Fatal("the check did not fire although the server fetched the canary URL")
	}

	f := fs[0]
	if f.Confidence != finding.ConfidenceConfirmed {
		t.Errorf("confidence = %q, want confirmed: the canary was actually hit", f.Confidence)
	}
	if f.Severity != finding.SeverityHigh {
		t.Errorf("severity = %q", f.Severity)
	}
	if f.Category != finding.CategorySSRF {
		t.Errorf("category = %q", f.Category)
	}
	// The whole point is that no real address was involved.
	if !strings.Contains(f.Evidence.Summary, "loopback") {
		t.Errorf("the summary should say the canary was local: %q", f.Evidence.Summary)
	}
	if strings.Contains(f.Evidence.Summary, "169.254.169.254") {
		t.Error("the finding mentions a real metadata address")
	}
	if err := f.Validate(); err != nil {
		t.Errorf("the finding breaks the contract: %v", err)
	}
}

func TestSSRFCanaryStaysSilentWhenTheHostIsChecked(t *testing.T) {
	srv := fetchingServer(t, false)
	env := testEnv(t, srv.URL, importRoutes())

	fs, err := (&SSRFCanary{}).Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("the check fired on a server that validates the host: %+v", fs)
	}
}

// With nothing that looks like a fetch endpoint, the listener should never be
// started at all.
func TestSSRFCanaryDoesNothingWithNoCandidateRoutes(t *testing.T) {
	srv := fetchingServer(t, true)
	env := testEnv(t, srv.URL, orderRoutes())

	fs, err := (&SSRFCanary{}).Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("findings were produced with no fetch-like route: %+v", fs)
	}
}

// A body-carrying method can change state, so it is only probed once the
// operator has opened both gates.
func TestSSRFCanarySkipsMutatingRoutesUnderTheDefaultPosture(t *testing.T) {
	srv := fetchingServer(t, true)
	postRoute := []surface.Route{{
		Method: "POST", Path: "/api/import", Mutating: true,
		File: "src/routes/import.js", Handler: "importFeed",
	}}

	env := testEnv(t, srv.URL, postRoute)
	if got := (&SSRFCanary{}).candidates(env); len(got) != 0 {
		t.Errorf("built %d candidates for a POST route under the non-destructive default", len(got))
	}

	// With both gates open, the POST route becomes a candidate.
	nonDestructive := false
	env.Config.Dynamic.NonDestructive = &nonDestructive
	env.Config.Dynamic.DisposableEnv = true

	if got := (&SSRFCanary{}).candidates(env); len(got) == 0 {
		t.Error("no candidates were built for a POST route with both gates open")
	}
}

// The canary must bind to loopback only. A listener on all interfaces would be
// a service Vibe Killer had opened on the operator's machine.
func TestCanaryBindsToLoopbackAndShutsDown(t *testing.T) {
	canary, err := startCanary()
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(canary.addr, "127.0.0.1:") {
		t.Errorf("the canary bound to %q, want loopback only", canary.addr)
	}

	n := nonce()
	if _, hit := canary.Hit(n); hit {
		t.Error("the canary reported a hit before any request")
	}

	resp, err := http.Get(canary.URLFor(n))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	if _, hit := canary.Hit(n); !hit {
		t.Error("the canary did not record a request to its own URL")
	}
	// A different nonce must not be reported as hit, or a finding could be
	// raised from someone else's traffic.
	if _, hit := canary.Hit(nonce()); hit {
		t.Error("the canary reported a hit for a nonce that was never requested")
	}

	if err := canary.Close(); err != nil {
		t.Errorf("the canary did not shut down cleanly: %v", err)
	}
	if _, err := http.Get(canary.URLFor(n)); err == nil {
		t.Error("the canary still answers after being closed")
	}
}

func TestNonceIsUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		n := nonce()
		if seen[n] {
			t.Fatalf("nonce %q repeated", n)
		}
		seen[n] = true
	}
}

// --- path traversal -------------------------------------------------------

func fileRoutes() []surface.Route {
	return []surface.Route{{
		Method: "GET", Path: "/api/files/{name}", PathParams: []string{"name"},
		File: "src/routes/files.js", Line: 20, Handler: "readFile",
	}}
}

// fileServer models the two behaviours: one that joins the path and tries to
// open it, and one that resolves and checks it first.
func fileServer(t *testing.T, confined bool, disclosePath bool) *httptest.Server {
	t.Helper()
	const root = "/srv/app/uploads"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/api/files/")

		if confined && strings.Contains(name, "..") {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid filename"}`))
			return
		}

		// Join without resolving, as an unconfined handler does, and report
		// the literal path it tried. That is what a real ENOENT carries: the
		// path as it was passed to open(), dot-dot segments and all.
		joined := root + "/" + name

		w.WriteHeader(http.StatusNotFound)
		if disclosePath {
			_, _ = w.Write([]byte(`{"error":"ENOENT: no such file or directory, open '` + joined + `'"}`))
			return
		}
		_, _ = w.Write([]byte(`{"error":"not found"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// When the handler discloses where it looked, the escape is visible and the
// finding is confirmed.
func TestPathEscapeConfirmsWhenThePathIsDisclosed(t *testing.T) {
	srv := fileServer(t, false, true)
	env := testEnv(t, srv.URL, fileRoutes())

	fs, err := (&PathEscape{}).Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("expected one finding, got %d: %+v", len(fs), fs)
	}

	f := fs[0]
	if f.Confidence != finding.ConfidenceConfirmed {
		t.Errorf("confidence = %q, want confirmed: the handler said where it looked", f.Confidence)
	}
	if f.Severity != finding.SeverityHigh {
		t.Errorf("severity = %q", f.Severity)
	}
	// It must be clear that nothing was read.
	if !strings.Contains(f.Evidence.Summary, "No file was read") {
		t.Errorf("the summary should state that no file was read: %q", f.Evidence.Summary)
	}
	if err := f.Validate(); err != nil {
		t.Errorf("the finding breaks the contract: %v", err)
	}
}

// Without a disclosed path the differential alone supports only "likely", and
// the check must say so rather than claiming the stronger result.
func TestPathEscapeIsOnlyLikelyWithoutADisclosedPath(t *testing.T) {
	srv := fileServer(t, false, false)
	env := testEnv(t, srv.URL, fileRoutes())

	fs, err := (&PathEscape{}).Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("expected one finding, got %d", len(fs))
	}

	f := fs[0]
	if f.Confidence != finding.ConfidenceLikely {
		t.Errorf("confidence = %q, want likely: the escape itself was never observed", f.Confidence)
	}
	if !strings.Contains(f.Evidence.Summary, "not observed") {
		t.Errorf("the summary should admit what was not seen: %q", f.Evidence.Summary)
	}
}

func TestPathEscapeStaysSilentOnAConfinedHandler(t *testing.T) {
	for _, disclose := range []bool{true, false} {
		srv := fileServer(t, true, disclose)
		env := testEnv(t, srv.URL, fileRoutes())

		fs, err := (&PathEscape{}).Detect(context.Background(), env)
		if err != nil {
			t.Fatal(err)
		}
		if len(fs) != 0 {
			t.Errorf("the check fired on a handler that rejects traversal (disclose=%v): %+v", disclose, fs)
		}
	}
}

// A handler that returns 200 for a filename that cannot exist is not using the
// parameter as a path, so there is nothing to compare.
func TestPathEscapeDrawsNoConclusionWhenTheBaselineSucceeds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"content":"always the same"}`))
	}))
	t.Cleanup(srv.Close)

	env := testEnv(t, srv.URL, fileRoutes())

	fs, err := (&PathEscape{}).Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("a finding was raised although the baseline returned 200: %+v", fs)
	}
}

func TestPathEscapeReproduceReflectsTheFix(t *testing.T) {
	vuln := fileServer(t, false, true)
	env := testEnv(t, vuln.URL, fileRoutes())

	fs, err := (&PathEscape{}).Detect(context.Background(), env)
	if err != nil || len(fs) == 0 {
		t.Fatalf("setup: %d findings (%v)", len(fs), err)
	}

	res, err := (&PathEscape{}).Reproduce(context.Background(), env, fs[0])
	if err != nil {
		t.Fatal(err)
	}
	if !res.Reproduced {
		t.Errorf("should still reproduce: %s", res.Detail)
	}

	fixed := fileServer(t, true, true)
	fixedEnv := testEnv(t, fixed.URL, fileRoutes())

	res, err = (&PathEscape{}).Reproduce(context.Background(), fixedEnv, fs[0])
	if err != nil {
		t.Fatal(err)
	}
	if res.Reproduced {
		t.Errorf("reproduced against the fixed server: %s", res.Detail)
	}
}

func TestLooksLikeFileRoute(t *testing.T) {
	yes := []surface.Route{
		{Path: "/api/files/{name}", PathParams: []string{"name"}},
		{Path: "/download/{id}", PathParams: []string{"id"}},
		{Path: "/api/x/{filename}", PathParams: []string{"filename"}},
		{Path: "/assets/{key}", PathParams: []string{"key"}},
	}
	for _, r := range yes {
		if !looksLikeFileRoute(r) {
			t.Errorf("looksLikeFileRoute(%q) = false, want true", r.Path)
		}
	}

	no := []surface.Route{
		{Path: "/api/orders/{id}", PathParams: []string{"id"}},
		{Path: "/api/users/{uid}", PathParams: []string{"uid"}},
		// "profiles" contains "file", which a substring test would match.
		{Path: "/api/profiles/{id}", PathParams: []string{"id"}},
		// And these contain "doc" and "report" as substrings only.
		{Path: "/api/dockers/{id}", PathParams: []string{"id"}},
		{Path: "/api/reporters/{id}", PathParams: []string{"id"}},
	}
	for _, r := range no {
		if looksLikeFileRoute(r) {
			t.Errorf("looksLikeFileRoute(%q) = true, want false", r.Path)
		}
	}
}

func TestDisclosedDir(t *testing.T) {
	probe := "vk-probe-abc123"

	tests := []struct{ body, want string }{
		{`ENOENT: open '/srv/app/uploads/vk-probe-abc123'`, "/srv/app/uploads"},
		{`ENOENT: open '/etc/vk-probe-abc123'`, "/etc"},
		{`no such file: C:\srv\app\uploads\vk-probe-abc123`, "C:/srv/app/uploads"},
		{`{"error":"not found"}`, ""},
		{`ENOENT: open '/srv/other/somefile'`, ""},
	}
	for _, tc := range tests {
		if got := disclosedDir(tc.body, probe); got != tc.want {
			t.Errorf("disclosedDir(%q) = %q, want %q", tc.body, got, tc.want)
		}
	}
}

func TestLooksLikeFetchRoute(t *testing.T) {
	for _, p := range []string{"/api/import", "/fetch", "/api/url/preview", "/webhook", "/api/pdf"} {
		if !looksLikeFetchRoute(p) {
			t.Errorf("looksLikeFetchRoute(%q) = false, want true", p)
		}
	}
	for _, p := range []string{"/api/orders", "/api/users", "/health"} {
		if looksLikeFetchRoute(p) {
			t.Errorf("looksLikeFetchRoute(%q) = true, want false", p)
		}
	}
}
