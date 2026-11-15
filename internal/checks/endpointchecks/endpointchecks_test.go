package endpointchecks

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rohitanakiya/Vibe-Killer/internal/check"
	"github.com/rohitanakiya/Vibe-Killer/internal/config"
	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
	"github.com/rohitanakiya/Vibe-Killer/internal/httpx"
	"github.com/rohitanakiya/Vibe-Killer/internal/run"
	"github.com/rohitanakiya/Vibe-Killer/internal/surface"
)

// These tests run against in-process servers rather than the Express and Flask
// fixtures, so they are hermetic: no npm install, no pip install, no port
// juggling in CI. The fixtures still exist and are exercised by the static
// tests and the end-to-end demo; what is under test here is the checks'
// reasoning, which is the part that has to be exactly right.
//
// Every check is tested twice: against a server that has the weakness and
// against one that does not. A check that fires on both is not detecting
// anything.

// canaryBody is the record a check is allowed to read as proof.
const canaryBody = `{"id":90001,"userId":"userB","note":"VK-CANARY-USERB","total":4242}`

// otherBody is user A's own record, which a correct app returns to user A.
const otherBody = `{"id":90002,"userId":"userA","note":"VK-CANARY-USERA","total":1111}`

// tokenFor maps an Authorization header to a seeded user id.
func tokenFor(r *http.Request) string {
	h := r.Header.Get("Authorization")
	switch {
	case strings.HasSuffix(h, "userA-token"):
		return "userA"
	case strings.HasSuffix(h, "userB-token"):
		return "userB"
	default:
		return ""
	}
}

// vulnerableServer has a missing ownership check: it returns any order to any
// authenticated caller, and serves profiles with no authentication at all.
func vulnerableServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/api/orders/", func(w http.ResponseWriter, r *http.Request) {
		if tokenFor(r) == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Authenticated, then looks up by id with no ownership check.
		id := strings.TrimPrefix(r.URL.Path, "/api/orders/")
		w.Header().Set("Content-Type", "application/json")
		switch id {
		case "90001":
			_, _ = w.Write([]byte(canaryBody))
		case "90002":
			_, _ = w.Write([]byte(otherBody))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	mux.HandleFunc("/api/profiles/", func(w http.ResponseWriter, r *http.Request) {
		// No authentication at all.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(canaryBody))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// patchedServer scopes every lookup to the authenticated caller.
func patchedServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	handler := func(w http.ResponseWriter, r *http.Request) {
		user := tokenFor(r)
		if user == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		id := r.URL.Path[strings.LastIndexByte(r.URL.Path, '/')+1:]

		// The owner is part of the lookup, and a miss is a 404 so the
		// endpoint does not confirm another user's record exists.
		owner := map[string]string{"90001": "userB", "90002": "userA"}[id]
		if owner == "" || owner != user {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if id == "90001" {
			_, _ = w.Write([]byte(canaryBody))
			return
		}
		_, _ = w.Write([]byte(otherBody))
	}

	mux.HandleFunc("/api/orders/", handler)
	mux.HandleFunc("/api/profiles/", handler)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// testEnv builds a check environment pointed at a server.
func testEnv(t *testing.T, target string, routes []surface.Route) *check.Env {
	t.Helper()

	t.Setenv("VK_TEST_USERA", "userA-token")
	t.Setenv("VK_TEST_USERB", "userB-token")

	cfg := config.Defaults()
	cfg.AuthorizedTargets = []string{target}
	cfg.SeededUsers = []config.SeededUser{
		{ID: "userA", TokenEnv: "VK_TEST_USERA"},
		{ID: "userB", TokenEnv: "VK_TEST_USERB"},
	}
	cfg.CanaryRecords = []config.CanaryRecord{
		{Owner: "userB", Resource: "order", ID: "90001", Marker: "VK-CANARY-USERB"},
	}
	// Keep the tests fast: the rate limiter is correctness-tested elsewhere.
	cfg.Dynamic.MaxRPS = 1000
	cfg.Dynamic.TimeoutSeconds = 5

	if err := cfg.Validate(); err != nil {
		t.Fatalf("the test config is not valid: %v", err)
	}

	guard, err := cfg.Guard(true)
	if err != nil {
		t.Fatal(err)
	}

	r, err := run.Create(t.TempDir(), run.Meta{
		RunID: "test", Tool: "vibekiller", Mode: "test", Target: target,
		TargetOwnershipAcknowledged: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })

	client, err := httpx.New(httpx.Options{
		Guard:    guard,
		MaxRPS:   1000,
		Timeout:  5 * time.Second,
		Recorder: r,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	return &check.Env{
		Config: &cfg, Guard: guard, Run: r, HTTP: client, Target: target,
		Surface:  &surface.Surface{Routes: routes},
		RepoRoot: t.TempDir(),
	}
}

func orderRoutes() []surface.Route {
	return []surface.Route{
		{
			Method: "GET", Path: "/api/orders/{id}", PathParams: []string{"id"},
			File: "src/routes/orders.js", Line: 42, Handler: "getOrder",
			Middleware: []string{"authenticate"}, DeclaredAuth: "authenticate",
		},
		{
			Method: "GET", Path: "/api/profiles/{id}", PathParams: []string{"id"},
			File: "src/routes/profiles.js", Line: 10, Handler: "getProfile",
		},
	}
}

// --- IDOR ------------------------------------------------------------------

func TestIDORFiresOnMissingOwnershipCheck(t *testing.T) {
	srv := vulnerableServer(t)
	env := testEnv(t, srv.URL, orderRoutes())

	fs, err := (&IDOR{}).Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("expected exactly one finding, got %d", len(fs))
	}

	f := fs[0]
	if f.RuleID != "idor.sequential-id-access" {
		t.Errorf("rule_id = %q", f.RuleID)
	}
	// A dynamic check that reproduced the issue is the only thing allowed to
	// claim confirmed.
	if f.Confidence != finding.ConfidenceConfirmed {
		t.Errorf("confidence = %q, want confirmed", f.Confidence)
	}
	if f.Severity != finding.SeverityHigh {
		t.Errorf("severity = %q", f.Severity)
	}
	if f.Reproduction == nil || f.Reproduction.ArtifactPath == "" {
		t.Error("a confirmed finding must carry a replayable artifact")
	}
	// The location must carry both halves so the reporter can merge this with
	// the static finding about the same handler.
	if f.Location.Endpoint != "GET /api/orders/{id}" {
		t.Errorf("endpoint = %q", f.Location.Endpoint)
	}
	if f.Location.File == "" || f.Location.Symbol == "" {
		t.Errorf("location is missing the code position: %+v", f.Location)
	}
	if err := f.Validate(); err != nil {
		t.Errorf("the finding breaks the contract: %v", err)
	}

	// The evidence must not carry the token it used.
	encoded, _ := json.Marshal(f)
	if strings.Contains(string(encoded), "userA-token") && !strings.Contains(f.Evidence.Request.Auth, "userA-token") {
		t.Error("a raw token leaked into the finding")
	}
	if got := f.Evidence.Request.Headers["Authorization"]; got != finding.RedactedMarker {
		t.Errorf("the Authorization header was recorded as %q, want it redacted", got)
	}
}

func TestIDORStaysSilentWhenOwnershipIsChecked(t *testing.T) {
	srv := patchedServer(t)
	env := testEnv(t, srv.URL, orderRoutes())

	fs, err := (&IDOR{}).Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Fatalf("the check fired on an application that does scope its lookups: %+v", fs)
	}
}

// The baseline step is what keeps this check honest. If the canary and the
// route do not line up, the owner's own request fails, and a refusal for the
// other user proves nothing about authorization. Without the baseline a
// scanner reports every such route as secure.
func TestIDORDrawsNoConclusionWhenTheBaselineFails(t *testing.T) {
	mux := http.NewServeMux()
	// Everything 404s, as it would if the canary id did not exist.
	mux.HandleFunc("/api/orders/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	env := testEnv(t, srv.URL, orderRoutes())

	fs, err := (&IDOR{}).Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("a finding was raised although the baseline never succeeded: %+v", fs)
	}
}

// A 200 with a body that is not the owner's record is not a disclosure. Plenty
// of applications answer an unauthorized read with 200 and an empty result.
func TestIDORRequiresTheCanaryToActuallyComeBack(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/orders/", func(w http.ResponseWriter, r *http.Request) {
		if tokenFor(r) == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if tokenFor(r) == "userB" {
			_, _ = w.Write([]byte(canaryBody))
			return
		}
		// 200, but scoped to the caller: no record disclosed.
		_, _ = w.Write([]byte(`{}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	env := testEnv(t, srv.URL, orderRoutes())

	fs, err := (&IDOR{}).Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("a 200 with an empty body was reported as a disclosure: %+v", fs)
	}
}

func TestIDORReproduceReflectsTheFix(t *testing.T) {
	// Find it on the vulnerable server.
	vuln := vulnerableServer(t)
	env := testEnv(t, vuln.URL, orderRoutes())

	fs, err := (&IDOR{}).Detect(context.Background(), env)
	if err != nil || len(fs) != 1 {
		t.Fatalf("setup: expected one finding, got %d (%v)", len(fs), err)
	}
	f := fs[0]

	// Still reproducible against the same server.
	res, err := (&IDOR{}).Reproduce(context.Background(), env, f)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Reproduced {
		t.Errorf("the finding should still reproduce against the unfixed server: %s", res.Detail)
	}

	// No longer reproducible against the fixed one.
	fixed := patchedServer(t)
	fixedEnv := testEnv(t, fixed.URL, orderRoutes())

	res, err = (&IDOR{}).Reproduce(context.Background(), fixedEnv, f)
	if err != nil {
		t.Fatal(err)
	}
	if res.Reproduced {
		t.Errorf("the finding reproduced against the fixed server: %s", res.Detail)
	}
	if !strings.Contains(res.Detail, "Not reproducible") {
		t.Errorf("detail = %q", res.Detail)
	}
}

// --- unprotected endpoints -------------------------------------------------

func TestUnprotectedFiresOnAnonymousCanaryRead(t *testing.T) {
	srv := vulnerableServer(t)
	// Point the canary's resource at the unauthenticated profiles route.
	routes := []surface.Route{{
		Method: "GET", Path: "/api/orders/{id}", PathParams: []string{"id"},
		File: "src/routes/orders.js", Handler: "getOrder",
	}}
	env := testEnv(t, srv.URL, routes)

	fs, err := (&Unprotected{}).Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	// The vulnerable orders route requires a token, so nothing should be
	// reported for an anonymous read of it.
	for _, f := range fs {
		if strings.HasPrefix(f.Evidence.EvidenceKey, "anon:") {
			t.Errorf("reported an anonymous disclosure on a route that does require a token: %+v", f)
		}
	}

	// Now the profiles route, which has no authentication at all.
	routes = []surface.Route{{
		Method: "GET", Path: "/api/profiles/{id}", PathParams: []string{"id"},
		File: "src/routes/profiles.js", Handler: "getProfile",
	}}
	env = testEnv(t, srv.URL, routes)
	env.Config.CanaryRecords = []config.CanaryRecord{
		{Owner: "userB", Resource: "profile", ID: "90001", Marker: "VK-CANARY-USERB"},
	}

	fs, err = (&Unprotected{}).Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) == 0 {
		t.Fatal("the check did not fire on an endpoint that serves a record with no credentials")
	}

	f := fs[0]
	if f.Confidence != finding.ConfidenceConfirmed {
		t.Errorf("confidence = %q, want confirmed", f.Confidence)
	}
	if f.Severity != finding.SeverityCritical {
		t.Errorf("severity = %q, want critical", f.Severity)
	}
	if f.Evidence.Request.Auth != "none" {
		t.Errorf("the evidence should record that no credentials were sent, got %q", f.Evidence.Request.Auth)
	}
	if err := f.Validate(); err != nil {
		t.Errorf("the finding breaks the contract: %v", err)
	}
}

func TestUnprotectedStaysSilentWhenAuthIsRequired(t *testing.T) {
	srv := patchedServer(t)
	env := testEnv(t, srv.URL, orderRoutes())
	env.Surface.AuthLayers = []surface.AuthLayer{{Kind: "middleware", Name: "authenticate", Global: true}}

	fs, err := (&Unprotected{}).Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("the check fired on an application that requires authentication: %+v", fs)
	}
}

// Login, health and the rest have to answer an anonymous caller. Reporting
// them would bury the findings that matter.
func TestPublicByDesignPathsAreNotReported(t *testing.T) {
	public := []string{"/login", "/signup", "/health", "/healthz", "/metrics", "/docs", "/openapi.json", "/", "/static/app.css", "/api/auth/callback"}
	for _, p := range public {
		if !isPublicByDesign(p) {
			t.Errorf("isPublicByDesign(%q) = false, want true", p)
		}
	}

	private := []string{"/api/orders/{id}", "/api/profiles/{id}", "/api/admin/users", "/api/invoices"}
	for _, p := range private {
		if isPublicByDesign(p) {
			t.Errorf("isPublicByDesign(%q) = true, want false", p)
		}
	}
}

// --- CORS ------------------------------------------------------------------

func TestCORSFiresOnReflectedOriginWithCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)

	env := testEnv(t, srv.URL, nil)

	fs, err := (&CORS{}).Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("expected one finding, got %d", len(fs))
	}
	f := fs[0]
	if f.Severity != finding.SeverityHigh {
		t.Errorf("reflected origin with credentials should be high, got %q", f.Severity)
	}
	if f.Confidence != finding.ConfidenceConfirmed {
		t.Errorf("confidence = %q", f.Confidence)
	}
	// The probe origin is in a reserved domain that cannot resolve, which is
	// what makes reflection distinguishable from an allowlist.
	if !strings.Contains(f.Evidence.Summary, ".invalid") {
		t.Errorf("the summary should explain why this is reflection: %q", f.Evidence.Summary)
	}
	if err := f.Validate(); err != nil {
		t.Errorf("the finding breaks the contract: %v", err)
	}
}

func TestCORSStaysSilentOnAnAllowlist(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") == "https://app.example.invalid" {
			w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)

	env := testEnv(t, srv.URL, nil)

	fs, err := (&CORS{}).Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("the check fired on an application using an allowlist: %+v", fs)
	}
}

// --- security headers ------------------------------------------------------

func TestSecurityHeadersReportsOnlyWhatIsMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)

	env := testEnv(t, srv.URL, nil)

	fs, err := (&SecurityHeaders{}).Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("expected one finding, got %d", len(fs))
	}
	f := fs[0]

	if strings.Contains(f.Evidence.Observed, "X-Content-Type-Options") {
		t.Error("a header that was present is listed as missing")
	}
	for _, want := range []string{"X-Frame-Options", "Content-Security-Policy"} {
		if !strings.Contains(f.Evidence.Observed, want) {
			t.Errorf("%s is missing but was not reported", want)
		}
	}
	// HSTS over plain HTTP is advice the operator cannot act on.
	if strings.Contains(f.Evidence.Observed, "Strict-Transport-Security") {
		t.Error("HSTS was reported against a plain-HTTP target")
	}
	// A missing header is hardening, not a vulnerability. Ranking it higher
	// is how scanner output becomes noise.
	if f.Severity != finding.SeverityLow {
		t.Errorf("severity = %q, want low", f.Severity)
	}
}

func TestSecurityHeadersStaysSilentWhenAllArePresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)

	env := testEnv(t, srv.URL, nil)

	fs, err := (&SecurityHeaders{}).Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("the check fired on a hardened response: %+v", fs)
	}
}

// --- verbose errors --------------------------------------------------------

func TestVerboseErrorsFiresOnADisclosedTraceback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Traceback (most recent call last):\n  File \"/srv/app/app.py\", line 42\nValueError: invalid literal for int()"))
	}))
	t.Cleanup(srv.Close)

	env := testEnv(t, srv.URL, orderRoutes())

	fs, err := (&VerboseErrors{}).Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) == 0 {
		t.Fatal("the check did not fire on a response containing a traceback")
	}
	f := fs[0]
	if f.Confidence != finding.ConfidenceConfirmed {
		t.Errorf("confidence = %q", f.Confidence)
	}
	if !strings.Contains(f.Evidence.Summary, "Python traceback") {
		t.Errorf("the summary should name what was disclosed: %q", f.Evidence.Summary)
	}
	if err := f.Validate(); err != nil {
		t.Errorf("the finding breaks the contract: %v", err)
	}
}

// An interactive debugger is remote code execution, not an information leak,
// and has to be ranked as such.
func TestVerboseErrorsTreatsAnInteractiveDebuggerAsCritical(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`<html><title>ValueError // Werkzeug Debugger</title><div class="console-ready">`))
	}))
	t.Cleanup(srv.Close)

	env := testEnv(t, srv.URL, orderRoutes())

	fs, err := (&VerboseErrors{}).Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) == 0 {
		t.Fatal("the check did not fire on an exposed interactive debugger")
	}
	if fs[0].Severity != finding.SeverityCritical {
		t.Errorf("severity = %q, want critical for a reachable debugger", fs[0].Severity)
	}
	if !strings.Contains(fs[0].Remediation.Guidance, "immediately") {
		t.Errorf("the guidance should be urgent: %q", fs[0].Remediation.Guidance)
	}
}

func TestVerboseErrorsStaysSilentOnAGenericError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid id","correlationId":"a1b2c3"}`))
	}))
	t.Cleanup(srv.Close)

	env := testEnv(t, srv.URL, orderRoutes())

	fs, err := (&VerboseErrors{}).Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("the check fired on a generic error response: %+v", fs)
	}
}

// --- scope enforcement -----------------------------------------------------

// A check cannot reach a host the operator never declared, even if it asks
// directly. This is the property the whole design rests on, so it is tested
// at the layer a check actually uses.
func TestChecksCannotReachAnUndeclaredHost(t *testing.T) {
	declared := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(declared.Close)

	undeclared := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("a request reached a host that was never declared")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(undeclared.Close)

	env := testEnv(t, declared.URL, nil)

	_, err := env.HTTP.Do(context.Background(), httpx.Request{
		RuleID: "test", Method: http.MethodGet, URL: undeclared.URL + "/api/secrets",
	})
	if err == nil {
		t.Fatal("the client allowed a request to an undeclared host")
	}
	if !strings.Contains(err.Error(), "outside the declared scope") {
		t.Errorf("error = %v, want a scope refusal", err)
	}
}

// --- helpers ---------------------------------------------------------------

func TestFillParams(t *testing.T) {
	tests := []struct{ path, value, want string }{
		{"/api/orders/{id}", "90001", "/api/orders/90001"},
		{"/api/users/{uid}/orders/{id}", "7", "/api/users/7/orders/7"},
		{"/api/orders", "90001", "/api/orders"},
	}
	for _, tc := range tests {
		if got := fillParams(tc.path, tc.value); got != tc.want {
			t.Errorf("fillParams(%q, %q) = %q, want %q", tc.path, tc.value, got, tc.want)
		}
	}
}

func TestRoutesForResourceMatchesSingularAndPlural(t *testing.T) {
	s := &surface.Surface{Routes: []surface.Route{
		{Method: "GET", Path: "/api/orders/{id}", PathParams: []string{"id"}},
		{Method: "GET", Path: "/api/orders/{id}/items/{itemId}", PathParams: []string{"id", "itemId"}},
		{Method: "GET", Path: "/api/invoices/{id}", PathParams: []string{"id"}},
		{Method: "POST", Path: "/api/orders/{id}", PathParams: []string{"id"}},
		{Method: "GET", Path: "/api/orders", PathParams: nil},
	}}

	got := routesForResource(s, "order", "GET")
	if len(got) != 2 {
		t.Fatalf("got %d routes, want the two GET order routes: %+v", len(got), got)
	}
	// The simplest by-id route must come first, since that is the one a canary
	// lookup should use.
	if got[0].Path != "/api/orders/{id}" {
		t.Errorf("routes are not ordered simplest first: %+v", got)
	}

	if len(routesForResource(s, "widget", "GET")) != 0 {
		t.Error("matched a resource that has no routes")
	}
	if len(routesForResource(nil, "order", "GET")) != 0 {
		t.Error("matched against a nil surface")
	}
}

func TestBodyLooksLikeRecord(t *testing.T) {
	for _, body := range []string{`{"id":1}`, `[{"id":1}]`, "some text"} {
		if !bodyLooksLikeRecord(body) {
			t.Errorf("bodyLooksLikeRecord(%q) = false, want true", body)
		}
	}
	// These are what an application returns when it correctly finds nothing.
	for _, body := range []string{"", "  ", "null", "[]", "{}", `""`, "0", "false"} {
		if bodyLooksLikeRecord(body) {
			t.Errorf("bodyLooksLikeRecord(%q) = true, want false", body)
		}
	}
}
