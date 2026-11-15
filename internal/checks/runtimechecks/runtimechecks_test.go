package runtimechecks

import (
	"context"
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
	"github.com/rohitanakiya/Vibe-Killer/internal/runtime"
	"github.com/rohitanakiya/Vibe-Killer/internal/surface"
)

// stubObserver stands in for an agent, so these tests exercise the checks'
// reasoning without needing a real application with a real database.
type stubObserver struct {
	byCorrelation map[string]runtime.Observation
	attached      bool
}

func (s *stubObserver) Name() string                { return "stub" }
func (s *stubObserver) Start(context.Context) error { return nil }
func (s *stubObserver) Attached() bool              { return s.attached }
func (s *stubObserver) Stop() error                 { return nil }

func (s *stubObserver) Observations() []runtime.Observation {
	out := make([]runtime.Observation, 0, len(s.byCorrelation))
	for _, o := range s.byCorrelation {
		out = append(out, o)
	}
	return out
}

func (s *stubObserver) ForCorrelation(id string) (runtime.Observation, bool) {
	o, ok := s.byCorrelation[id]
	return o, ok
}

// recordServer answers an authenticated read of the canary.
func recordServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":90001,"note":"VK-CANARY-USERB"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testEnv(t *testing.T, target string, routes []surface.Route, obs *stubObserver) *check.Env {
	t.Helper()

	t.Setenv("VK_TEST_USERB", "userB-token")

	cfg := config.Defaults()
	cfg.AuthorizedTargets = []string{target}
	cfg.SeededUsers = []config.SeededUser{{ID: "userB", TokenEnv: "VK_TEST_USERB"}}
	cfg.CanaryRecords = []config.CanaryRecord{
		{Owner: "userB", Resource: "order", ID: "90001", Marker: "VK-CANARY-USERB"},
	}
	cfg.Dynamic.MaxRPS = 1000
	cfg.Dynamic.TimeoutSeconds = 5

	if err := cfg.Validate(); err != nil {
		t.Fatalf("test config invalid: %v", err)
	}

	guard, err := cfg.Guard(true)
	if err != nil {
		t.Fatal(err)
	}

	r, err := run.Create(t.TempDir(), run.Meta{RunID: "test", Tool: "vibekiller", Mode: "with-runtime"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })

	client, err := httpx.New(httpx.Options{
		Guard: guard, MaxRPS: 1000, Timeout: 5 * time.Second, Recorder: r,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	return &check.Env{
		Config: &cfg, Guard: guard, Run: r, HTTP: client, Target: target,
		Surface:  &surface.Surface{Routes: routes},
		RepoRoot: t.TempDir(),
		Runtime:  obs,
	}
}

func orderRoute() []surface.Route {
	return []surface.Route{{
		Method: "GET", Path: "/api/orders/{id}", PathParams: []string{"id"},
		File: "src/routes/orders.js", Line: 42, Handler: "getOrder",
		Middleware: []string{"authenticate"}, DeclaredAuth: "authenticate",
	}}
}

// --- query owner filter ----------------------------------------------------

// The finding this check exists for: a legitimate read by the record's own
// owner, whose SQL shows there is no ownership constraint at all.
func TestQueryOwnerFilterFiresOnAnUnscopedRead(t *testing.T) {
	srv := recordServer(t)

	obs := &stubObserver{attached: true, byCorrelation: map[string]runtime.Observation{
		"vk-order-90001-owner": {
			Method: "GET", Path: "/api/orders/90001", Status: 200, Handler: "getOrder",
			AuthChecks: []string{"authenticate"},
			Queries: []runtime.Query{
				{SQL: "SELECT id, item, total FROM orders WHERE id = ?", ParamCount: 1},
			},
		},
	}}

	env := testEnv(t, srv.URL, orderRoute(), obs)

	fs, err := (&QueryOwnerFilter{}).Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("expected one finding, got %d: %+v", len(fs), fs)
	}

	f := fs[0]
	if f.Source != finding.SourceRuntime {
		t.Errorf("source = %q, want runtime", f.Source)
	}
	if f.Confidence != finding.ConfidenceConfirmed {
		t.Errorf("confidence = %q", f.Confidence)
	}
	if f.Severity != finding.SeverityHigh {
		t.Errorf("severity = %q", f.Severity)
	}
	// The statement is the evidence, and it is what makes this a better
	// handoff than the endpoint finding: the fix is visible.
	if !strings.Contains(f.Evidence.Snippet, "SELECT id, item, total FROM orders") {
		t.Errorf("the statement is not in the evidence: %q", f.Evidence.Snippet)
	}
	if !strings.Contains(f.Evidence.Summary, "orders") {
		t.Errorf("the summary should name the table: %q", f.Evidence.Summary)
	}
	// It must be clear that no boundary was crossed.
	if !strings.Contains(f.Evidence.Summary, "No boundary was crossed") {
		t.Errorf("the summary should say no boundary was crossed: %q", f.Evidence.Summary)
	}
	if err := f.Validate(); err != nil {
		t.Errorf("the finding breaks the contract: %v", err)
	}
}

func TestQueryOwnerFilterStaysSilentOnAScopedRead(t *testing.T) {
	srv := recordServer(t)

	obs := &stubObserver{attached: true, byCorrelation: map[string]runtime.Observation{
		"vk-order-90001-owner": {
			Method: "GET", Path: "/api/orders/90001", Status: 200,
			Queries: []runtime.Query{
				{SQL: "SELECT id, item FROM orders WHERE id = ? AND user_id = ?", ParamCount: 2},
			},
		},
	}}

	env := testEnv(t, srv.URL, orderRoute(), obs)

	fs, err := (&QueryOwnerFilter{}).Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("the check fired on a query that scopes by owner: %+v", fs)
	}
}

// A handler that issues several statements, one of which is correctly scoped,
// must not be excused by that one.
func TestQueryOwnerFilterFindsTheUnscopedStatementAmongSeveral(t *testing.T) {
	srv := recordServer(t)

	obs := &stubObserver{attached: true, byCorrelation: map[string]runtime.Observation{
		"vk-order-90001-owner": {
			Method: "GET", Path: "/api/orders/90001", Status: 200,
			Queries: []runtime.Query{
				{SQL: "SELECT id FROM sessions WHERE token = ? AND user_id = ?", ParamCount: 2},
				{SQL: "SELECT * FROM orders WHERE id = ?", ParamCount: 1},
			},
		},
	}}

	env := testEnv(t, srv.URL, orderRoute(), obs)

	fs, err := (&QueryOwnerFilter{}).Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("expected one finding, got %d", len(fs))
	}
	if !strings.Contains(fs[0].Evidence.Snippet, "FROM orders") {
		t.Errorf("the wrong statement was reported: %q", fs[0].Evidence.Snippet)
	}
}

// No observation means the agent is not reporting for this route. That is a
// gap in coverage, not a clean result, and it must not produce a finding
// either way.
func TestQueryOwnerFilterReportsNothingWithoutAnObservation(t *testing.T) {
	srv := recordServer(t)
	obs := &stubObserver{attached: true, byCorrelation: map[string]runtime.Observation{}}

	env := testEnv(t, srv.URL, orderRoute(), obs)

	fs, err := (&QueryOwnerFilter{}).Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("a finding was produced with no observation to read: %+v", fs)
	}
}

func TestQueryOwnerFilterNeedsAnObserver(t *testing.T) {
	srv := recordServer(t)
	env := testEnv(t, srv.URL, orderRoute(), nil)
	env.Runtime = nil

	if _, err := (&QueryOwnerFilter{}).Detect(context.Background(), env); err == nil {
		t.Error("expected an error with no observer attached")
	}
}

// --- auth check fired ------------------------------------------------------

// The gap nothing else can see: the source declares authorization, the request
// succeeds, and the middleware never ran.
func TestAuthCheckFiredFiresWhenNothingRan(t *testing.T) {
	srv := recordServer(t)

	obs := &stubObserver{attached: true, byCorrelation: map[string]runtime.Observation{
		"vk-auth-GET-/api/orders/{id}": {
			Method: "GET", Path: "/api/orders/90001", Status: 200, Handler: "getOrder",
			AuthChecks: nil,
		},
	}}

	env := testEnv(t, srv.URL, orderRoute(), obs)

	fs, err := (&AuthCheckFired{}).Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("expected one finding, got %d: %+v", len(fs), fs)
	}

	f := fs[0]
	if f.Source != finding.SourceRuntime {
		t.Errorf("source = %q", f.Source)
	}
	if f.Confidence != finding.ConfidenceConfirmed {
		t.Errorf("confidence = %q", f.Confidence)
	}
	// The summary has to explain why this is invisible from outside, or the
	// reader will not believe it.
	if !strings.Contains(f.Evidence.Summary, "invisible from outside") {
		t.Errorf("the summary should explain why no other check finds this: %q", f.Evidence.Summary)
	}
	if !strings.Contains(f.Evidence.Summary, "authenticate") {
		t.Errorf("the summary should name the declared middleware: %q", f.Evidence.Summary)
	}
	if err := f.Validate(); err != nil {
		t.Errorf("the finding breaks the contract: %v", err)
	}
}

func TestAuthCheckFiredStaysSilentWhenTheCheckRan(t *testing.T) {
	srv := recordServer(t)

	obs := &stubObserver{attached: true, byCorrelation: map[string]runtime.Observation{
		"vk-auth-GET-/api/orders/{id}": {
			Method: "GET", Path: "/api/orders/90001", Status: 200,
			AuthChecks: []string{"authenticate"},
		},
	}}

	env := testEnv(t, srv.URL, orderRoute(), obs)

	fs, err := (&AuthCheckFired{}).Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("the check fired although the middleware ran: %+v", fs)
	}
}

// A route that declares no authorization has nothing to contradict, so this
// check has nothing to say about it. The unprotected-endpoint check owns that
// case.
func TestAuthCheckFiredIgnoresRoutesThatDeclareNoAuth(t *testing.T) {
	srv := recordServer(t)

	routes := []surface.Route{{
		Method: "GET", Path: "/api/public/{id}", PathParams: []string{"id"},
		File: "src/routes/public.js", Handler: "getPublic",
	}}
	obs := &stubObserver{attached: true, byCorrelation: map[string]runtime.Observation{
		"vk-auth-GET-/api/public/{id}": {Method: "GET", Status: 200},
	}}

	env := testEnv(t, srv.URL, routes, obs)

	fs, err := (&AuthCheckFired{}).Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("the check fired on a route that declares no authorization: %+v", fs)
	}
}

// --- gating ----------------------------------------------------------------

// A runtime check must not run against a sink nothing is posting to. A clean
// result there would mean only that the agent was never installed, which is
// the most misleading outcome available.
func TestRuntimeChecksAreSkippedWhenTheAgentIsNotReporting(t *testing.T) {
	srv := recordServer(t)
	obs := &stubObserver{attached: false, byCorrelation: map[string]runtime.Observation{}}

	env := testEnv(t, srv.URL, orderRoute(), obs)

	for _, c := range []check.Check{&QueryOwnerFilter{}, &AuthCheckFired{}} {
		ok, reason := check.CanRun(c.Meta(), env)
		if ok {
			t.Errorf("%s was allowed to run with no agent reporting", c.Meta().RuleID)
			continue
		}
		if !strings.Contains(reason, "agent is not reporting") {
			t.Errorf("%s skip reason = %q, want it to name the missing agent", c.Meta().RuleID, reason)
		}
	}

	// And with no observer at all, the reason should name the flag.
	env.Runtime = nil
	_, reason := check.CanRun((&QueryOwnerFilter{}).Meta(), env)
	if !strings.Contains(reason, "--with-runtime") {
		t.Errorf("skip reason = %q, want it to name the flag", reason)
	}
}

func TestRuntimeChecksAreRegisteredOnTheRuntimeLayer(t *testing.T) {
	for _, id := range []string{"runtime.query-missing-owner-filter", "runtime.auth-check-not-fired"} {
		c, ok := check.Default.Get(id)
		if !ok {
			t.Errorf("%s is not registered", id)
			continue
		}
		if c.Meta().Layer != check.LayerRuntime {
			t.Errorf("%s is on layer %q, want runtime", id, c.Meta().Layer)
		}
	}
}

// --- helpers ---------------------------------------------------------------

func TestFillParams(t *testing.T) {
	if got := fillParams("/api/orders/{id}", "90001"); got != "/api/orders/90001" {
		t.Errorf("got %q", got)
	}
	if got := fillParams("/api/orders", "90001"); got != "/api/orders" {
		t.Errorf("got %q", got)
	}
}

func TestRoutesForResource(t *testing.T) {
	s := &surface.Surface{Routes: []surface.Route{
		{Method: "GET", Path: "/api/orders/{id}", PathParams: []string{"id"}},
		{Method: "POST", Path: "/api/orders/{id}", PathParams: []string{"id"}},
		{Method: "GET", Path: "/api/invoices/{id}", PathParams: []string{"id"}},
		{Method: "GET", Path: "/api/orders", PathParams: nil},
	}}

	got := routesForResource(s, "order")
	if len(got) != 1 || got[0].Path != "/api/orders/{id}" {
		t.Errorf("got %+v, want only the GET by-id order route", got)
	}
	if len(routesForResource(nil, "order")) != 0 {
		t.Error("matched against a nil surface")
	}
}
