package exposurechecks

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
)

// service models one component. acceptsToken decides whether it verifies the
// token the other component issued, which is the shared-trust-domain
// condition.
func service(t *testing.T, acceptsToken bool, probed *[]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if probed != nil {
			*probed = append(*probed, r.URL.Path)
		}

		token := r.Header.Get("Authorization")
		if token == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"authentication required"}`))
			return
		}
		if !acceptsToken {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid token for this service"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"userB","email":"grace@example.invalid"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testEnv(t *testing.T, primary string, declared []string) *check.Env {
	t.Helper()

	t.Setenv("VK_TEST_USERB", "userB-token")

	cfg := config.Defaults()
	cfg.AuthorizedTargets = declared
	cfg.SeededUsers = []config.SeededUser{{ID: "userB", TokenEnv: "VK_TEST_USERB"}}
	cfg.Dynamic.MaxRPS = 1000
	cfg.Dynamic.TimeoutSeconds = 5

	if err := cfg.Validate(); err != nil {
		t.Fatalf("test config invalid: %v", err)
	}

	guard, err := cfg.Guard(true)
	if err != nil {
		t.Fatal(err)
	}

	r, err := run.Create(t.TempDir(), run.Meta{RunID: "test", Tool: "vibekiller", Mode: "full"})
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
		Config: &cfg, Guard: guard, Run: r, HTTP: client, Target: primary,
		RepoRoot: t.TempDir(),
	}
}

// The finding this analyzer exists for: a token minted by one component is
// verified by another, so the two are one trust domain.
func TestFiresWhenANeighbourAcceptsTheOtherComponentsToken(t *testing.T) {
	primary := service(t, true, nil)
	neighbour := service(t, true, nil)

	env := testEnv(t, primary.URL, []string{primary.URL, neighbour.URL})

	fs, err := (&SharedTrustDomain{}).Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("expected one finding, got %d: %+v", len(fs), fs)
	}

	f := fs[0]
	if f.Source != finding.SourceBlastRadius {
		t.Errorf("source = %q, want blast-radius", f.Source)
	}
	if f.Confidence != finding.ConfidenceConfirmed {
		t.Errorf("confidence = %q", f.Confidence)
	}
	if f.Category != finding.CategoryCrossService {
		t.Errorf("category = %q", f.Category)
	}

	// The blast radius block is what makes this finding what it is.
	if f.BlastRadius == nil {
		t.Fatal("the finding carries no blast radius")
	}
	if f.BlastRadius.Scope != finding.ScopeDeclaredOnly {
		t.Errorf("scope = %q, want declared-targets-only", f.BlastRadius.Scope)
	}
	if len(f.BlastRadius.Reached) != 1 {
		t.Errorf("reached = %v", f.BlastRadius.Reached)
	}
	if f.BlastRadius.ReachableFrom == "" {
		t.Error("reachable_from is empty")
	}

	// Separating trust domains is a deployment decision, not a code edit.
	if f.Remediation.FixableByGiver {
		t.Error("the finding claims to be auto-fixable; new signing keys are a deployment decision")
	}
	if f.Remediation.HumanRequiredReason == "" {
		t.Error("no reason a human is required")
	}

	// The summary must make clear that nothing real was replayed.
	if !strings.Contains(f.Evidence.Summary, "no credential from your repository") {
		t.Errorf("the summary should state that no real credential was used: %q", f.Evidence.Summary)
	}
	if got := f.Evidence.Request.Headers["Authorization"]; got != finding.RedactedMarker {
		t.Errorf("the Authorization header was recorded as %q, want it redacted", got)
	}

	if err := f.Validate(); err != nil {
		t.Errorf("the finding breaks the contract: %v", err)
	}
}

// Separate trust domains are the correct arrangement, and the analyzer has to
// stay quiet about them.
func TestStaysSilentWhenTheNeighbourRejectsTheToken(t *testing.T) {
	primary := service(t, true, nil)
	neighbour := service(t, false, nil)

	env := testEnv(t, primary.URL, []string{primary.URL, neighbour.URL})

	fs, err := (&SharedTrustDomain{}).Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("the analyzer fired on components with separate trust domains: %+v", fs)
	}
}

// With one host declared there is no neighbour, and the analyzer must say so
// rather than inventing something to compare against.
func TestDoesNothingWithASingleDeclaredHost(t *testing.T) {
	primary := service(t, true, nil)

	env := testEnv(t, primary.URL, []string{primary.URL})

	fs, err := (&SharedTrustDomain{}).Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("findings were produced with no neighbour declared: %+v", fs)
	}
}

// This is the property the whole package rests on. The analyzer is the one
// part of the tool that contacts more than one host, so it must contact only
// the ones the operator listed — and nothing else, even when something else
// is running and reachable.
func TestNeverContactsAnUndeclaredHost(t *testing.T) {
	primary := service(t, true, nil)

	var declaredProbes, undeclaredProbes []string
	neighbour := service(t, true, &declaredProbes)
	undeclared := service(t, true, &undeclaredProbes)

	// The undeclared service is up and would answer, but it is not listed.
	env := testEnv(t, primary.URL, []string{primary.URL, neighbour.URL})

	if _, err := (&SharedTrustDomain{}).Detect(context.Background(), env); err != nil {
		t.Fatal(err)
	}

	if len(declaredProbes) == 0 {
		t.Error("the declared neighbour was never probed")
	}
	if len(undeclaredProbes) != 0 {
		t.Errorf("the analyzer contacted a host that was never declared: %v", undeclaredProbes)
	}

	// And asking the client directly is refused too, so a bug in the check
	// could not reach it either.
	_, err := env.HTTP.Do(context.Background(), httpx.Request{
		RuleID: "test", Method: http.MethodGet, URL: undeclared.URL + "/api/me",
	})
	if err == nil {
		t.Fatal("the client allowed a request to an undeclared host")
	}
	if !strings.Contains(err.Error(), "outside the declared scope") {
		t.Errorf("error = %v, want a scope refusal", err)
	}
}

// An endpoint that serves anonymous callers says nothing about whether a token
// was verified, so it must not be read as acceptance.
func TestAnAnonymouslyReadableNeighbourProducesNoFinding(t *testing.T) {
	primary := service(t, true, nil)

	open := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serves everyone, with or without credentials.
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(open.Close)

	env := testEnv(t, primary.URL, []string{primary.URL, open.URL})

	fs, err := (&SharedTrustDomain{}).Detect(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("an anonymously readable endpoint was read as token acceptance: %+v", fs)
	}
}

func TestNeighboursExcludesThePrimaryHoweverItIsWritten(t *testing.T) {
	primary := service(t, true, nil)
	neighbour := service(t, true, nil)

	// The same primary host declared twice, in two spellings.
	env := testEnv(t, primary.URL, []string{primary.URL, primary.URL + "/", neighbour.URL})

	got, err := (&SharedTrustDomain{}).neighbours(env)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("neighbours = %v, want only the one other host", got)
	}
	primaryOrigin, _ := originOf(primary.URL)
	gotOrigin, _ := originOf(got[0])
	if gotOrigin == primaryOrigin {
		t.Error("the primary target was returned as its own neighbour")
	}
}

func TestOriginOf(t *testing.T) {
	tests := []struct{ in, want string }{
		{"http://localhost:3000", "http://localhost:3000"},
		{"http://localhost:3000/", "http://localhost:3000"},
		{"http://LOCALHOST:3000/api", "http://localhost:3000"},
		{"http://localhost", "http://localhost:80"},
		{"https://example.invalid", "https://example.invalid:443"},
	}
	for _, tc := range tests {
		got, err := originOf(tc.in)
		if err != nil {
			t.Errorf("originOf(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("originOf(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	if _, err := originOf("not a url at all"); err == nil {
		t.Error("originOf accepted something with no host")
	}
}

// A replay must respect scope exactly as a scan does.
func TestReproduceRefusesAFindingWithAWidenedScope(t *testing.T) {
	primary := service(t, true, nil)
	env := testEnv(t, primary.URL, []string{primary.URL})

	f := finding.Finding{
		BlastRadius: &finding.BlastRadius{
			ReachableFrom: "service-A",
			Reached:       []string{"the internet"},
			Scope:         "everything",
		},
	}

	_, err := (&SharedTrustDomain{}).Reproduce(context.Background(), env, f)
	if err == nil {
		t.Fatal("expected a refusal for a finding claiming a wider scope")
	}
	if !strings.Contains(err.Error(), "refusing to replay") {
		t.Errorf("error = %v", err)
	}
}

func TestReproduceReflectsTheSeparation(t *testing.T) {
	primary := service(t, true, nil)
	neighbour := service(t, true, nil)

	env := testEnv(t, primary.URL, []string{primary.URL, neighbour.URL})

	fs, err := (&SharedTrustDomain{}).Detect(context.Background(), env)
	if err != nil || len(fs) != 1 {
		t.Fatalf("setup: %d findings (%v)", len(fs), err)
	}

	res, err := (&SharedTrustDomain{}).Reproduce(context.Background(), env, fs[0])
	if err != nil {
		t.Fatal(err)
	}
	if !res.Reproduced {
		t.Errorf("should still reproduce against the same pair: %s", res.Detail)
	}

	// Now the neighbour rejects foreign tokens.
	separated := service(t, false, nil)
	sepEnv := testEnv(t, primary.URL, []string{primary.URL, separated.URL})

	// Re-point the finding's evidence key at the new neighbour so the replay
	// can find it.
	sepOrigin, _ := originOf(separated.URL)
	primaryOrigin, _ := originOf(primary.URL)
	f := fs[0]
	f.Evidence.EvidenceKey = "trust-domain:" + primaryOrigin + "->" + sepOrigin

	res, err = (&SharedTrustDomain{}).Reproduce(context.Background(), sepEnv, f)
	if err != nil {
		t.Fatal(err)
	}
	if res.Reproduced {
		t.Errorf("reproduced against a component that rejects foreign tokens: %s", res.Detail)
	}
}

func TestRegisteredOnTheExposureLayer(t *testing.T) {
	c, ok := check.Default.Get("exposure.shared-trust-domain")
	if !ok {
		t.Fatal("the check is not registered")
	}
	if c.Meta().Layer != check.LayerExposure {
		t.Errorf("layer = %q, want exposure", c.Meta().Layer)
	}
}
