package check

import (
	"strings"
	"testing"

	"github.com/rohitanakiya/Vibe-Killer/internal/config"
	"github.com/rohitanakiya/Vibe-Killer/internal/surface"
)

// A surface that exists but carries no routes used to pass this gate, because
// the gate only looked for nil. Every check declaring NeedsSurface works by
// requesting an endpoint, so an empty route list meant each one ran against
// nothing, found nothing, and the scan exited 0 having exercised no endpoint
// at all -- a result indistinguishable from an application checked and found
// sound. These cases exist to keep that state reportable.
func TestCanRunRefusesASurfaceWithNoRoutes(t *testing.T) {
	cfg := config.Defaults()

	mapped := func(st surface.Stack, routes ...surface.Route) *surface.Surface {
		return &surface.Surface{Stack: st, Routes: routes}
	}

	tests := []struct {
		name    string
		surface *surface.Surface
		wantOK  bool
		wantIn  []string
	}{
		{
			name:    "surface was never mapped",
			surface: nil,
			wantOK:  false,
			wantIn:  []string{"not mapped"},
		},
		{
			// Naming the framework is the whole point: it tells the operator
			// the gap is in this tool rather than in their repository.
			name:    "framework recognized with no extractor behind it",
			surface: mapped(surface.Stack{Language: "python", Framework: "django"}),
			wantOK:  false,
			wantIn:  []string{"no routes", "django"},
		},
		{
			name:    "language known but framework unrecognized",
			surface: mapped(surface.Stack{Language: "python"}),
			wantOK:  false,
			wantIn:  []string{"no routes", "python", "no framework"},
		},
		{
			name:    "nothing recognized at all",
			surface: mapped(surface.Stack{}),
			wantOK:  false,
			wantIn:  []string{"no routes"},
		},
		{
			name:    "a single route is enough to proceed",
			surface: mapped(surface.Stack{Framework: "flask"}, surface.Route{Method: "GET", Path: "/orders/:id"}),
			wantOK:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := &Env{Config: &cfg, Surface: tc.surface}
			ok, reason := CanRun(Meta{RuleID: "x.endpoint", NeedsSurface: true}, env)

			if ok != tc.wantOK {
				t.Fatalf("CanRun ok = %v (reason %q), want %v", ok, reason, tc.wantOK)
			}
			if tc.wantOK {
				if reason != "" {
					t.Errorf("reason = %q, want it empty when the check may run", reason)
				}
				return
			}
			for _, want := range tc.wantIn {
				if !strings.Contains(reason, want) {
					t.Errorf("reason = %q, want it to mention %q", reason, want)
				}
			}
		})
	}
}

// The gate must stay narrow. A check that does not declare NeedsSurface has
// no business being blocked by an empty route list: the security-header and
// CORS checks request the target root and never look at routes, so gating
// them here would remove real coverage while claiming to report it.
func TestCanRunLeavesChecksThatDoNotNeedTheSurfaceAlone(t *testing.T) {
	cfg := config.Defaults()
	env := &Env{
		Config:  &cfg,
		Surface: &surface.Surface{Stack: surface.Stack{Framework: "django"}},
	}

	ok, reason := CanRun(Meta{RuleID: "x.static", Layer: LayerStatic}, env)
	if !ok {
		t.Fatalf("CanRun = false (%q), want a check with NeedsSurface unset to be unaffected", reason)
	}
}

// A static-only run leaves out eleven checks for three reasons. One line per
// check buried those three facts under repetition, so the reason is printed
// once and names the checks it covers. findings.json keeps the per-check form,
// where a consumer joins on the check id.
func TestGroupSkipLinesCollapsesASharedReason(t *testing.T) {
	shared := "this run was static-only, so the endpoint layer did not run"
	skips := []SkipReason{
		{RuleID: "traversal.path-escape", Layer: LayerEndpoint, Reason: shared},
		{RuleID: "authz.unprotected-endpoint", Layer: LayerEndpoint, Reason: shared},
		{RuleID: "idor.sequential-id-access", Layer: LayerEndpoint, Reason: shared},
		{RuleID: "exposure.shared-trust-domain", Layer: LayerExposure, Reason: "needs 1 seeded users with tokens, found 0"},
	}

	lines := GroupSkipLines(skips)
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want one per distinct reason:\n%s", len(lines), strings.Join(lines, "\n"))
	}

	joined := strings.Join(lines, "\n")
	if strings.Count(joined, shared) != 1 {
		t.Errorf("the shared reason appears %d times, want once:\n%s", strings.Count(joined, shared), joined)
	}
	// Collapsing must not lose which checks are covered.
	for _, id := range []string{"traversal.path-escape", "authz.unprotected-endpoint", "idor.sequential-id-access"} {
		if !strings.Contains(joined, id) {
			t.Errorf("%s is not named anywhere:\n%s", id, joined)
		}
	}
	// A lone skip keeps the familiar "id: reason" shape, which reads better
	// than a group of one.
	var lone string
	for _, l := range lines {
		if strings.HasPrefix(l, "exposure.shared-trust-domain: ") {
			lone = l
		}
	}
	if lone == "" {
		t.Errorf("a single skip should stay in id-first form:\n%s", joined)
	}

	// Grouped ids are ordered, so two runs of the same scan do not produce
	// gratuitously different reports.
	want := "authz.unprotected-endpoint, idor.sequential-id-access, traversal.path-escape"
	if !strings.Contains(joined, want) {
		t.Errorf("grouped ids are not sorted, want %q in:\n%s", want, joined)
	}

	if GroupSkipLines(nil) != nil {
		t.Error("an empty skip list should produce no lines")
	}
}
