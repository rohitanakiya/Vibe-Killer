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
