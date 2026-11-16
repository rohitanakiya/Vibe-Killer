package engine

import (
	"strings"
	"testing"

	"github.com/rohitanakiya/Vibe-Killer/internal/check"
)

// layersOf collects the distinct layers a skip list covers.
func layersOf(skips []check.SkipReason) map[check.Layer]bool {
	out := map[check.Layer]bool{}
	for _, s := range skips {
		out[s.Layer] = true
	}
	return out
}

// selectChecks returns a subset and the rest never reach the orchestrator, so
// for a long time nothing recorded them anywhere. A --static-only run wrote a
// findings.json with an empty skip list, which made every endpoint finding
// from an earlier run look fixed -- and "full scan locally, narrower scan in
// CI" is the commonest way two runs differ, so this was the likeliest shape of
// that bug rather than an edge case.
func TestStaticOnlyRecordsTheLayersItDidNotRun(t *testing.T) {
	selected := selectChecks(ModeStaticOnly, nil)
	if len(selected) == 0 {
		t.Fatal("static-only selected no checks at all")
	}

	skips := deselectedSkips(ModeStaticOnly, nil, selected)
	if len(skips) == 0 {
		t.Fatal("static-only recorded nothing as skipped, so a consumer cannot tell those layers did not run")
	}

	got := layersOf(skips)
	for _, want := range []check.Layer{check.LayerEndpoint, check.LayerRuntime, check.LayerExposure} {
		if !got[want] {
			t.Errorf("layer %q was not recorded as skipped", want)
		}
	}
	// The layers it did run must not appear, or the report would claim it
	// skipped work it actually did.
	for _, ran := range []check.Layer{check.LayerStatic, check.LayerDeps, check.LayerSecrets} {
		if got[ran] {
			t.Errorf("layer %q ran but was recorded as skipped", ran)
		}
	}

	// Every reason has to name the flag, since the reason doubles as the
	// instruction for including the check next time.
	for _, s := range skips {
		if s.Reason == "" {
			t.Fatalf("%s was recorded with no reason", s.RuleID)
		}
		if !strings.Contains(s.Reason, "static-only") {
			t.Errorf("%s reason = %q, want it to name the mode", s.RuleID, s.Reason)
		}
	}
}

// The default mode leaves out the runtime layer, and that omission was equally
// invisible. Its reason should point at the flag that includes it.
func TestFullModeRecordsTheRuntimeLayerItLeavesOut(t *testing.T) {
	skips := deselectedSkips(ModeFull, nil, selectChecks(ModeFull, nil))

	if !layersOf(skips)[check.LayerRuntime] {
		t.Fatal("the runtime layer was left out without being recorded")
	}
	for _, s := range skips {
		if s.Layer == check.LayerRuntime && !strings.Contains(s.Reason, "--with-runtime") {
			t.Errorf("%s reason = %q, want it to name --with-runtime", s.RuleID, s.Reason)
		}
	}
}

// With runtime enabled everything is selected, so nothing should be reported
// as left out.
func TestWithRuntimeLeavesNothingOut(t *testing.T) {
	if skips := deselectedSkips(ModeWithRuntime, nil, selectChecks(ModeWithRuntime, nil)); len(skips) != 0 {
		t.Errorf("deselected = %v, want none when every layer is selected", skips)
	}
}

// An --only filter is a deliberate narrowing, and it still has to be visible
// in the output rather than looking like a clean full run.
func TestAnOnlyFilterRecordsWhatItExcluded(t *testing.T) {
	selected := selectChecks(ModeFull, []string{"engine.semgrep"})
	if len(selected) != 1 {
		t.Fatalf("selected %d checks, want just the one named", len(selected))
	}

	skips := deselectedSkips(ModeFull, []string{"engine.semgrep"}, selected)
	if len(skips) == 0 {
		t.Fatal("an --only run recorded nothing as excluded")
	}
	for _, s := range skips {
		if s.RuleID == "engine.semgrep" {
			t.Error("the selected check was also reported as excluded")
		}
		if !strings.Contains(s.Reason, "--only") {
			t.Errorf("%s reason = %q, want it to name --only", s.RuleID, s.Reason)
		}
	}
}

// mergeSkips feeds findings.json, the Markdown report, the terminal summary
// and Result.Skipped from one list, so the ordering has to be stable or those
// four disagree between runs.
func TestMergeSkipsIsOrderedAndComplete(t *testing.T) {
	gated := []check.SkipReason{{RuleID: "z.gated", Layer: check.LayerEndpoint, Reason: "gated"}}
	deselected := []check.SkipReason{
		{RuleID: "a.deselected", Layer: check.LayerRuntime, Reason: "deselected"},
		{RuleID: "m.deselected", Layer: check.LayerRuntime, Reason: "deselected"},
	}

	out := mergeSkips(gated, deselected)
	if len(out) != 3 {
		t.Fatalf("merged %d, want 3", len(out))
	}
	for i := 1; i < len(out); i++ {
		if out[i-1].RuleID > out[i].RuleID {
			t.Fatalf("not ordered by rule id: %v", out)
		}
	}
	if n := len(mergeSkips(nil, nil)); n != 0 {
		t.Errorf("merging nothing gave %d entries", n)
	}
}
