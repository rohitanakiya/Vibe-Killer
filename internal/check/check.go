// Package check defines what a Vibe Killer check is and holds the registry
// the orchestrator draws from.
//
// A check is a self-contained unit: it declares what it needs, detects, and
// where it is dynamic, knows how to reproduce itself. It never decides whether
// it is allowed to run. That decision belongs to CanRun below, so that the
// safety gates are enforced once, centrally, rather than being re-implemented
// correctly in every check and incorrectly in one.
package check

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/rohitanakiya/Vibe-Killer/internal/config"
	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
	"github.com/rohitanakiya/Vibe-Killer/internal/httpx"
	"github.com/rohitanakiya/Vibe-Killer/internal/run"
	"github.com/rohitanakiya/Vibe-Killer/internal/runtime"
	"github.com/rohitanakiya/Vibe-Killer/internal/scope"
	"github.com/rohitanakiya/Vibe-Killer/internal/surface"
)

// Layer is which engine a check belongs to.
type Layer string

const (
	LayerStatic   Layer = "static"
	LayerEndpoint Layer = "endpoint"
	LayerRuntime  Layer = "runtime"
	LayerDeps     Layer = "deps"
	LayerSecrets  Layer = "secrets"
	LayerExposure Layer = "exposure"
)

// Meta is a check's self-description, including its prerequisites.
type Meta struct {
	// RuleID is the contract rule_id this check emits.
	RuleID string

	// Title is a short human label for progress output.
	Title string

	Layer    Layer
	Category finding.Category

	// NeedsTarget means the check talks to a running instance.
	NeedsTarget bool

	// NeedsSeededUsers means the check needs at least two seeded identities
	// to compare across a boundary.
	NeedsSeededUsers int

	// NeedsCanary means the check needs a seeded canary record to read, so it
	// never has to touch a real one.
	NeedsCanary bool

	// Mutating means the check changes state on the target. Such a check runs
	// only when the operator has opened both gates in config.
	Mutating bool

	// NeedsSurface means the check needs the route model.
	NeedsSurface bool
}

// Env is everything a check is given. A check reads from Env and never
// constructs its own transport or reads config files of its own.
type Env struct {
	Config *config.Config
	Guard  *scope.Guard
	Run    *run.Run

	// HTTP is nil for a static-only run.
	HTTP *httpx.Client

	// Target is the base URL of the running instance, or "" when there is
	// none.
	Target string

	// Surface is the model of the app, or nil if mapping did not run.
	Surface *surface.Surface

	RepoRoot string
	RepoRev  string

	// RulesDir is where the embedded Semgrep pack was written for this run.
	RulesDir string

	// HasGit reports whether the repo is a git checkout, which decides
	// whether secret scanning can look at history.
	HasGit bool

	// Runtime is the observe-only runtime observer, or nil when the run did
	// not enable it. It is an interface so the core never knows which
	// stack-specific agent is reporting.
	Runtime runtime.Observer
}

// Check is one detection unit.
type Check interface {
	Meta() Meta
	Detect(ctx context.Context, env *Env) ([]finding.Finding, error)
}

// Reproducer is implemented by checks that can re-verify a single finding on
// demand, which is what backs `vibekiller reproduce`.
type Reproducer interface {
	Check

	// Reproduce re-runs the proof for one finding and reports whether it still
	// holds.
	Reproduce(ctx context.Context, env *Env, f finding.Finding) (Result, error)
}

// Result is the outcome of a reproduction attempt.
type Result struct {
	// Reproduced is true when the issue was observed again.
	Reproduced bool

	// Evidence is the fresh observation.
	Evidence finding.Evidence

	// Detail is a human-readable account of what happened.
	Detail string
}

// SkipReason explains why a check did not run. A skip is reported rather than
// silently dropped: a scan that quietly ran half its checks is worse than one
// that says what it could not do.
type SkipReason struct {
	RuleID string
	Reason string

	// Layer is the engine the skipped check belongs to.
	//
	// It is carried because rule_id alone cannot connect a skip to the
	// findings it suppressed. The scanner-backed checks are the reason:
	// engine.osv-scanner produces findings whose rule_id is
	// deps.known-vulnerability, so a consumer joining on rule_id would see
	// those findings vanish and the skip of engine.osv-scanner as unrelated
	// facts. The layer is what ties them together.
	Layer Layer
}

func (s SkipReason) String() string { return s.RuleID + ": " + s.Reason }

// GroupSkipLines renders a skip list for a human, collapsing the checks that
// share a reason.
//
// One line per check is right in findings.json, where a consumer joins on the
// check id. It is wrong in a report: a static-only run leaves out eleven
// checks for three reasons, and printing the same sentence eleven times buries
// the three facts someone actually needs. The reason is the information here,
// so it appears once and names the checks it covers.
func GroupSkipLines(skips []SkipReason) []string {
	if len(skips) == 0 {
		return nil
	}

	ids := map[string][]string{}
	var order []string
	for _, s := range skips {
		if _, seen := ids[s.Reason]; !seen {
			order = append(order, s.Reason)
		}
		ids[s.Reason] = append(ids[s.Reason], s.RuleID)
	}

	out := make([]string, 0, len(order))
	for _, reason := range order {
		group := ids[reason]
		sort.Strings(group)
		if len(group) == 1 {
			out = append(out, group[0]+": "+reason)
			continue
		}
		out = append(out, fmt.Sprintf("%s [%d checks: %s]", reason, len(group), strings.Join(group, ", ")))
	}
	sort.Strings(out)
	return out
}

// CanRun decides whether a check may execute in this environment, and says why
// not when it may not.
//
// This is the single enforcement point for the dynamic gates. In particular, a
// mutating check requires three independent things to be true: the operator
// turned off the non-destructive default, separately asserted the environment
// is disposable, and acknowledged target ownership. Any one of them missing
// means the check does not run.
func CanRun(m Meta, env *Env) (bool, string) {
	if m.NeedsTarget {
		if env.Target == "" {
			return false, "no running instance was given (pass --target)"
		}
		if env.HTTP == nil {
			return false, "this run has no HTTP client (static-only mode)"
		}
		if env.Guard == nil {
			return false, "no scope guard was built, so no request can be authorized"
		}
		if err := env.Guard.AuthorizeTarget(env.Target); err != nil {
			return false, err.Error()
		}
	}

	if m.NeedsSurface {
		if env.Surface == nil {
			return false, "the application surface was not mapped"
		}

		// A mapped surface carrying no routes is the most misleading state
		// available to these checks, and a nil check does not catch it. Every
		// check that declares NeedsSurface works by requesting an endpoint, so
		// against an empty route list each one runs, finds nothing, and reports
		// nothing -- and the scan exits 0 having exercised no endpoint at all.
		// In the report and in the exit code that is indistinguishable from an
		// application that was checked and found sound, which is the one
		// outcome this tool must never produce.
		//
		// The state is real rather than hypothetical: an adapter can recognize
		// a framework by name and still have no extractor for its routing,
		// and the report then names the stack confidently while the endpoint
		// layer silently covers nothing. Saying so is what the skip list is
		// for.
		//
		// Django and Next.js were both in that state, and they are why this
		// gate exists; their routes are read now. What remains is a stack
		// whose routing no extractor recognizes, or a project laid out in a
		// way one does not expect -- a Next.js app whose routes are all
		// behind a rewrite, say -- which is exactly the case this is for.
		if len(env.Surface.Routes) == 0 {
			return false, noRoutesReason(env.Surface.Stack)
		}
	}

	// A runtime check needs the agent to be reporting, not merely enabled.
	// Letting one run against a sink nothing is posting to would produce a
	// clean result that means only that the agent was never installed, which
	// is the most misleading outcome available.
	if m.Layer == LayerRuntime {
		if env.Runtime == nil {
			return false, "runtime observation was not enabled for this run (pass --with-runtime)"
		}
		if !env.Runtime.Attached() {
			return false, "the runtime agent is not reporting: no observations have arrived. " +
				"Install the agent in your application and restart it with VIBEKILLER_SINK set"
		}
	}

	if n := m.NeedsSeededUsers; n > 0 {
		available := 0
		var missing []string
		for _, u := range env.Config.SeededUsers {
			if _, err := u.Token(); err != nil {
				missing = append(missing, fmt.Sprintf("%s (%s is not set)", u.ID, u.TokenEnv))
				continue
			}
			available++
		}
		if available < n {
			msg := fmt.Sprintf("needs %d seeded users with tokens, found %d", n, available)
			if len(missing) > 0 {
				msg += "; missing: " + strings.Join(missing, ", ")
			}
			return false, msg
		}
	}

	if m.NeedsCanary && len(env.Config.CanaryRecords) == 0 {
		return false, "needs a seeded canary record to read, and config declares none " +
			"(a canary is what lets this be proven without touching real data)"
	}

	if m.Mutating {
		if !env.Config.MutatingChecksAllowed() {
			return false, "this check changes state, so it runs only when dynamic.non_destructive " +
				"is false and dynamic.disposable_env is true"
		}
		if env.Guard == nil || !env.Guard.Acknowledged() {
			return false, "this check changes state and requires --i-own-this-target"
		}
	}

	return true, ""
}

// noRoutesReason explains an empty route list in terms of what was actually
// detected, because the operator's next move differs by case: a stack nothing
// recognized is a configuration or layout problem at their end, while a stack
// that was recognized and still yielded no routes is a gap in this tool.
func noRoutesReason(st surface.Stack) string {
	switch {
	case st.Framework != "":
		return fmt.Sprintf("no routes were extracted from the repository even though %s "+
			"was detected, so this check has no endpoint to exercise", st.Framework)
	case st.Language != "":
		return fmt.Sprintf("no routes were extracted from the repository and no framework "+
			"was recognized in the %s code, so this check has no endpoint to exercise", st.Language)
	default:
		return "no routes were extracted from the repository, so this check has no endpoint to exercise"
	}
}

// Registry holds the available checks, keyed by rule id.
//
// The shape is modelled on Nuclei's template registry: checks register
// themselves at init time, and the orchestrator selects by layer or id without
// knowing what exists.
type Registry struct {
	mu     sync.RWMutex
	checks map[string]Check
}

// NewRegistry builds an empty registry.
func NewRegistry() *Registry {
	return &Registry{checks: map[string]Check{}}
}

// Default is the registry checks register into at init time.
var Default = NewRegistry()

// Register adds a check. It panics on a duplicate rule id, because that is a
// programming error that would otherwise silently drop a check.
func (r *Registry) Register(c Check) {
	r.mu.Lock()
	defer r.mu.Unlock()

	id := c.Meta().RuleID
	if id == "" {
		panic("check: a check registered with an empty rule id")
	}
	if _, dup := r.checks[id]; dup {
		panic("check: duplicate rule id " + id)
	}
	r.checks[id] = c
}

// Register adds a check to the default registry.
func Register(c Check) { Default.Register(c) }

// All returns every registered check, ordered by rule id so that runs are
// deterministic.
func (r *Registry) All() []Check {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]Check, 0, len(r.checks))
	for _, c := range r.checks {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Meta().RuleID < out[j].Meta().RuleID
	})
	return out
}

// ByLayer returns the checks in the given layers.
func (r *Registry) ByLayer(layers ...Layer) []Check {
	want := map[Layer]bool{}
	for _, l := range layers {
		want[l] = true
	}

	var out []Check
	for _, c := range r.All() {
		if want[c.Meta().Layer] {
			out = append(out, c)
		}
	}
	return out
}

// Get returns one check by rule id.
func (r *Registry) Get(ruleID string) (Check, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.checks[ruleID]
	return c, ok
}

// Len reports how many checks are registered.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.checks)
}
