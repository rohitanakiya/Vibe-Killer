package endpointchecks

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/rohitanakiya/Vibe-Killer/internal/check"
	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
	"github.com/rohitanakiya/Vibe-Killer/internal/httpx"
	"github.com/rohitanakiya/Vibe-Killer/internal/surface"
)

func init() { check.Register(&SQLDifferential{}) }

// SQLDifferential confirms that a request value reaches a SQL parser as
// syntax rather than as data.
//
// It does this with the smallest probe that can establish it: a benign string
// with one unbalanced quote in it. If the value is being concatenated into a
// statement, the statement no longer parses and the database says so; if it is
// being passed as a bound parameter, the quote is just a character in a string
// and nothing happens.
//
// That is the whole test. The probe carries no statement of its own, reads
// nothing, and changes nothing — and assertInertProbe refuses to send it if it
// ever does. What the finding reports is that the boundary between statement
// and data is missing, which is what has to be fixed; whether a destructive
// statement is reachable through that gap follows from it, and does not need
// to be demonstrated.
type SQLDifferential struct{}

// Meta describes the check.
func (c *SQLDifferential) Meta() check.Meta {
	return check.Meta{
		RuleID:   "injection.sql-differential",
		Title:    "Request values reaching a SQL parser (detection only)",
		Layer:    check.LayerEndpoint,
		Category: finding.CategoryInjection,

		NeedsTarget:  true,
		NeedsSurface: true,
	}
}

// maxInjectionProbes bounds the request count on a large application.
// maxInjectionProbes bounds the requests this check sends.
//
// It is spent breadth-first across routes, so the number that matters is how
// many routes get their first parameter name tried rather than how many names
// one route gets. Sixty is two requests each for thirty routes, which covers
// an ordinary application's read surface; a larger one truncates depth, and
// the run log says how many routes still had names untried.
const maxInjectionProbes = 60

// benignValue is the baseline: a plain identifier-shaped string that no
// handler should choke on.
const benignValue = "vk-probe"

// quoteProbe is the detection probe: the baseline with one unbalanced quote.
const quoteProbe = "vk-probe'"

// Detect sends a baseline and a probe to each candidate route.
func (c *SQLDifferential) Detect(ctx context.Context, env *check.Env) ([]finding.Finding, error) {
	ruleID := c.Meta().RuleID

	// Refuse before anything is sent, not after.
	if err := assertInertProbes(ruleID, benignValue, quoteProbe); err != nil {
		return nil, err
	}

	var out []finding.Finding
	probes := 0
	seen := map[string]bool{}

	// Collect the work first, then spend the budget breadth-first across
	// routes rather than depth-first within one.
	//
	// Depth-first meant the first route consumed the budget. A route with no
	// path parameter gets one slot per name in commonQueryParams, which is ten
	// slots and twenty requests -- the whole allowance -- so whether a later
	// route was probed at all came down to the order the adapter happened to
	// enumerate routes in. Adding one unrelated endpoint to a fixture was
	// enough to stop this check reaching the route that actually had the
	// injection, and nothing in the output said a route had gone unprobed.
	//
	// Breadth-first makes a truncated budget cost parameter names rather than
	// whole routes: every route gets its first slot before any route gets its
	// second.
	type work struct {
		route surface.Route
		slots []slot
	}
	var routes []work
	deepest := 0

	for _, route := range env.Surface.Routes {
		// Read-only: a GET cannot change state whatever the handler does with
		// the value.
		if !strings.EqualFold(route.Method, http.MethodGet) || route.Mutating {
			continue
		}
		if seen[route.Path] {
			continue
		}
		seen[route.Path] = true

		slots := c.slotsFor(route)
		if len(slots) == 0 {
			continue
		}
		routes = append(routes, work{route: route, slots: slots})
		if len(slots) > deepest {
			deepest = len(slots)
		}
	}

	// A route stops being probed once it has produced a finding: the missing
	// boundary is a property of the handler, not of the parameter.
	done := make([]bool, len(routes))

	for depth := 0; depth < deepest; depth++ {
		for i := range routes {
			if done[i] || depth >= len(routes[i].slots) {
				continue
			}
			if probes >= maxInjectionProbes {
				unprobed := 0
				for j := range routes {
					if !done[j] && depth < len(routes[j].slots) {
						unprobed++
					}
				}
				env.Run.Log("check.note", map[string]any{
					"rule_id": ruleID,
					"note": fmt.Sprintf("stopped after %d probes to keep the request count bounded; "+
						"%d route(s) still had parameter names untried", maxInjectionProbes, unprobed),
				})
				return out, nil
			}

			f, sent, err := c.probeSlot(ctx, env, routes[i].route, routes[i].slots[depth])
			probes += sent
			if err != nil {
				env.Run.Log("check.note", map[string]any{
					"rule_id": ruleID, "route": routes[i].route.Endpoint(),
					"note": "probe could not complete: " + err.Error(),
				})
				continue
			}
			if f != nil {
				out = append(out, *f)
				done[i] = true
			}
		}
	}

	return out, nil
}

// slot is one place in a request where a value can be put.
type slot struct {
	// name is the parameter's name, for the evidence.
	name string

	// query is set when the value goes in a query parameter rather than in
	// the path.
	query bool
}

func (s slot) describe() string {
	if s.query {
		return "the " + s.name + " query parameter"
	}
	return "the " + s.name + " path parameter"
}

// urlFor renders the route with the value in this slot.
func (s slot) urlFor(routePath, value string) string {
	if !s.query {
		return fillParams(routePath, value)
	}
	sep := "?"
	if strings.Contains(routePath, "?") {
		sep = "&"
	}
	return routePath + sep + s.name + "=" + url.QueryEscape(value)
}

// commonQueryParams are the query parameter names that most often carry a
// value straight into a statement.
//
// Query parameters have to be guessed, because a route template says nothing
// about them: a framework route is "/api/search" whether the handler reads one
// parameter or ten. Guessing a short list is the only way to reach them at
// all, and leaving them out would miss the most common injection site there
// is — a search or filter endpoint.
var commonQueryParams = []string{"q", "search", "query", "filter", "id", "name", "sort", "order", "email", "slug"}

// slotsFor returns the places in this route worth probing.
func (c *SQLDifferential) slotsFor(route surface.Route) []slot {
	var out []slot

	// Path parameters are known from the route template, so they come first
	// and are the more reliable signal.
	for _, p := range route.PathParams {
		out = append(out, slot{name: p})
	}

	// A route with no path parameter is a collection or a search endpoint, and
	// those are exactly the ones that read a query parameter.
	if len(route.PathParams) == 0 {
		for _, p := range commonQueryParams {
			out = append(out, slot{name: p, query: true})
		}
	}

	return out
}

// probeSlot runs the baseline-then-probe pair for one parameter slot and
// reports how many requests it sent.
func (c *SQLDifferential) probeSlot(ctx context.Context, env *check.Env, route surface.Route, s slot) (*finding.Finding, int, error) {
	ruleID := c.Meta().RuleID
	sent := 0

	baselineURL, err := absURL(env, s.urlFor(route.Path, benignValue))
	if err != nil {
		return nil, sent, err
	}
	probeURL, err := absURL(env, s.urlFor(route.Path, quoteProbe))
	if err != nil {
		return nil, sent, err
	}

	// Step 1: the baseline. A handler that already returns a database error
	// for an ordinary string is broken in some other way, and a probe that
	// also errors would prove nothing about the quote.
	baselineReq := identifiedRequest(ruleID, http.MethodGet, baselineURL, env,
		"baseline: an ordinary string in the same parameter")
	baselineResp, err := send(ctx, env, baselineReq)
	sent++
	if err != nil {
		return nil, sent, err
	}
	if _, isSQLError := matchSQLError(baselineResp.Body); isSQLError {
		env.Run.Log("check.note", map[string]any{
			"rule_id": ruleID, "route": route.Endpoint(),
			"note": "baseline already returns a database error, so the quote probe would " +
				"prove nothing; no conclusion drawn",
		})
		return nil, sent, nil
	}

	// Step 2: the same request with one unbalanced quote.
	probeReq := identifiedRequest(ruleID, http.MethodGet, probeURL, env,
		"probe: the same string with one unbalanced quote")
	probeResp, err := send(ctx, env, probeReq)
	sent++
	if err != nil {
		return nil, sent, err
	}

	engine, isSQLError := matchSQLError(probeResp.Body)
	if !isSQLError {
		// Either the value is parameterized, or the handler returns a generic
		// error. Both mean this check has nothing to report; the static rules
		// cover the case where the code is wrong but the error is hidden.
		if matchNoSQLError(probeResp.Body) {
			env.Run.Log("check.note", map[string]any{
				"rule_id": ruleID, "route": route.Endpoint(),
				"note": "the response mentions a document-store operator error, which this " +
					"check does not interpret; see the static nosql rule",
			})
		}
		return nil, sent, nil
	}

	loc := locationFor(route, env.RepoRev)
	f := finding.Finding{
		RuleID: ruleID,
		Title: fmt.Sprintf("Request value reaches the SQL statement as syntax in %s",
			route.Endpoint()),
		Category:   finding.CategoryInjection,
		CWE:        "CWE-89",
		Severity:   finding.SeverityCritical,
		Confidence: finding.ConfidenceConfirmed,
		Source:     finding.SourceDAST,
		Location:   loc,
		Evidence: finding.Evidence{
			Summary: fmt.Sprintf(
				"The same request was sent twice, differing only in one unbalanced quote in %s. "+
					"The ordinary value returned %d with no database error; the value with the "+
					"quote returned %d and a %s parser error. The statement therefore no longer parses, "+
					"which means the value is being concatenated into it rather than bound as a parameter. "+
					"There is no boundary between the statement and the data in it.",
				s.describe(), baselineResp.Status, probeResp.Status, engine),
			Request:  evidenceRequest(probeReq),
			Observed: fmt.Sprintf("%d with a %s parser error", probeResp.Status, engine),
			Expected: fmt.Sprintf("the same %d the baseline returned: a quote is an ordinary character in a bound parameter", baselineResp.Status),
			Snippet:  firstLines(probeResp.Body, 4, 400),
			// Keyed on the route, so re-running against the same application
			// produces the same finding id.
			EvidenceKey: "sql-differential:" + route.Endpoint() + ":" + s.name,
		},
		Remediation: finding.Remediation{
			Guidance: "Pass the value as a bound parameter instead of building the statement as a string. " +
				"Parameterizing is what separates statement from data; escaping by hand does not, because " +
				"the escaping rules differ per driver, per encoding and per context.",
			RootCauseHint: "The query is assembled by concatenation or interpolation, so the value is " +
				"parsed as part of the statement.",
			References: []string{
				"https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html",
			},
			FixableByGiver: true,
		},
		Status: finding.StatusOpen,
	}
	f.AssignID()

	artifact := writeReproArtifact(env, f.FindingID,
		[]httpx.Request{baselineReq, probeReq},
		[]string{
			"The two requests differ only in one unbalanced quote.",
			"Both are inert: neither carries a statement, reads anything, or changes anything.",
			"A fixed application answers both the same way.",
		})

	f.Reproduction = &finding.Reproduction{
		Kind:    finding.ReproHTTP,
		Command: "vibekiller reproduce " + f.FindingID,
		Steps: []string{
			fmt.Sprintf("Send GET %s and note the status: %d, no database error.",
				s.urlFor(route.Path, benignValue), baselineResp.Status),
			fmt.Sprintf("Send GET %s, which is the same value with one quote added.",
				s.urlFor(route.Path, quoteProbe)),
			fmt.Sprintf("It returns %d with a %s parser error, so the value is part of the statement.",
				probeResp.Status, engine),
		},
		ArtifactPath: artifact,
	}

	return &f, sent, nil
}

// Reproduce re-runs the differential for one finding.
func (c *SQLDifferential) Reproduce(ctx context.Context, env *check.Env, f finding.Finding) (check.Result, error) {
	if f.Evidence.Request == nil || f.Evidence.Request.Path == "" {
		return check.Result{}, fmt.Errorf("this finding carries no recorded request to replay")
	}

	ruleID := c.Meta().RuleID
	if err := assertInertProbe(ruleID, quoteProbe); err != nil {
		return check.Result{}, err
	}

	probeURL, err := absURL(env, f.Evidence.Request.Path)
	if err != nil {
		return check.Result{}, err
	}

	req := identifiedRequest(ruleID, http.MethodGet, probeURL, env, "reproduction: the quote probe")
	resp, err := send(ctx, env, req)
	if err != nil {
		return check.Result{}, err
	}

	engine, isSQLError := matchSQLError(resp.Body)
	if !isSQLError {
		return check.Result{
			Reproduced: false,
			Detail: fmt.Sprintf("Not reproducible: the probe now returns %d with no database parser error. "+
				"The value appears to be bound rather than concatenated.", resp.Status),
			Evidence: finding.Evidence{
				Summary:  "The quote probe no longer produces a parser error.",
				Request:  evidenceRequest(req),
				Observed: fmt.Sprintf("%d, no parser error", resp.Status),
				Expected: "no parser error",
			},
		}, nil
	}

	return check.Result{
		Reproduced: true,
		Detail:     fmt.Sprintf("Still reproducible: the probe returns a %s parser error.", engine),
		Evidence: finding.Evidence{
			Summary:  fmt.Sprintf("The unbalanced quote still reaches a %s parser.", engine),
			Request:  evidenceRequest(req),
			Observed: fmt.Sprintf("%d with a %s parser error", resp.Status, engine),
			Expected: "the same response as an ordinary value",
		},
	}, nil
}
