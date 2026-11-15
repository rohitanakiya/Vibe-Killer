// Package runtimechecks holds the checks that read what the application
// actually did, rather than what it looks like it does or what it answered.
//
// These are the deepest findings Vibe Killer produces. An endpoint check can
// show that one user read another's record; a runtime check can show the
// query that did it, with no owner predicate in it, which is the root cause
// rather than the symptom. That is a materially better handoff: the fix is
// visible in the finding.
//
// The package is deliberately decoupled from the rest of the checks. It
// depends on the runtime observer interface and nothing else, so the
// stack-specific half — the agent the operator installs in their own
// application — can differ per language without any of this changing.
package runtimechecks

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/rohitanakiya/Vibe-Killer/internal/check"
	"github.com/rohitanakiya/Vibe-Killer/internal/config"
	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
	"github.com/rohitanakiya/Vibe-Killer/internal/httpx"
	"github.com/rohitanakiya/Vibe-Killer/internal/runtime"
	"github.com/rohitanakiya/Vibe-Killer/internal/surface"
)

func init() {
	check.Register(&QueryOwnerFilter{})
	check.Register(&AuthCheckFired{})
}

// probeURL builds an absolute URL for a path on the target.
//
// This is a local copy of a few lines rather than an import of the endpoint
// checks, so that the runtime layer stays independent of them: a stack whose
// runtime observer works differently should not have to pull in the HTTP
// probe machinery.
func probeURL(env *check.Env, path string) (string, error) {
	base := strings.TrimSuffix(env.Target, "/")
	if base == "" {
		return "", fmt.Errorf("no target is configured")
	}

	prefix := strings.TrimSuffix(strings.TrimSpace(env.Config.Dynamic.BasePath), "/")
	if prefix != "" && !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	full := base + prefix + path
	if _, err := url.Parse(full); err != nil {
		return "", fmt.Errorf("building a URL for %q: %w", path, err)
	}
	return full, nil
}

// fillParams substitutes a value into every path parameter.
func fillParams(path, value string) string {
	out := path
	for {
		start := strings.IndexByte(out, '{')
		if start < 0 {
			return out
		}
		end := strings.IndexByte(out[start:], '}')
		if end < 0 {
			return out
		}
		out = out[:start] + value + out[start+end+1:]
	}
}

// correlatedRequest builds a request carrying a seeded user's credentials and
// a correlation header, so the agent's observation can be tied to it.
func correlatedRequest(ruleID, method, target string, u config.SeededUser, correlationID, note string) (httpx.Request, error) {
	name, value, err := u.AuthHeader()
	if err != nil {
		return httpx.Request{}, err
	}
	return httpx.Request{
		RuleID: ruleID,
		Method: method,
		URL:    target,
		Headers: map[string]string{
			name:                      value,
			runtime.HeaderCorrelation: correlationID,
		},
		AuthLabel: u.ID,
		Note:      note,
	}, nil
}

// evidenceRequest converts a sent request into the contract's evidence form,
// with credentials redacted.
func evidenceRequest(req httpx.Request) *finding.Request {
	path := req.URL
	if u, err := url.Parse(req.URL); err == nil {
		path = u.RequestURI()
	}
	label := req.AuthLabel
	if label != "" && label != "none" {
		label += "-token"
	}
	return &finding.Request{
		Method:  req.Method,
		Path:    path,
		Headers: finding.RedactHeaders(req.Headers),
		Auth:    label,
	}
}

// routesForResource returns mapped GET routes that plausibly serve a resource.
func routesForResource(s *surface.Surface, resource string) []surface.Route {
	if s == nil {
		return nil
	}
	resource = strings.ToLower(strings.TrimSpace(resource))
	singular := strings.TrimSuffix(resource, "s")

	var out []surface.Route
	for _, r := range s.Routes {
		if !strings.EqualFold(r.Method, http.MethodGet) || len(r.PathParams) != 1 {
			continue
		}
		lower := strings.ToLower(r.Path)
		for _, seg := range strings.Split(lower, "/") {
			if seg == resource || seg == singular || seg == singular+"s" {
				out = append(out, r)
				break
			}
		}
	}
	return out
}

// observer returns the run's runtime observer, or nil.
func observer(env *check.Env) runtime.Observer { return env.Runtime }

// --- query owner filter ----------------------------------------------------

// QueryOwnerFilter reads the statement the application issued while serving a
// legitimate request and reports whether it constrained on ownership.
//
// It makes one request: the canary's own owner reading their own record. That
// is an entirely ordinary read, allowed by any correct authorization model,
// and it is all this check needs — because what it inspects is not the
// response but the SQL. If the statement that fetched the record was keyed
// only on the id, then the handler would have returned the same row to anyone
// who asked, and the missing predicate is the reason.
//
// This finds the cause of an access-control failure without having to cross a
// boundary at all.
type QueryOwnerFilter struct{}

// Meta describes the check.
func (c *QueryOwnerFilter) Meta() check.Meta {
	return check.Meta{
		RuleID:   "runtime.query-missing-owner-filter",
		Title:    "Record reads whose SQL has no ownership predicate",
		Layer:    check.LayerRuntime,
		Category: finding.CategoryBrokenAccessControl,

		NeedsTarget:      true,
		NeedsSurface:     true,
		NeedsSeededUsers: 1,
		NeedsCanary:      true,
	}
}

// Detect asks each canary's owner to read their own record and inspects the
// resulting statement.
func (c *QueryOwnerFilter) Detect(ctx context.Context, env *check.Env) ([]finding.Finding, error) {
	obs := observer(env)
	if obs == nil {
		return nil, fmt.Errorf("no runtime observer is attached")
	}

	ruleID := c.Meta().RuleID
	var out []finding.Finding
	reported := map[string]bool{}

	for _, canary := range env.Config.CanaryRecords {
		owner, ok := env.Config.User(canary.Owner)
		if !ok {
			continue
		}

		for _, route := range routesForResource(env.Surface, canary.Resource) {
			target, err := probeURL(env, fillParams(route.Path, canary.ID))
			if err != nil {
				continue
			}

			correlation := "vk-" + canary.Resource + "-" + canary.ID + "-owner"
			req, err := correlatedRequest(ruleID, http.MethodGet, target, owner, correlation,
				"the canary's own owner reading their own record, to observe the query it produces")
			if err != nil {
				continue
			}

			resp, err := env.HTTP.Do(ctx, req)
			if err != nil {
				continue
			}
			if resp.Status != http.StatusOK {
				env.Run.Log("check.note", map[string]any{
					"rule_id": ruleID, "route": route.Endpoint(),
					"note": fmt.Sprintf("the owner got %d for its own canary, so no query to inspect",
						resp.Status),
				})
				continue
			}

			observation, got := obs.ForCorrelation(correlation)
			if !got {
				env.Run.Log("check.note", map[string]any{
					"rule_id": ruleID, "route": route.Endpoint(),
					"note": "the request succeeded but the agent reported no observation for it; " +
						"check that the agent is installed and VIBEKILLER_SINK is set",
				})
				continue
			}

			f := c.evaluate(env, route, canary, owner, req, observation)
			if f == nil || reported[f.FindingID] {
				continue
			}
			reported[f.FindingID] = true
			out = append(out, *f)
		}
	}

	return out, nil
}

// evaluate inspects the observed statements for a missing owner predicate.
func (c *QueryOwnerFilter) evaluate(
	env *check.Env,
	route surface.Route,
	canary config.CanaryRecord,
	owner config.SeededUser,
	req httpx.Request,
	obs runtime.Observation,
) *finding.Finding {
	if len(obs.Queries) == 0 {
		env.Run.Log("check.note", map[string]any{
			"rule_id": c.Meta().RuleID, "route": route.Endpoint(),
			"note": "the agent reported no queries for this request, so there is nothing to inspect " +
				"(the handler may not use a SQL database, or the driver is not wrapped)",
		})
		return nil
	}

	// Find the statement that read the record.
	var offender *runtime.Query
	for i := range obs.Queries {
		q := obs.Queries[i]
		if !q.IsSingleRecordRead() {
			continue
		}
		if q.HasOwnerPredicate() {
			// This read is correctly scoped. Keep looking: a handler may
			// issue several.
			continue
		}
		offender = &obs.Queries[i]
		break
	}
	if offender == nil {
		return nil
	}

	table := offender.TableOf()
	loc := finding.Location{
		Type:     finding.LocationEndpoint,
		Endpoint: route.Endpoint(),
		File:     route.File,
		Line:     route.Line,
		Symbol:   firstNonEmpty(obs.Handler, route.Handler),
		RepoRev:  env.RepoRev,
	}

	f := finding.Finding{
		RuleID: c.Meta().RuleID,
		Title: fmt.Sprintf("Record read in %s has no ownership predicate in its SQL",
			route.Endpoint()),
		Category:   finding.CategoryBrokenAccessControl,
		CWE:        "CWE-639",
		Severity:   finding.SeverityHigh,
		Confidence: finding.ConfidenceConfirmed,
		Source:     finding.SourceRuntime,
		Location:   loc,
		Evidence: finding.Evidence{
			Summary: fmt.Sprintf(
				"Seeded user %s read their own canary record, which is an ordinary and entirely "+
					"permitted request. The runtime agent reported the statement the application issued "+
					"to serve it, and that statement selects a single row from %s keyed on an identifier "+
					"with no ownership column constrained anywhere in it. The row is therefore returned "+
					"on the strength of the id alone, so the same statement would have returned it to "+
					"any caller. No boundary was crossed to establish this: the query itself shows there "+
					"is none.",
				owner.ID, orUnknown(table)),
			Request: evidenceRequest(req),
			Observed: fmt.Sprintf("the statement bound %d parameter(s) and constrained no ownership column: %s",
				offender.ParamCount, offender.SQL),
			Expected: fmt.Sprintf("the statement to constrain an ownership column as well, for example "+
				"... WHERE id = ? AND user_id = ?, so that a row belonging to another principal is "+
				"never read from %s", orUnknown(table)),
			Snippet: offender.SQL,
			// Keyed on the route and the table, so the same weakness keeps its
			// identity between runs.
			EvidenceKey: "runtime-query:" + route.Endpoint() + ":" + strings.ToLower(table),
		},
		Remediation: finding.Remediation{
			Guidance: fmt.Sprintf(
				"Add the principal to this query's WHERE clause rather than checking ownership after the "+
					"row is loaded, so a row belonging to someone else is never read. Scoping at the data "+
					"boundary also survives a later refactor of the handler, which a check placed after "+
					"the fetch does not. Return 404 rather than 403 when it misses, so %s does not confirm "+
					"that another principal's record exists.",
				route.Endpoint()),
			RootCauseHint: "Authorization is absent from the data-access layer. The statement is keyed " +
				"only on the client-supplied identifier.",
			References:     []string{"https://owasp.org/Top10/A01_2021-Broken_Access_Control/"},
			FixableByGiver: true,
		},
		Status: finding.StatusOpen,
	}
	f.AssignID()

	f.Reproduction = &finding.Reproduction{
		Kind:    finding.ReproScript,
		Command: "vibekiller scan --with-runtime --only " + c.Meta().RuleID,
		Steps: []string{
			"Install the runtime agent and restart the application with VIBEKILLER_SINK set.",
			fmt.Sprintf("As seeded user %s, GET %s. This is a legitimate read of their own record.",
				owner.ID, fillParams(route.Path, canary.ID)),
			"The agent reports the statement that served it.",
			"That statement constrains the id and no ownership column.",
		},
	}

	return &f
}

// --- auth check fired ------------------------------------------------------

// AuthCheckFired compares the authorization the source declares against the
// authorization that actually ran.
//
// This is the gap that static analysis cannot see and a response cannot
// reveal. A route can carry an authentication middleware in the source and
// still be served without it: the middleware may be registered after the
// route, mounted on a different router, short-circuited by an earlier
// handler, or skipped by a framework-specific ordering rule. The response
// looks identical either way, because a request with valid credentials
// succeeds whether or not anything checked them.
//
// The agent reports which checks ran. An empty list for a route whose source
// declares one is a finding, and it is a finding that nothing else in the tool
// could produce.
type AuthCheckFired struct{}

// Meta describes the check.
func (c *AuthCheckFired) Meta() check.Meta {
	return check.Meta{
		RuleID:   "runtime.auth-check-not-fired",
		Title:    "Routes whose declared authorization never runs",
		Layer:    check.LayerRuntime,
		Category: finding.CategoryBrokenAccessControl,

		NeedsTarget:      true,
		NeedsSurface:     true,
		NeedsSeededUsers: 1,
	}
}

// maxAuthProbes bounds the request count.
const maxAuthProbes = 25

// Detect requests each route that declares authorization, with valid
// credentials, and checks whether anything actually ran.
func (c *AuthCheckFired) Detect(ctx context.Context, env *check.Env) ([]finding.Finding, error) {
	obs := observer(env)
	if obs == nil {
		return nil, fmt.Errorf("no runtime observer is attached")
	}

	ruleID := c.Meta().RuleID

	var user config.SeededUser
	found := false
	for _, u := range env.Config.SeededUsers {
		if _, err := u.Token(); err == nil {
			user, found = u, true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("no seeded user has a usable token")
	}

	var out []finding.Finding
	probes := 0

	for _, route := range env.Surface.Routes {
		if probes >= maxAuthProbes {
			env.Run.Log("check.note", map[string]any{
				"rule_id": ruleID,
				"note":    fmt.Sprintf("stopped after %d probes to keep the request count bounded", maxAuthProbes),
			})
			break
		}
		// Read-only, and only routes the source claims are protected: a route
		// that declares nothing has nothing to contradict.
		if !strings.EqualFold(route.Method, http.MethodGet) || route.Mutating {
			continue
		}
		if route.DeclaredAuth == "" {
			continue
		}

		path := route.Path
		if len(route.PathParams) > 0 {
			path = fillParams(route.Path, c.probeID(env, route))
		}
		target, err := probeURL(env, path)
		if err != nil {
			continue
		}

		correlation := "vk-auth-" + strings.ReplaceAll(route.Endpoint(), " ", "-")
		req, err := correlatedRequest(ruleID, http.MethodGet, target, user, correlation,
			"a valid request, to observe whether the declared authorization runs")
		if err != nil {
			continue
		}

		if _, err := env.HTTP.Do(ctx, req); err != nil {
			continue
		}
		probes++

		observation, got := obs.ForCorrelation(correlation)
		if !got {
			continue
		}
		if len(observation.AuthChecks) > 0 {
			// Something ran. That is the correct outcome.
			continue
		}

		out = append(out, c.finding(env, route, user, req, observation))
	}

	return out, nil
}

// probeID returns a value for a path parameter: a seeded canary id where one
// fits the route, so the request is a real read rather than a miss.
func (c *AuthCheckFired) probeID(env *check.Env, route surface.Route) string {
	lower := strings.ToLower(route.Path)
	for _, canary := range env.Config.CanaryRecords {
		res := strings.ToLower(canary.Resource)
		if strings.Contains(lower, res) || strings.Contains(lower, strings.TrimSuffix(res, "s")) {
			return canary.ID
		}
	}
	return "vk-probe"
}

func (c *AuthCheckFired) finding(
	env *check.Env, route surface.Route, user config.SeededUser,
	req httpx.Request, obs runtime.Observation,
) finding.Finding {
	f := finding.Finding{
		RuleID: c.Meta().RuleID,
		Title: fmt.Sprintf("Declared authorization never runs for %s",
			route.Endpoint()),
		Category:   finding.CategoryBrokenAccessControl,
		CWE:        "CWE-862",
		Severity:   finding.SeverityHigh,
		Confidence: finding.ConfidenceConfirmed,
		Source:     finding.SourceRuntime,
		Location: finding.Location{
			Type:     finding.LocationEndpoint,
			Endpoint: route.Endpoint(),
			File:     route.File,
			Line:     route.Line,
			Symbol:   firstNonEmpty(obs.Handler, route.Handler),
			RepoRev:  env.RepoRev,
		},
		Evidence: finding.Evidence{
			Summary: fmt.Sprintf(
				"The source declares %q on this route, but the runtime agent reported that no "+
					"authorization check ran while the request was served. The request succeeded, which "+
					"is why this is invisible from outside: a call with valid credentials returns the same "+
					"response whether or not anything verified them. The middleware is registered and not "+
					"executing — commonly because it is mounted after the route, attached to a different "+
					"router, or bypassed by the framework's ordering.",
				route.DeclaredAuth),
			Request:  evidenceRequest(req),
			Observed: fmt.Sprintf("the handler returned %d and the agent reported zero authorization checks", obs.Status),
			Expected: fmt.Sprintf("the agent to report %q having run", route.DeclaredAuth),
			// Keyed on the route and what the source claimed, so the finding
			// is stable while the claim stands.
			EvidenceKey: "runtime-auth:" + route.Endpoint() + ":" + route.DeclaredAuth,
		},
		Remediation: finding.Remediation{
			Guidance: "Check the order in which the middleware and this route are registered, and prefer " +
				"mounting authorization on the router rather than per route, so that registration order " +
				"cannot silently remove it. Then add a test that calls this endpoint with no credentials " +
				"and asserts a 401, since that is the assertion that would have caught this.",
			RootCauseHint: "The authorization middleware is declared but not in the executed chain for " +
				"this route.",
			FixableByGiver: true,
		},
		Status: finding.StatusOpen,
	}
	f.AssignID()

	f.Reproduction = &finding.Reproduction{
		Kind:    finding.ReproScript,
		Command: "vibekiller scan --with-runtime --only " + c.Meta().RuleID,
		Steps: []string{
			"Install the runtime agent and restart the application with VIBEKILLER_SINK set.",
			fmt.Sprintf("As seeded user %s, GET %s with valid credentials.", user.ID, route.Path),
			"The request succeeds and the agent reports no authorization check having run.",
		},
	}

	return f
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func orUnknown(s string) string {
	if strings.TrimSpace(s) == "" {
		return "the table"
	}
	return s
}
