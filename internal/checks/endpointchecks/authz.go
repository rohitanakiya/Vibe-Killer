package endpointchecks

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/rohitanakiya/Vibe-Killer/internal/check"
	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
	"github.com/rohitanakiya/Vibe-Killer/internal/httpx"
)

func init() { check.Register(&Unprotected{}) }

// Unprotected tests whether endpoints serve data to a caller with no
// credentials at all.
//
// It reports two different things, with different confidence, because they are
// different claims. An anonymous request that returns a seeded canary record
// is proof: that record belongs to a specific user and nobody asked who was
// calling. An anonymous request that returns some other 200 is weaker, because
// the endpoint may be public by design, so it is reported as likely and says
// so.
type Unprotected struct{}

// Meta describes the check.
func (c *Unprotected) Meta() check.Meta {
	return check.Meta{
		RuleID:   "authz.unprotected-endpoint",
		Title:    "Endpoints reachable with no credentials",
		Layer:    check.LayerEndpoint,
		Category: finding.CategoryBrokenAccessControl,

		NeedsTarget:  true,
		NeedsSurface: true,
	}
}

// publicByDesign names the path segments that normally have to be reachable
// without credentials. Flagging these would bury the findings that matter: a
// sign-in endpoint that demanded authentication could never be used.
var publicByDesign = []string{
	"login", "signin", "sign-in", "signup", "sign-up", "register",
	"auth", "oauth", "callback", "logout", "forgot", "reset", "verify", "confirm",
	"health", "healthz", "livez", "readyz", "ping", "status", "metrics",
	"public", "static", "assets", "favicon", "robots", "sitemap",
	"docs", "openapi", "swagger", "redoc", "graphql",
	"webhook", "webhooks", "csrf", "version",
}

// isPublicByDesign reports whether any segment of a path names one of these.
//
// Matching per segment rather than on the whole path matters because these
// endpoints are usually mounted under a prefix: a prefix test would miss
// /api/auth/callback, and a substring test would wrongly exclude something
// like /api/public-orders/{id}.
func isPublicByDesign(path string) bool {
	lower := strings.ToLower(strings.TrimSpace(path))
	if lower == "" || lower == "/" {
		return true
	}

	for _, seg := range strings.Split(lower, "/") {
		if seg == "" || strings.HasPrefix(seg, "{") {
			continue
		}
		for _, p := range publicByDesign {
			// A prefix test on the segment, so that healthz matches health and
			// openapi.json matches openapi, without matching an unrelated
			// segment that merely contains the word.
			if seg == p || strings.HasPrefix(seg, p) {
				return true
			}
		}
	}
	return false
}

// Detect sends unauthenticated requests to mapped read routes.
func (c *Unprotected) Detect(ctx context.Context, env *check.Env) ([]finding.Finding, error) {
	var out []finding.Finding
	ruleID := c.Meta().RuleID

	// The strong case: a canary record served to an anonymous caller.
	for _, canary := range env.Config.CanaryRecords {
		for _, route := range routesForResource(env.Surface, canary.Resource, http.MethodGet) {
			concrete := fillParams(route.Path, canary.ID)
			target, err := absURL(env, concrete)
			if err != nil {
				continue
			}

			req := anonRequest(ruleID, http.MethodGet, target,
				fmt.Sprintf("probe: read %s's canary with no credentials", canary.Owner))
			resp, err := send(ctx, env, req)
			if err != nil {
				continue
			}
			if resp.Status != http.StatusOK {
				continue
			}

			disclosed := canary.Marker != "" && resp.BodyContains(canary.Marker)
			if !disclosed && canary.Marker == "" {
				disclosed = bodyLooksLikeRecord(resp.Body)
			}
			if !disclosed {
				continue
			}

			f := finding.Finding{
				RuleID: ruleID,
				Title: fmt.Sprintf("No authentication required: %s returns %s's record to an anonymous caller",
					route.Endpoint(), canary.Owner),
				Category:   finding.CategoryBrokenAccessControl,
				CWE:        "CWE-306",
				Severity:   finding.SeverityCritical,
				Confidence: finding.ConfidenceConfirmed,
				Source:     finding.SourceDAST,
				Location:   locationFor(route, env.RepoRev),
				Evidence: finding.Evidence{
					Summary: fmt.Sprintf(
						"A request to %s with no Authorization header, no cookie and no credentials of any kind "+
							"returned the seeded canary record owned by %s. The endpoint never asks who is calling, "+
							"so this data is readable by anyone who can reach the server.",
						concrete, canary.Owner),
					Request:     evidenceRequest(req),
					Observed:    "200 OK with the canary record, sent with no credentials",
					Expected:    "401 Unauthorized",
					EvidenceKey: fmt.Sprintf("anon:%s:%s", canary.Resource, canary.ID),
				},
				Remediation: finding.Remediation{
					Guidance: "Require authentication on this route, and prefer mounting the authentication " +
						"middleware on the router so that routes added later are protected by default rather " +
						"than by remembering. Then add the ownership check, since authentication alone would " +
						"still let any logged-in user read this record.",
					RootCauseHint:  "Authentication is applied per route by hand, and this route was missed.",
					FixableByGiver: true,
				},
				Status: finding.StatusOpen,
			}
			f.AssignID()

			artifact := writeReproArtifact(env, f.FindingID, []httpx.Request{req},
				[]string{"This request carries no credentials at all.", "A fixed application answers it with 401."})

			f.Reproduction = &finding.Reproduction{
				Kind:    finding.ReproHTTP,
				Command: "vibekiller reproduce " + f.FindingID,
				Steps: []string{
					fmt.Sprintf("Send GET %s with no Authorization header and no cookies.", concrete),
					"It returns 200 with another user's record; a correct implementation returns 401.",
				},
				ArtifactPath: artifact,
			}

			out = append(out, f)
			break
		}
	}

	// The weaker case: any other mapped read route answering an anonymous
	// caller with data, in an application that authenticates elsewhere.
	if len(env.Surface.AuthLayers) > 0 {
		out = append(out, c.probeOtherRoutes(ctx, env)...)
	}

	return out, nil
}

// maxAnonProbes bounds how many routes the weaker probe touches, so that a
// large application does not turn a scan into a load test.
const maxAnonProbes = 40

// probeOtherRoutes looks for read routes with no declared authorization that
// still answer an anonymous caller with content.
func (c *Unprotected) probeOtherRoutes(ctx context.Context, env *check.Env) []finding.Finding {
	var out []finding.Finding
	ruleID := c.Meta().RuleID
	probes := 0

	for _, route := range env.Surface.Routes {
		if probes >= maxAnonProbes {
			env.Run.Log("check.note", map[string]any{
				"rule_id": ruleID,
				"note":    fmt.Sprintf("stopped after %d anonymous probes to keep the request count bounded", maxAnonProbes),
			})
			break
		}
		if !strings.EqualFold(route.Method, http.MethodGet) || route.Mutating {
			continue
		}
		if route.HasAuth() || isPublicByDesign(route.Path) {
			continue
		}

		// A route with a path parameter needs a value, and guessing record ids
		// would mean probing data that is not ours. Use the probe marker
		// instead: it will not match a real record, so a 200 with content here
		// means the handler ignores the id, which is itself worth seeing.
		concrete := route.Path
		if len(route.PathParams) > 0 {
			concrete = fillParams(route.Path, "vk-probe")
		}

		target, err := absURL(env, concrete)
		if err != nil {
			continue
		}

		req := anonRequest(ruleID, http.MethodGet, target, "probe: anonymous read of a route with no declared auth")
		resp, err := send(ctx, env, req)
		probes++
		if err != nil || resp.Status != http.StatusOK || !bodyLooksLikeRecord(resp.Body) {
			continue
		}

		f := finding.Finding{
			RuleID:   ruleID,
			Title:    fmt.Sprintf("%s has no authorization and answers anonymous callers", route.Endpoint()),
			Category: finding.CategoryBrokenAccessControl,
			CWE:      "CWE-306",
			Severity: finding.SeverityMedium,
			// Not confirmed: the endpoint returned data, but nothing here
			// establishes that the data is meant to be private. Claiming
			// confirmed would be claiming more than was observed.
			Confidence: finding.ConfidenceLikely,
			Source:     finding.SourceDAST,
			Location:   locationFor(route, env.RepoRev),
			Evidence: finding.Evidence{
				Summary: fmt.Sprintf(
					"This application authenticates elsewhere, but %s has no authorization visible in the source "+
						"and returned 200 with content to a request carrying no credentials. Confirm whether this "+
						"endpoint is meant to be public; if it is not, it is currently open to anyone who can reach "+
						"the server.",
					route.Endpoint()),
				Request:     evidenceRequest(req),
				Observed:    fmt.Sprintf("200 OK with a %d byte body, sent with no credentials", len(resp.Body)),
				Expected:    "401 Unauthorized, if this endpoint is not intended to be public",
				EvidenceKey: "anon-route:" + route.Endpoint(),
			},
			Remediation: finding.Remediation{
				Guidance: "If this endpoint is not meant to be public, attach the authentication middleware to it. " +
					"If it is meant to be public, say so explicitly in the route definition so the next reader " +
					"does not have to guess.",
				RootCauseHint:  "Authorization is applied per route, so a route can be added without it.",
				FixableByGiver: true,
			},
			Status: finding.StatusOpen,
		}
		f.AssignID()
		f.Reproduction = &finding.Reproduction{
			Kind:    finding.ReproHTTP,
			Command: "vibekiller reproduce " + f.FindingID,
			Steps: []string{
				fmt.Sprintf("Send GET %s with no credentials.", concrete),
				"It returns 200 with a response body.",
				"Decide whether this endpoint is intended to be public.",
			},
			ArtifactPath: writeReproArtifact(env, f.FindingID, []httpx.Request{req}, nil),
		}

		out = append(out, f)
	}

	return out
}

// Reproduce replays the anonymous request for one finding.
func (c *Unprotected) Reproduce(ctx context.Context, env *check.Env, f finding.Finding) (check.Result, error) {
	if f.Evidence.Request == nil || f.Evidence.Request.Path == "" {
		return check.Result{}, fmt.Errorf("this finding carries no recorded request to replay")
	}

	target, err := absURL(env, f.Evidence.Request.Path)
	if err != nil {
		return check.Result{}, err
	}

	req := anonRequest(c.Meta().RuleID, http.MethodGet, target, "reproduction: anonymous read")
	resp, err := send(ctx, env, req)
	if err != nil {
		return check.Result{}, err
	}

	// Where the original finding named a canary, require the canary again
	// rather than accepting any 200.
	wantCanary := strings.HasPrefix(f.Evidence.EvidenceKey, "anon:")
	reproduced := resp.Status == http.StatusOK && bodyLooksLikeRecord(resp.Body)

	if wantCanary {
		parts := strings.SplitN(f.Evidence.EvidenceKey, ":", 3)
		if len(parts) == 3 {
			for _, cr := range env.Config.CanaryRecords {
				if cr.Resource == parts[1] && cr.ID == parts[2] && cr.Marker != "" {
					reproduced = resp.Status == http.StatusOK && resp.BodyContains(cr.Marker)
				}
			}
		}
	}

	detail := fmt.Sprintf("Not reproducible: the endpoint now answers an anonymous request with %d.", resp.Status)
	if reproduced {
		detail = fmt.Sprintf("Still reproducible: %s returns 200 with content to a request carrying no credentials.",
			f.Evidence.Request.Path)
	}

	return check.Result{
		Reproduced: reproduced,
		Detail:     detail,
		Evidence: finding.Evidence{
			Summary:  detail,
			Request:  evidenceRequest(req),
			Observed: fmt.Sprintf("%d, %d byte body", resp.Status, len(resp.Body)),
			Expected: "401 Unauthorized",
		},
	}, nil
}
