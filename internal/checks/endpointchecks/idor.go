package endpointchecks

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/rohitanakiya/Vibe-Killer/internal/check"
	"github.com/rohitanakiya/Vibe-Killer/internal/config"
	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
	"github.com/rohitanakiya/Vibe-Killer/internal/httpx"
	"github.com/rohitanakiya/Vibe-Killer/internal/surface"
)

func init() { check.Register(&IDOR{}) }

// IDOR tests whether one seeded user can read another seeded user's record.
//
// This is the check the whole design is built around, because a missing
// ownership check is the most common serious weakness in generated code and
// because it can be proven completely safely. The proof is a single GET for a
// record the operator created as a decoy. Nothing real is read, nothing is
// written, and the result is unambiguous: either the boundary held or it did
// not.
//
// The check is careful about false positives in one specific way: before
// concluding anything, it confirms that the record's owner can read it. If the
// owner gets a 404, then the route and the canary do not line up and a 404 for
// the other user proves nothing. Skipping that baseline is how access-control
// scanners end up reporting every route as secure.
type IDOR struct{}

// Meta describes the check.
func (c *IDOR) Meta() check.Meta {
	return check.Meta{
		RuleID:   "idor.sequential-id-access",
		Title:    "Cross-user record access (reads a seeded canary, never real data)",
		Layer:    check.LayerEndpoint,
		Category: finding.CategoryBrokenAccessControl,

		NeedsTarget:      true,
		NeedsSurface:     true,
		NeedsSeededUsers: 2,
		NeedsCanary:      true,
	}
}

// Detect probes each canary record from an account that does not own it.
func (c *IDOR) Detect(ctx context.Context, env *check.Env) ([]finding.Finding, error) {
	var out []finding.Finding

	for _, canary := range env.Config.CanaryRecords {
		owner, ok := env.Config.User(canary.Owner)
		if !ok {
			env.Run.Log("check.note", map[string]any{
				"rule_id": c.Meta().RuleID,
				"note":    fmt.Sprintf("canary %s/%s names owner %q, which is not a seeded user", canary.Resource, canary.ID, canary.Owner),
			})
			continue
		}
		prober, ok := pickProber(env, canary.Owner)
		if !ok {
			continue
		}

		// Read-only: GET alone. A missing ownership check on a write is just
		// as serious, but proving it would mean changing a record, which is
		// gated behind the disposable-environment flags and handled elsewhere.
		routes := routesForResource(env.Surface, canary.Resource, http.MethodGet)
		if len(routes) == 0 {
			env.Run.Log("check.note", map[string]any{
				"rule_id": c.Meta().RuleID,
				"note": fmt.Sprintf("no mapped GET route matches canary resource %q; "+
					"add the route or rename the resource to match the path", canary.Resource),
			})
			continue
		}

		for _, route := range routes {
			f, err := c.probeRoute(ctx, env, route, canary, owner, prober)
			if err != nil {
				// One unreachable route must not end the check.
				env.Run.Log("check.note", map[string]any{
					"rule_id": c.Meta().RuleID,
					"route":   route.Endpoint(),
					"note":    "probe could not complete: " + err.Error(),
				})
				continue
			}
			if f != nil {
				out = append(out, *f)
				// One confirmed finding per canary is enough; probing further
				// routes for the same record adds requests without adding
				// information.
				break
			}
		}
	}

	return out, nil
}

// probeRoute runs the baseline-then-probe sequence for one route and canary.
func (c *IDOR) probeRoute(
	ctx context.Context,
	env *check.Env,
	route surface.Route,
	canary config.CanaryRecord,
	owner, prober config.SeededUser,
) (*finding.Finding, error) {
	ruleID := c.Meta().RuleID

	concrete := fillParams(route.Path, canary.ID)
	target, err := absURL(env, concrete)
	if err != nil {
		return nil, err
	}

	// Step 1: establish that the owner can read their own canary. Without
	// this, a refusal for the prober means nothing.
	ownerReq, err := authedRequest(ruleID, http.MethodGet, target, owner,
		"baseline: confirm the canary's owner can read it")
	if err != nil {
		return nil, err
	}
	ownerResp, err := send(ctx, env, ownerReq)
	if err != nil {
		return nil, err
	}
	if ownerResp.Status != http.StatusOK {
		env.Run.Log("check.note", map[string]any{
			"rule_id": ruleID,
			"route":   route.Endpoint(),
			"note": fmt.Sprintf("baseline failed: owner %s got %d for its own canary %s, "+
				"so this route and canary do not line up and no conclusion is drawn",
				owner.ID, ownerResp.Status, canary.ID),
		})
		return nil, nil
	}
	if !bodyLooksLikeRecord(ownerResp.Body) {
		env.Run.Log("check.note", map[string]any{
			"rule_id": ruleID,
			"route":   route.Endpoint(),
			"note": "baseline returned 200 but no record body, so there is nothing " +
				"whose disclosure could be detected",
		})
		return nil, nil
	}

	// Step 2: the same request as a user who does not own the record.
	proberReq, err := authedRequest(ruleID, http.MethodGet, target, prober,
		fmt.Sprintf("probe: read %s's canary as %s", owner.ID, prober.ID))
	if err != nil {
		return nil, err
	}
	proberResp, err := send(ctx, env, proberReq)
	if err != nil {
		return nil, err
	}

	// The boundary held. This is the common and correct outcome.
	if proberResp.Status == http.StatusForbidden || proberResp.Status == http.StatusNotFound ||
		proberResp.Status == http.StatusUnauthorized {
		return nil, nil
	}
	if proberResp.Status != http.StatusOK {
		env.Run.Log("check.note", map[string]any{
			"rule_id": ruleID,
			"route":   route.Endpoint(),
			"note": fmt.Sprintf("probe got an unexpected %d, which is neither a clear refusal "+
				"nor a disclosure; no conclusion is drawn", proberResp.Status),
		})
		return nil, nil
	}

	// A 200 is not yet a disclosure: the handler may have returned an empty
	// result or someone else's scoped view. Require evidence that this is the
	// owner's record.
	matchedMarker := canary.Marker != "" && proberResp.BodyContains(canary.Marker)
	matchedBody := canary.Marker == "" &&
		bodyLooksLikeRecord(proberResp.Body) &&
		strings.TrimSpace(proberResp.Body) == strings.TrimSpace(ownerResp.Body)

	if !matchedMarker && !matchedBody {
		env.Run.Log("check.note", map[string]any{
			"rule_id": ruleID,
			"route":   route.Endpoint(),
			"note": "probe got 200 but the body does not match the owner's record, so the " +
				"record was probably not disclosed; no finding raised",
		})
		return nil, nil
	}

	how := "the response body is byte-identical to the owner's"
	if matchedMarker {
		how = fmt.Sprintf("the response contains the canary marker %q", canary.Marker)
	}

	loc := locationFor(route, env.RepoRev)
	f := finding.Finding{
		RuleID: ruleID,
		Title: fmt.Sprintf("Missing ownership check: %s can read %s's record via %s",
			prober.ID, owner.ID, route.Endpoint()),
		Category:   finding.CategoryBrokenAccessControl,
		CWE:        "CWE-639",
		Severity:   finding.SeverityHigh,
		Confidence: finding.ConfidenceConfirmed,
		Source:     finding.SourceDAST,
		Location:   loc,
		Evidence: finding.Evidence{
			Summary: fmt.Sprintf(
				"Requesting %s as seeded user %s returned the canary record owned by seeded user %s. "+
					"The owner's own request was checked first and succeeded, so this route does serve the record; "+
					"%s. Authentication is working and authorization is not: the handler returns the record to "+
					"whoever asks for it by id.",
				concrete, prober.ID, owner.ID, how),
			Request:  evidenceRequest(proberReq),
			Observed: fmt.Sprintf("200 OK, and %s", how),
			Expected: "403 Forbidden or 404 Not Found, because the caller does not own this record",
			// Keyed on the canary, so re-running against the same seeded data
			// produces the same finding id.
			EvidenceKey: fmt.Sprintf("canary:%s:%s", canary.Resource, canary.ID),
		},
		Remediation: finding.Remediation{
			Guidance: "Scope the lookup to the authenticated principal rather than checking ownership after " +
				"fetching, so a record belonging to someone else is never loaded. Return 404 rather than 403 " +
				"on a miss, so the endpoint does not confirm that another user's record exists.",
			RootCauseHint: "Authorization is missing at the data-access layer. The route authenticates the " +
				"caller and then queries by the id it was given, without the principal as part of the query.",
			References:     []string{"https://owasp.org/Top10/A01_2021-Broken_Access_Control/"},
			FixableByGiver: true,
		},
		Status: finding.StatusOpen,
	}
	f.AssignID()

	artifact := writeReproArtifact(env, f.FindingID,
		[]httpx.Request{ownerReq, proberReq},
		[]string{
			"The first request is the baseline: the canary's owner reading their own record.",
			"The second is the probe: a different seeded user reading the same record.",
			"A fixed application answers the second with 403 or 404.",
		})

	f.Reproduction = &finding.Reproduction{
		Kind:    finding.ReproHTTP,
		Command: "vibekiller reproduce " + f.FindingID,
		Steps: []string{
			fmt.Sprintf("As seeded user %s, GET %s and confirm it returns 200 with the canary record.", owner.ID, concrete),
			fmt.Sprintf("As seeded user %s, GET the same path.", prober.ID),
			"It returns 200 with the other user's record; a correct implementation returns 403 or 404.",
		},
		ArtifactPath: artifact,
	}

	return &f, nil
}

// Reproduce re-runs the probe for one finding.
//
// It repeats the same two-step sequence rather than only the probe, so that a
// finding is reported as fixed only when the boundary actually holds, not
// because the canary or the route went away.
func (c *IDOR) Reproduce(ctx context.Context, env *check.Env, f finding.Finding) (check.Result, error) {
	if f.Evidence.Request == nil || f.Evidence.Request.Path == "" {
		return check.Result{}, fmt.Errorf("this finding carries no recorded request to replay")
	}

	proberID := strings.TrimSuffix(f.Evidence.Request.Auth, "-token")
	prober, ok := env.Config.User(proberID)
	if !ok {
		return check.Result{}, fmt.Errorf("seeded user %q is no longer in the config, so this finding cannot be replayed", proberID)
	}

	// Recover the canary from the evidence key, which was built as
	// canary:<resource>:<id>.
	parts := strings.SplitN(f.Evidence.EvidenceKey, ":", 3)
	if len(parts) != 3 || parts[0] != "canary" {
		return check.Result{}, fmt.Errorf("this finding's evidence key %q is not a canary reference", f.Evidence.EvidenceKey)
	}
	resource, canaryID := parts[1], parts[2]

	var canary config.CanaryRecord
	found := false
	for _, cr := range env.Config.CanaryRecords {
		if cr.Resource == resource && cr.ID == canaryID {
			canary, found = cr, true
			break
		}
	}
	if !found {
		return check.Result{}, fmt.Errorf("canary %s/%s is no longer declared in the config", resource, canaryID)
	}
	owner, ok := env.Config.User(canary.Owner)
	if !ok {
		return check.Result{}, fmt.Errorf("canary owner %q is no longer a seeded user", canary.Owner)
	}

	target, err := absURL(env, f.Evidence.Request.Path)
	if err != nil {
		return check.Result{}, err
	}

	ruleID := c.Meta().RuleID

	ownerReq, err := authedRequest(ruleID, http.MethodGet, target, owner, "baseline for reproduction")
	if err != nil {
		return check.Result{}, err
	}
	ownerResp, err := send(ctx, env, ownerReq)
	if err != nil {
		return check.Result{}, err
	}
	if ownerResp.Status != http.StatusOK {
		return check.Result{
			Reproduced: false,
			Detail: fmt.Sprintf("Inconclusive: the owner %s now gets %d for its own canary, so the boundary "+
				"cannot be tested. Check that the seeded data still exists.", owner.ID, ownerResp.Status),
		}, nil
	}

	proberReq, err := authedRequest(ruleID, http.MethodGet, target, prober, "probe for reproduction")
	if err != nil {
		return check.Result{}, err
	}
	proberResp, err := send(ctx, env, proberReq)
	if err != nil {
		return check.Result{}, err
	}

	disclosed := proberResp.Status == http.StatusOK &&
		((canary.Marker != "" && proberResp.BodyContains(canary.Marker)) ||
			(canary.Marker == "" && strings.TrimSpace(proberResp.Body) == strings.TrimSpace(ownerResp.Body)))

	if !disclosed {
		return check.Result{
			Reproduced: false,
			Detail: fmt.Sprintf("Not reproducible: %s now gets %d and the canary was not returned. "+
				"The ownership check appears to be in place.", prober.ID, proberResp.Status),
			Evidence: finding.Evidence{
				Summary:  "The probe no longer returns the other user's record.",
				Request:  evidenceRequest(proberReq),
				Observed: fmt.Sprintf("%d, canary not present in the body", proberResp.Status),
				Expected: "403 or 404",
			},
		}, nil
	}

	return check.Result{
		Reproduced: true,
		Detail: fmt.Sprintf("Still reproducible: %s read %s's canary record at %s.",
			prober.ID, owner.ID, f.Evidence.Request.Path),
		Evidence: finding.Evidence{
			Summary:  fmt.Sprintf("Request as %s still returns %s's canary record.", prober.ID, owner.ID),
			Request:  evidenceRequest(proberReq),
			Observed: "200 OK, canary record present in the body",
			Expected: "403 or 404",
		},
	}, nil
}
