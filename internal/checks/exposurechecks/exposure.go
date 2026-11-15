// Package exposurechecks holds the scoped cross-service exposure analyzer.
//
// It answers one question: if an attacker reached one of your components, what
// else would that get them? In a generated multi-service application the
// answer is usually "everything", for a mundane reason — the services were
// scaffolded together and share a signing secret, so a token minted by one is
// accepted by all of them. Each service looks correctly authenticated in
// isolation, and the trust domain is accidentally global.
//
// # Scope is the whole design here
//
// This is the one part of Vibe Killer that deliberately looks at more than one
// host, so it is also the part where the boundary matters most. The analyzer:
//
//   - only ever contacts hosts the operator listed in authorized_targets, and
//     the HTTP client refuses anything else at dial time regardless;
//   - uses only the throwaway seeded credentials, never a credential found in
//     the repository, so nothing real is replayed anywhere;
//   - sends read-only requests, one small set per declared host;
//   - never follows a lead. It does not read a discovered hostname out of a
//     response and go there, it does not enumerate, and it does not expand
//     its own scope. The list it works from is fixed before it starts and
//     cannot grow.
//
// Every finding it produces carries scope "declared-targets-only", and the
// contract validator rejects any other value.
package exposurechecks

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/rohitanakiya/Vibe-Killer/internal/check"
	"github.com/rohitanakiya/Vibe-Killer/internal/config"
	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
	"github.com/rohitanakiya/Vibe-Killer/internal/httpx"
)

func init() { check.Register(&SharedTrustDomain{}) }

// SharedTrustDomain tests whether a token issued for one declared component is
// accepted by another.
//
// The test is a differential, which is what makes it conclusive rather than
// suggestive. For each other declared host, the same request is sent twice:
// once with no credentials and once with a seeded token that belongs to the
// primary target. If the host refuses the first and serves the second, it
// verified a token it was never meant to be able to verify, and the two
// components share whatever key or session store backs that verification.
type SharedTrustDomain struct{}

// Meta describes the check.
func (c *SharedTrustDomain) Meta() check.Meta {
	return check.Meta{
		RuleID:   "exposure.shared-trust-domain",
		Title:    "Credentials from one declared component accepted by another",
		Layer:    check.LayerExposure,
		Category: finding.CategoryCrossService,

		NeedsTarget:      true,
		NeedsSeededUsers: 1,
	}
}

// probePaths are the endpoints tried on a neighbour, in order.
//
// The list is short and fixed. It is not a discovery sweep: the point is to
// find one endpoint that distinguishes an authenticated request from an
// anonymous one, and if none of these does, the check reports nothing rather
// than going looking.
var probePaths = []string{
	"/api/me",
	"/api/user",
	"/api/users/me",
	"/api/profile",
	"/api/account",
	"/me",
	"/api/orders",
	"/api/v1/me",
	"/api",
}

// Detect compares each declared neighbour against the primary target.
func (c *SharedTrustDomain) Detect(ctx context.Context, env *check.Env) ([]finding.Finding, error) {
	ruleID := c.Meta().RuleID

	// The scope is fixed here, before anything is sent, and nothing below can
	// add to it.
	neighbours, err := c.neighbours(env)
	if err != nil {
		return nil, err
	}
	if len(neighbours) == 0 {
		env.Run.Log("check.note", map[string]any{
			"rule_id": ruleID,
			"note": "only one host is declared in authorized_targets, so there is no neighbour to " +
				"compare against. Declare the other components you own to enable this check",
		})
		return nil, nil
	}

	user, ok := firstUsableUser(env)
	if !ok {
		return nil, fmt.Errorf("no seeded user has a usable token")
	}

	env.Run.Log("exposure.scope", map[string]any{
		"rule_id":    ruleID,
		"primary":    env.Target,
		"neighbours": neighbours,
		"note":       "fixed before probing; the analyzer cannot add to this list",
	})

	var out []finding.Finding
	for _, neighbour := range neighbours {
		f, err := c.probeNeighbour(ctx, env, user, neighbour)
		if err != nil {
			env.Run.Log("check.note", map[string]any{
				"rule_id": ruleID, "neighbour": neighbour,
				"note": "could not be probed: " + err.Error(),
			})
			continue
		}
		if f != nil {
			out = append(out, *f)
		}
	}

	return out, nil
}

// neighbours returns the declared targets other than the primary one.
func (c *SharedTrustDomain) neighbours(env *check.Env) ([]string, error) {
	if env.Guard == nil {
		return nil, fmt.Errorf("no scope guard is available, so no host can be authorized")
	}

	primary, err := originOf(env.Target)
	if err != nil {
		return nil, err
	}

	var out []string
	for _, declared := range env.Guard.Targets() {
		origin, err := originOf(declared)
		if err != nil {
			continue
		}
		if origin == primary {
			continue
		}
		// Belt and braces: the guard produced this list, and it is asked
		// again anyway. A check should not be the only thing standing between
		// a bug and an undeclared host.
		if err := env.Guard.AuthorizeTarget(declared); err != nil {
			continue
		}
		out = append(out, declared)
	}

	sort.Strings(out)
	return dedupe(out), nil
}

// originOf normalizes a URL to scheme://host:port so that the same host
// written two ways is recognized as one.
func originOf(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parsing %q: %w", raw, err)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", fmt.Errorf("%q names no host", raw)
	}
	port := u.Port()
	if port == "" {
		if strings.EqualFold(u.Scheme, "https") {
			port = "443"
		} else {
			port = "80"
		}
	}
	return strings.ToLower(u.Scheme) + "://" + host + ":" + port, nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		key, err := originOf(s)
		if err != nil || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, s)
	}
	return out
}

func firstUsableUser(env *check.Env) (config.SeededUser, bool) {
	for _, u := range env.Config.SeededUsers {
		if _, err := u.Token(); err == nil {
			return u, true
		}
	}
	return config.SeededUser{}, false
}

// probeNeighbour runs the anonymous-then-authenticated differential against
// one declared host.
func (c *SharedTrustDomain) probeNeighbour(
	ctx context.Context, env *check.Env, user config.SeededUser, neighbour string,
) (*finding.Finding, error) {
	ruleID := c.Meta().RuleID
	base := strings.TrimSuffix(neighbour, "/")

	for _, path := range probePaths {
		target := base + path

		// Step 1: no credentials. An endpoint that serves an anonymous caller
		// tells us nothing about token acceptance, so only a refusal is
		// interesting.
		anonReq := httpx.Request{
			RuleID: ruleID, Method: http.MethodGet, URL: target,
			AuthLabel: "none",
			Note:      "baseline: does this neighbour refuse an anonymous request",
		}
		anonResp, err := env.HTTP.Do(ctx, anonReq)
		if err != nil {
			// A path that does not exist, or a host that is not up. Try the
			// next path; do not go looking elsewhere.
			continue
		}
		if anonResp.Status != http.StatusUnauthorized && anonResp.Status != http.StatusForbidden {
			continue
		}

		// Step 2: the same request with a token minted for the other
		// component.
		name, value, err := user.AuthHeader()
		if err != nil {
			return nil, err
		}
		authReq := httpx.Request{
			RuleID: ruleID, Method: http.MethodGet, URL: target,
			Headers:   map[string]string{name: value},
			AuthLabel: user.ID,
			Note:      "probe: present a token issued for the primary target to this neighbour",
		}
		authResp, err := env.HTTP.Do(ctx, authReq)
		if err != nil {
			continue
		}

		if authResp.Status == http.StatusUnauthorized || authResp.Status == http.StatusForbidden {
			// The neighbour rejected it. That is the correct outcome and the
			// whole point of separate trust domains.
			env.Run.Log("check.note", map[string]any{
				"rule_id": ruleID, "neighbour": neighbour, "path": path,
				"note": fmt.Sprintf("the neighbour refused the primary target's token with %d, "+
					"so these components do not share a trust domain at this endpoint", authResp.Status),
			})
			return nil, nil
		}
		if authResp.Status >= 400 {
			// Neither a refusal nor an acceptance.
			continue
		}

		return c.finding(env, user, neighbour, path, anonResp.Status, authResp.Status, authReq), nil
	}

	env.Run.Log("check.note", map[string]any{
		"rule_id": ruleID, "neighbour": neighbour,
		"note": "no probed endpoint distinguished an authenticated request from an anonymous one, " +
			"so nothing could be established either way. This is a gap in coverage, not a clean result",
	})
	return nil, nil
}

func (c *SharedTrustDomain) finding(
	env *check.Env, user config.SeededUser,
	neighbour, path string, anonStatus, authStatus int,
	authReq httpx.Request,
) *finding.Finding {
	primaryOrigin, _ := originOf(env.Target)
	neighbourOrigin, _ := originOf(neighbour)

	f := finding.Finding{
		RuleID: c.Meta().RuleID,
		Title: fmt.Sprintf("A token issued for %s is accepted by %s",
			primaryOrigin, neighbourOrigin),
		Category:   finding.CategoryCrossService,
		CWE:        "CWE-522",
		Severity:   finding.SeverityHigh,
		Confidence: finding.ConfidenceConfirmed,
		Source:     finding.SourceBlastRadius,
		Location: finding.Location{
			Type:     finding.LocationEndpoint,
			Endpoint: "GET " + path,
			RepoRev:  env.RepoRev,
		},
		Evidence: finding.Evidence{
			Summary: fmt.Sprintf(
				"%s refused an anonymous request to %s with %d, and served the same request with %d "+
					"when it carried a seeded token belonging to %s. It therefore verified a credential "+
					"issued by a different component, which means the two share the key or session store "+
					"that backs that verification. Compromising either one yields working credentials for "+
					"the other, so they are a single trust domain however they are deployed. "+
					"Only hosts you declared were contacted, and only the throwaway seeded token was "+
					"used: no credential from your repository was replayed anywhere.",
				neighbourOrigin, path, anonStatus, authStatus, primaryOrigin),
			Request:  evidenceRequest(authReq),
			Observed: fmt.Sprintf("%d anonymous, %d with the other component's token", anonStatus, authStatus),
			Expected: fmt.Sprintf("%d with the other component's token: a credential minted elsewhere "+
				"should not verify here", anonStatus),
			// Keyed on the pair, so the same exposure keeps its identity.
			EvidenceKey: "trust-domain:" + primaryOrigin + "->" + neighbourOrigin,
		},
		BlastRadius: &finding.BlastRadius{
			ReachableFrom: primaryOrigin,
			Reached: []string{
				fmt.Sprintf("%s, via a credential accepted at GET %s", neighbourOrigin, path),
			},
			Scope: finding.ScopeDeclaredOnly,
		},
		Remediation: finding.Remediation{
			Guidance: "Give each component its own signing key, and have it accept only tokens it issued " +
				"or tokens from an issuer it names explicitly. Where a shared identity provider is " +
				"intended, set and verify the audience claim so each component accepts only tokens " +
				"minted for it. Rotating the shared key without separating the domains only resets the " +
				"clock.",
			RootCauseHint: "The components were scaffolded with the same signing secret or session " +
				"store, so every service can verify every other service's credentials.",
			References: []string{
				"https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
			},
			// Separating trust domains means issuing new keys and deciding
			// which component owns identity. That is an operational decision
			// about a deployment, and getting it wrong locks users out.
			FixableByGiver: false,
			HumanRequiredReason: "separating the trust domains means issuing new signing keys and " +
				"deciding which component owns identity, which is a deployment decision rather than a " +
				"code edit, and a wrong move here signs every user out",
		},
		Status: finding.StatusOpen,
	}
	f.AssignID()

	f.Reproduction = &finding.Reproduction{
		Kind:    finding.ReproHTTP,
		Command: "vibekiller reproduce " + f.FindingID,
		Steps: []string{
			fmt.Sprintf("Send GET %s%s with no credentials. It returns %d.", neighbour, path, anonStatus),
			fmt.Sprintf("Send the same request with seeded user %s's token, which was issued for %s.",
				user.ID, primaryOrigin),
			fmt.Sprintf("It returns %d, so this component verified another component's credential.", authStatus),
		},
	}

	return &f
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

// Reproduce re-runs the differential for one finding.
func (c *SharedTrustDomain) Reproduce(ctx context.Context, env *check.Env, f finding.Finding) (check.Result, error) {
	if f.BlastRadius == nil {
		return check.Result{}, fmt.Errorf("this finding carries no blast radius to replay")
	}
	// The scope rule applies on a replay exactly as it does on a scan.
	if f.BlastRadius.Scope != finding.ScopeDeclaredOnly {
		return check.Result{}, fmt.Errorf("refusing to replay a finding whose scope is %q",
			f.BlastRadius.Scope)
	}

	user, ok := firstUsableUser(env)
	if !ok {
		return check.Result{}, fmt.Errorf("no seeded user has a usable token")
	}

	neighbours, err := c.neighbours(env)
	if err != nil {
		return check.Result{}, err
	}

	path := strings.TrimPrefix(f.Location.Endpoint, "GET ")
	for _, neighbour := range neighbours {
		origin, oerr := originOf(neighbour)
		if oerr != nil {
			continue
		}
		if !strings.Contains(f.Evidence.EvidenceKey, origin) {
			continue
		}

		target := strings.TrimSuffix(neighbour, "/") + path

		name, value, aerr := user.AuthHeader()
		if aerr != nil {
			return check.Result{}, aerr
		}
		req := httpx.Request{
			RuleID: c.Meta().RuleID, Method: http.MethodGet, URL: target,
			Headers:   map[string]string{name: value},
			AuthLabel: user.ID,
			Note:      "reproduction: present the other component's token",
		}
		resp, derr := env.HTTP.Do(ctx, req)
		if derr != nil {
			return check.Result{}, derr
		}

		accepted := resp.Status < 400
		detail := fmt.Sprintf("Not reproducible: %s now answers %d to the other component's token.",
			origin, resp.Status)
		if accepted {
			detail = fmt.Sprintf("Still reproducible: %s accepted the other component's token with %d.",
				origin, resp.Status)
		}

		return check.Result{
			Reproduced: accepted,
			Detail:     detail,
			Evidence: finding.Evidence{
				Summary:  detail,
				Request:  evidenceRequest(req),
				Observed: fmt.Sprintf("%d", resp.Status),
				Expected: "401 or 403",
			},
		}, nil
	}

	return check.Result{}, fmt.Errorf("the neighbour this finding names is no longer in authorized_targets, " +
		"so it cannot be replayed without widening the declared scope")
}
