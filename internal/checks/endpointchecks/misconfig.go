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

func init() {
	check.Register(&CORS{})
	check.Register(&SecurityHeaders{})
	check.Register(&VerboseErrors{})
}

// probeOrigin is the Origin header used for the CORS check.
//
// It is in the .invalid top-level domain, which RFC 2606 reserves and which
// therefore cannot resolve to anyone's host. Using a real-looking domain here
// would mean a scan that mentions somebody else's name in a log it does not
// control.
const probeOrigin = "https://cors-probe.vibekiller.invalid"

// probeEndpoint returns a path to send a generic request to: a mapped read
// route if one exists, otherwise the application root.
func probeEndpoint(env *check.Env) string {
	if env.Surface != nil {
		for _, r := range env.Surface.Routes {
			if strings.EqualFold(r.Method, http.MethodGet) && len(r.PathParams) == 0 {
				return r.Path
			}
		}
		for _, r := range env.Surface.Routes {
			if strings.EqualFold(r.Method, http.MethodGet) {
				return fillParams(r.Path, "vk-probe")
			}
		}
	}
	return "/"
}

// --- CORS ------------------------------------------------------------------

// CORS checks whether the application reflects an arbitrary origin while
// allowing credentials.
//
// That combination is what makes a cross-origin policy dangerous rather than
// merely permissive: with credentials allowed, any site a logged-in user
// visits can call the API as them and read the response. Either setting alone
// is usually harmless.
type CORS struct{}

// Meta describes the check.
func (c *CORS) Meta() check.Meta {
	return check.Meta{
		RuleID:      "misconfig.cors-reflection",
		Title:       "Cross-origin policy reflects any origin with credentials",
		Layer:       check.LayerEndpoint,
		Category:    finding.CategoryMisconfiguration,
		NeedsTarget: true,
	}
}

// Detect sends one request with a probe Origin and reads the response headers.
func (c *CORS) Detect(ctx context.Context, env *check.Env) ([]finding.Finding, error) {
	ruleID := c.Meta().RuleID
	path := probeEndpoint(env)

	target, err := absURL(env, path)
	if err != nil {
		return nil, err
	}

	req := httpx.Request{
		RuleID:    ruleID,
		Method:    http.MethodGet,
		URL:       target,
		Headers:   map[string]string{"Origin": probeOrigin},
		AuthLabel: "none",
		Note:      "probe: does the app reflect an arbitrary Origin",
	}
	resp, err := send(ctx, env, req)
	if err != nil {
		return nil, err
	}

	allowOrigin := strings.TrimSpace(resp.Headers.Get("Access-Control-Allow-Origin"))
	allowCreds := strings.EqualFold(strings.TrimSpace(resp.Headers.Get("Access-Control-Allow-Credentials")), "true")

	reflected := allowOrigin == probeOrigin
	wildcard := allowOrigin == "*"

	if !reflected && !wildcard {
		return nil, nil
	}

	var severity finding.Severity
	var summary, expected string

	switch {
	case reflected && allowCreds:
		severity = finding.SeverityHigh
		summary = fmt.Sprintf(
			"The application echoed the Origin header back as Access-Control-Allow-Origin and set "+
				"Access-Control-Allow-Credentials to true. The probe origin %s is a reserved .invalid domain that "+
				"cannot exist, so this is reflection rather than an allowlist. Any site a logged-in user visits can "+
				"call this API as them and read the response.", probeOrigin)
		expected = "the Origin header not echoed, and only configured origins allowed"
	case wildcard && allowCreds:
		severity = finding.SeverityHigh
		summary = "Access-Control-Allow-Origin is * and Access-Control-Allow-Credentials is true. " +
			"Browsers reject this combination, so credentialed cross-origin requests will fail at runtime, " +
			"but the configuration shows the intent was to allow any origin with credentials."
		expected = "an explicit list of allowed origins"
	case reflected:
		severity = finding.SeverityMedium
		summary = fmt.Sprintf(
			"The application echoed the Origin header back as Access-Control-Allow-Origin. Credentials are not "+
				"allowed, so a browser will not send cookies cross-origin, but any origin can read unauthenticated "+
				"responses. The probe origin %s cannot exist, so this is reflection rather than an allowlist.", probeOrigin)
		expected = "the Origin header not echoed"
	default:
		severity = finding.SeverityLow
		summary = "Access-Control-Allow-Origin is *, so any origin can read unauthenticated responses. " +
			"Credentials are not allowed, which limits the impact."
		expected = "an explicit list of allowed origins, if cross-origin access is needed at all"
	}

	f := finding.Finding{
		RuleID:     ruleID,
		Title:      "Cross-origin policy accepts an arbitrary origin",
		Category:   finding.CategoryMisconfiguration,
		CWE:        "CWE-942",
		Severity:   severity,
		Confidence: finding.ConfidenceConfirmed,
		Source:     finding.SourceDAST,
		Location: finding.Location{
			Type:     finding.LocationEndpoint,
			Endpoint: "GET " + path,
			RepoRev:  env.RepoRev,
		},
		Evidence: finding.Evidence{
			Summary:     summary,
			Request:     evidenceRequest(req),
			Observed:    fmt.Sprintf("Access-Control-Allow-Origin: %s, Access-Control-Allow-Credentials: %v", allowOrigin, allowCreds),
			Expected:    expected,
			EvidenceKey: fmt.Sprintf("cors:%s:%v", map[bool]string{true: "reflected", false: "wildcard"}[reflected], allowCreds),
		},
		Remediation: finding.Remediation{
			Guidance: "Replace the reflected or wildcard origin with an explicit allowlist, and keep credentials " +
				"enabled only for those origins. Echoing the request's Origin header is equivalent to allowing " +
				"every site, however it is written.",
			RootCauseHint:  "The origin check was widened to clear a browser error during development and never narrowed.",
			References:     []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"},
			FixableByGiver: true,
		},
		Status: finding.StatusOpen,
	}
	f.AssignID()
	f.Reproduction = &finding.Reproduction{
		Kind:    finding.ReproHTTP,
		Command: "vibekiller reproduce " + f.FindingID,
		Steps: []string{
			fmt.Sprintf("Send GET %s with the header: Origin: %s", path, probeOrigin),
			"Read Access-Control-Allow-Origin in the response.",
			"It carries the probe origin back, which no allowlist would do.",
		},
		ArtifactPath: writeReproArtifact(env, f.FindingID, []httpx.Request{req}, nil),
	}

	return []finding.Finding{f}, nil
}

// --- security headers ------------------------------------------------------

// SecurityHeaders reports response headers that are absent.
//
// These are reported as low severity on purpose. A missing header is a
// hardening gap, not a vulnerability, and treating it as one is how scanner
// output becomes noise that nobody reads.
type SecurityHeaders struct{}

// Meta describes the check.
func (c *SecurityHeaders) Meta() check.Meta {
	return check.Meta{
		RuleID:      "misconfig.missing-security-headers",
		Title:       "Response hardening headers",
		Layer:       check.LayerEndpoint,
		Category:    finding.CategoryMisconfiguration,
		NeedsTarget: true,
	}
}

// headerCheck is one header the check looks for.
type headerCheck struct {
	name     string
	why      string
	fix      string
	httpOnly bool // only meaningful over HTTPS
}

var wantedHeaders = []headerCheck{
	{
		name: "X-Content-Type-Options",
		why:  "without it a browser may ignore the declared content type and interpret a response as something else, such as treating an uploaded file as HTML",
		fix:  "send X-Content-Type-Options: nosniff",
	},
	{
		name: "X-Frame-Options",
		why:  "without it, or a frame-ancestors directive, the application can be framed by another site, which enables clickjacking",
		fix:  "send X-Frame-Options: DENY, or set frame-ancestors in a Content-Security-Policy",
	},
	{
		name: "Content-Security-Policy",
		why:  "a policy limits what a successful script injection can do; without one, any injected script runs with the page's full authority",
		fix:  "add a Content-Security-Policy, starting with default-src 'self'",
	},
	{
		name:     "Strict-Transport-Security",
		why:      "without it a browser will try plain HTTP first on a later visit, which exposes that request to interception",
		fix:      "send Strict-Transport-Security with a max-age once the site is reliably served over HTTPS",
		httpOnly: true,
	},
}

// Detect reads the headers from a single response.
func (c *SecurityHeaders) Detect(ctx context.Context, env *check.Env) ([]finding.Finding, error) {
	path := probeEndpoint(env)
	target, err := absURL(env, path)
	if err != nil {
		return nil, err
	}

	req := anonRequest(c.Meta().RuleID, http.MethodGet, target, "probe: read response hardening headers")
	resp, err := send(ctx, env, req)
	if err != nil {
		return nil, err
	}

	overHTTPS := strings.HasPrefix(strings.ToLower(env.Target), "https://")

	var missing []headerCheck
	for _, h := range wantedHeaders {
		if h.httpOnly && !overHTTPS {
			// Asking for HSTS on a plain-HTTP dev server is advice the
			// operator cannot act on, so it is not reported.
			continue
		}
		if strings.TrimSpace(resp.Headers.Get(h.name)) == "" {
			missing = append(missing, h)
		}
	}
	if len(missing) == 0 {
		return nil, nil
	}

	var names []string
	var detail strings.Builder
	for _, h := range missing {
		names = append(names, h.name)
		fmt.Fprintf(&detail, "- %s: %s. Fix: %s.\n", h.name, h.why, h.fix)
	}

	f := finding.Finding{
		RuleID:     c.Meta().RuleID,
		Title:      fmt.Sprintf("%d response hardening header(s) are not set", len(missing)),
		Category:   finding.CategoryMisconfiguration,
		CWE:        "CWE-693",
		Severity:   finding.SeverityLow,
		Confidence: finding.ConfidenceConfirmed,
		Source:     finding.SourceDAST,
		Location: finding.Location{
			Type:     finding.LocationEndpoint,
			Endpoint: "GET " + path,
			RepoRev:  env.RepoRev,
		},
		Evidence: finding.Evidence{
			Summary: fmt.Sprintf("The response to GET %s does not set: %s.\n\n%s\nThese are hardening gaps rather "+
				"than vulnerabilities on their own: each one limits the damage a different flaw could do.",
				path, strings.Join(names, ", "), detail.String()),
			Request:     evidenceRequest(req),
			Observed:    "headers absent from the response: " + strings.Join(names, ", "),
			Expected:    "each header present with a restrictive value",
			EvidenceKey: "headers:" + strings.Join(names, ","),
		},
		Remediation: finding.Remediation{
			Guidance: "Set these headers once, globally, rather than per route. Most frameworks have a single " +
				"middleware for it, such as helmet for Express or a response-header hook elsewhere.",
			RootCauseHint:  "No response-hardening middleware is installed.",
			FixableByGiver: true,
		},
		Status: finding.StatusOpen,
	}
	f.AssignID()
	f.Reproduction = &finding.Reproduction{
		Kind:    finding.ReproHTTP,
		Command: "vibekiller reproduce " + f.FindingID,
		Steps: []string{
			fmt.Sprintf("Send GET %s and read the response headers.", path),
			"The headers listed in the evidence are absent.",
		},
		ArtifactPath: writeReproArtifact(env, f.FindingID, []httpx.Request{req}, nil),
	}

	return []finding.Finding{f}, nil
}

// --- verbose errors --------------------------------------------------------

// VerboseErrors checks whether an error response discloses internals.
//
// The probe is a single benign request: an id that is a harmless string. Many
// generated handlers pass it straight into a typed query, and the resulting
// error is returned to the caller with a stack trace, file paths and library
// versions in it. The check sends nothing designed to cause an effect; it just
// reads what comes back.
type VerboseErrors struct{}

// Meta describes the check.
func (c *VerboseErrors) Meta() check.Meta {
	return check.Meta{
		RuleID:       "misconfig.verbose-error",
		Title:        "Error responses disclose internal detail",
		Layer:        check.LayerEndpoint,
		Category:     finding.CategoryMisconfiguration,
		NeedsTarget:  true,
		NeedsSurface: true,
	}
}

// errorSignatures are strings that only appear in an unhandled-error response,
// never in a deliberate error message.
var errorSignatures = []struct {
	needle, means string
}{
	{"Traceback (most recent call last)", "a Python traceback"},
	{"werkzeug.exceptions", "a Werkzeug exception page"},
	{"Werkzeug Debugger", "the Werkzeug interactive debugger, which allows code execution"},
	{"console-ready", "the Werkzeug interactive debugger, which allows code execution"},
	{"django.core.exceptions", "a Django exception"},
	{"DEBUG = True", "Django settings"},
	{"at Object.<anonymous>", "a Node.js stack trace"},
	{"at Module._compile", "a Node.js stack trace"},
	{"node_modules/", "a Node.js stack trace with filesystem paths"},
	{"ER_PARSE_ERROR", "a MySQL driver error"},
	{"SQLSTATE[", "a database driver error"},
	{"syntax error at or near", "a PostgreSQL error"},
	{"SequelizeDatabaseError", "a Sequelize database error"},
	{"MongoServerError", "a MongoDB server error"},
	{"java.lang.NullPointerException", "a Java stack trace"},
	{"goroutine ", "a Go panic trace"},
	{"ValidationError:", "an unhandled validation error"},
}

// probeValue is the value substituted into a path parameter. It is a plain
// string with no syntax in it: the point is to be a type mismatch, not a
// payload.
const probeValue = "vk-probe"

// Detect sends one benign mismatched request per route family.
func (c *VerboseErrors) Detect(ctx context.Context, env *check.Env) ([]finding.Finding, error) {
	ruleID := c.Meta().RuleID
	var out []finding.Finding
	probes := 0
	seen := map[string]bool{}

	for _, route := range env.Surface.RoutesWithParams() {
		if probes >= 12 {
			break
		}
		if !strings.EqualFold(route.Method, http.MethodGet) {
			continue
		}

		concrete := fillParams(route.Path, probeValue)
		if seen[concrete] {
			continue
		}
		seen[concrete] = true

		target, err := absURL(env, concrete)
		if err != nil {
			continue
		}

		req := identifiedRequest(ruleID, http.MethodGet, target, env,
			"probe: send a type-mismatched id and read the error response")
		resp, err := send(ctx, env, req)
		probes++
		if err != nil {
			continue
		}

		// Only an error response is interesting here.
		if resp.Status < 400 {
			continue
		}

		var matched []string
		for _, sig := range errorSignatures {
			if strings.Contains(resp.Body, sig.needle) {
				matched = append(matched, sig.means)
			}
		}
		if len(matched) == 0 {
			continue
		}

		severity := finding.SeverityMedium
		debugger := strings.Contains(resp.Body, "Werkzeug Debugger") || strings.Contains(resp.Body, "console-ready")
		if debugger {
			// An interactive debugger on a reachable endpoint is not an
			// information leak, it is remote code execution.
			severity = finding.SeverityCritical
		}

		f := finding.Finding{
			RuleID:     ruleID,
			Title:      fmt.Sprintf("Error response from %s discloses internal detail", route.Endpoint()),
			Category:   finding.CategoryMisconfiguration,
			CWE:        "CWE-209",
			Severity:   severity,
			Confidence: finding.ConfidenceConfirmed,
			Source:     finding.SourceDAST,
			Location:   locationFor(route, env.RepoRev),
			Evidence: finding.Evidence{
				Summary: fmt.Sprintf(
					"Requesting %s with a plain string where the handler expects a different type returned %d, "+
						"and the response body contains %s. Error detail like this tells an attacker the framework, "+
						"the library versions and the filesystem layout, which is how they work out what else to try.",
					concrete, resp.Status, strings.Join(dedupeStrings(matched), " and ")),
				Request:     evidenceRequest(req),
				Observed:    fmt.Sprintf("%d with internal detail in the body", resp.Status),
				Expected:    "a generic error message, with the detail logged server-side",
				Snippet:     firstLines(resp.Body, 6, 500),
				EvidenceKey: "verbose-error:" + route.Endpoint(),
			},
			Remediation: finding.Remediation{
				Guidance: errorGuidance(debugger),
				RootCauseHint: "The error handler forwards the exception to the caller instead of logging it, " +
					"usually because debug mode is on.",
				FixableByGiver: true,
			},
			Status: finding.StatusOpen,
		}
		f.AssignID()
		f.Reproduction = &finding.Reproduction{
			Kind:    finding.ReproHTTP,
			Command: "vibekiller reproduce " + f.FindingID,
			Steps: []string{
				fmt.Sprintf("Send GET %s.", concrete),
				fmt.Sprintf("The response is %d and its body contains internal detail.", resp.Status),
			},
			ArtifactPath: writeReproArtifact(env, f.FindingID, []httpx.Request{req}, nil),
		}

		out = append(out, f)
	}

	return out, nil
}

func errorGuidance(debugger bool) string {
	base := "Catch unhandled errors in one place, log the exception with its stack on the server, and return a " +
		"generic message with a correlation id to the caller."
	if debugger {
		return "Turn off debug mode on this instance immediately. The interactive debugger is reachable, and it " +
			"allows arbitrary code execution on the server by anyone who can load that page. " + base
	}
	return base
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// firstLines returns the first n lines of a body, bounded in total length, for
// use as a snippet.
func firstLines(body string, n, maxLen int) string {
	lines := strings.Split(body, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	out := strings.TrimSpace(strings.Join(lines, "\n"))
	if len(out) > maxLen {
		out = out[:maxLen] + "..."
	}
	return out
}
