package endpointchecks

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rohitanakiya/Vibe-Killer/internal/check"
	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
	"github.com/rohitanakiya/Vibe-Killer/internal/httpx"
	"github.com/rohitanakiya/Vibe-Killer/internal/surface"
)

func init() { check.Register(&SSRFCanary{}) }

// SSRFCanary establishes whether an endpoint will fetch a URL the caller
// supplies, by asking it to fetch one that Vibe Killer is listening on.
//
// This is the cleanest proof in the whole tool. The classic way to test for
// server-side request forgery is to aim the application at a cloud metadata
// address and see what credentials come back — which means reading the
// operator's real credentials out of their real infrastructure to tell them a
// thing they could have been told without it.
//
// Instead, the canary is a listener Vibe Killer starts on loopback, on an
// ephemeral port, serving one random path. If a request arrives on that path,
// the application fetched a URL it was handed, and the finding is established
// completely: the server's network position is reachable by the caller.
// Nothing real was contacted and no credential was read.
//
// The listener belongs to this process and is shut down when the run ends.
type SSRFCanary struct{}

// Meta describes the check.
func (c *SSRFCanary) Meta() check.Meta {
	return check.Meta{
		RuleID:   "ssrf.internal-canary-fetch",
		Title:    "Endpoints that fetch a caller-supplied URL (proven with a local canary)",
		Layer:    check.LayerEndpoint,
		Category: finding.CategorySSRF,

		NeedsTarget:  true,
		NeedsSurface: true,
	}
}

// canaryListener is a local HTTP server that records the paths requested of it.
type canaryListener struct {
	srv  *http.Server
	addr string

	mu  sync.Mutex
	hit map[string]canaryHit
}

// canaryHit is one request the canary received.
type canaryHit struct {
	At        time.Time
	UserAgent string
	RemoteIP  string
}

// startCanary binds a listener on loopback and begins serving.
//
// It binds to 127.0.0.1 explicitly rather than to all interfaces: a probe
// endpoint that anything on the network could reach would be a service Vibe
// Killer had opened on the operator's machine, which is the opposite of the
// promise it makes.
func startCanary() (*canaryListener, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("starting the canary listener: %w", err)
	}

	c := &canaryListener{
		addr: ln.Addr().String(),
		hit:  map[string]canaryHit{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)

		c.mu.Lock()
		c.hit[strings.TrimPrefix(r.URL.Path, "/")] = canaryHit{
			At: time.Now(), UserAgent: r.Header.Get("User-Agent"), RemoteIP: ip,
		}
		c.mu.Unlock()

		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("vibekiller-canary\n"))
	})

	c.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = c.srv.Serve(ln) }()

	return c, nil
}

// URLFor returns the canary URL for a nonce.
func (c *canaryListener) URLFor(nonce string) string {
	return "http://" + c.addr + "/" + nonce
}

// Hit reports whether the canary received a request for a nonce.
func (c *canaryListener) Hit(nonce string) (canaryHit, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	h, ok := c.hit[nonce]
	return h, ok
}

// Close shuts the listener down.
func (c *canaryListener) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return c.srv.Shutdown(ctx)
}

// nonce returns a random path segment, so a hit can only have come from the
// probe that was just sent.
func nonce() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// urlParamNames are the query parameters that commonly carry a URL to fetch.
var urlParamNames = []string{"url", "uri", "src", "target", "link", "feed", "image", "page", "endpoint", "webhook"}

// fetchRouteHints are path segments that suggest a handler fetches a remote
// resource. RAG and agent features are the common source of these.
var fetchRouteHints = []string{
	"import", "fetch", "proxy", "preview", "thumbnail", "screenshot", "render",
	"url", "link", "webhook", "callback", "ingest", "scrape", "crawl",
	"download", "pdf", "convert", "embed", "oembed", "unfurl", "avatar",
	"document", "source", "remote", "load",
}

func looksLikeFetchRoute(path string) bool {
	lower := strings.ToLower(path)
	for _, h := range fetchRouteHints {
		if strings.Contains(lower, h) {
			return true
		}
	}
	return false
}

// maxSSRFProbes bounds the request count.
const maxSSRFProbes = 24

// Detect asks candidate endpoints to fetch the canary.
func (c *SSRFCanary) Detect(ctx context.Context, env *check.Env) ([]finding.Finding, error) {
	ruleID := c.Meta().RuleID

	candidates := c.candidates(env)
	if len(candidates) == 0 {
		env.Run.Log("check.note", map[string]any{
			"rule_id": ruleID,
			"note": "no mapped route looks like it fetches a remote resource, so the canary " +
				"was not started and nothing was probed",
		})
		return nil, nil
	}

	canary, err := startCanary()
	if err != nil {
		return nil, err
	}
	// The listener is this process's, and it goes away with the run.
	env.Run.Defer("shut down the SSRF canary listener", canary.Close)
	env.Run.Log("canary.started", map[string]any{
		"rule_id": ruleID,
		"addr":    canary.addr,
		"note":    "loopback only, ephemeral port, serves one random path per probe",
	})

	var out []finding.Finding
	probes := 0

	for _, cand := range candidates {
		if probes >= maxSSRFProbes {
			env.Run.Log("check.note", map[string]any{
				"rule_id": ruleID,
				"note":    fmt.Sprintf("stopped after %d probes to keep the request count bounded", maxSSRFProbes),
			})
			break
		}

		n := nonce()
		canaryURL := canary.URLFor(n)

		req, err := cand.request(env, ruleID, canaryURL)
		if err != nil {
			continue
		}
		// The probe carries a URL, not a statement, but it is still assembled
		// at runtime and still gets checked.
		if err := assertInertProbe(ruleID, n); err != nil {
			return nil, err
		}

		resp, err := send(ctx, env, req)
		probes++
		if err != nil {
			continue
		}

		// The fetch may be queued rather than synchronous, so allow a short
		// grace period before concluding it did not happen.
		hit, got := canary.Hit(n)
		if !got {
			hit, got = c.waitForHit(ctx, canary, n)
		}
		if !got {
			continue
		}

		f := c.finding(env, cand, req, resp.Status, canaryURL, hit)
		out = append(out, f)

		env.Run.Log("canary.hit", map[string]any{
			"rule_id":    ruleID,
			"route":      cand.route.Endpoint(),
			"from_ip":    hit.RemoteIP,
			"user_agent": hit.UserAgent,
		})
	}

	return out, nil
}

// waitForHit polls briefly for an asynchronous fetch.
func (c *SSRFCanary) waitForHit(ctx context.Context, canary *canaryListener, n string) (canaryHit, bool) {
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(150 * time.Millisecond)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return canaryHit{}, false
		case <-deadline.C:
			return canaryHit{}, false
		case <-tick.C:
			if hit, ok := canary.Hit(n); ok {
				return hit, true
			}
		}
	}
}

// candidate is one way of handing a URL to one route.
type candidate struct {
	route surface.Route

	// param is the query parameter name, for a GET candidate.
	param string

	// body is the JSON body template, for a POST candidate.
	bodyField string
}

// request builds the probe request for this candidate.
func (c candidate) request(env *check.Env, ruleID, canaryURL string) (httpx.Request, error) {
	if c.bodyField != "" {
		target, err := absURL(env, c.route.Path)
		if err != nil {
			return httpx.Request{}, err
		}
		return httpx.Request{
			RuleID:    ruleID,
			Method:    strings.ToUpper(c.route.Method),
			URL:       target,
			Headers:   map[string]string{"Content-Type": "application/json"},
			Body:      fmt.Sprintf(`{%q:%q}`, c.bodyField, canaryURL),
			AuthLabel: "none",
			Note:      "probe: ask the endpoint to fetch a local canary URL",
		}, nil
	}

	target, err := absURL(env, c.route.Path)
	if err != nil {
		return httpx.Request{}, err
	}
	sep := "?"
	if strings.Contains(target, "?") {
		sep = "&"
	}
	return httpx.Request{
		RuleID:    ruleID,
		Method:    http.MethodGet,
		URL:       target + sep + c.param + "=" + canaryURL,
		AuthLabel: "none",
		Note:      "probe: ask the endpoint to fetch a local canary URL",
	}, nil
}

// how describes the candidate for a finding's evidence.
func (c candidate) how() string {
	if c.bodyField != "" {
		return fmt.Sprintf("the %q field of the JSON body", c.bodyField)
	}
	return fmt.Sprintf("the %q query parameter", c.param)
}

// candidates builds the probe list.
//
// GET routes are probed unconditionally: a GET cannot change state whatever
// the handler does. A body-carrying method can, so those candidates are only
// built when the operator has opened the mutating gates. The check does not
// authorize itself — CanRun already decided it may run at all — it is
// declining to use part of its own repertoire, and it records that it did.
func (c *SSRFCanary) candidates(env *check.Env) []candidate {
	var out []candidate
	allowMutating := env.Config.MutatingChecksAllowed()
	skippedMutating := 0

	for _, route := range env.Surface.Routes {
		if !looksLikeFetchRoute(route.Path) {
			continue
		}
		// A route with a path parameter needs a value for it, and the URL goes
		// in a query parameter or a body, so those are skipped here.
		if len(route.PathParams) > 0 {
			continue
		}

		if strings.EqualFold(route.Method, http.MethodGet) {
			for _, p := range urlParamNames {
				out = append(out, candidate{route: route, param: p})
			}
			continue
		}

		if !surface.IsMutating(route.Method) {
			continue
		}
		if !allowMutating {
			skippedMutating++
			continue
		}
		for _, field := range urlParamNames {
			out = append(out, candidate{route: route, bodyField: field})
		}
	}

	if skippedMutating > 0 {
		env.Run.Log("check.note", map[string]any{
			"rule_id": c.Meta().RuleID,
			"note": fmt.Sprintf("%d route(s) that fetch a URL take a body-carrying method, so probing "+
				"them could change state; they were skipped because dynamic.non_destructive is true. "+
				"Set it false and dynamic.disposable_env true to include them.", skippedMutating),
		})
	}

	return out
}

// finding builds the confirmed SSRF finding.
func (c *SSRFCanary) finding(
	env *check.Env, cand candidate, req httpx.Request, status int, canaryURL string, hit canaryHit,
) finding.Finding {
	loc := locationFor(cand.route, env.RepoRev)

	f := finding.Finding{
		RuleID: c.Meta().RuleID,
		Title: fmt.Sprintf("%s fetches a URL supplied by the caller",
			cand.route.Endpoint()),
		Category:   finding.CategorySSRF,
		CWE:        "CWE-918",
		Severity:   finding.SeverityHigh,
		Confidence: finding.ConfidenceConfirmed,
		Source:     finding.SourceDAST,
		Location:   loc,
		Evidence: finding.Evidence{
			Summary: fmt.Sprintf(
				"A URL was passed to this endpoint in %s, pointing at a listener Vibe Killer had just "+
					"started on loopback with a random one-time path. The listener received a request for "+
					"that exact path from %s, so the application fetched it. Requests therefore originate "+
					"from inside your network under the caller's control, which reaches internal services "+
					"and cloud instance metadata that are not exposed externally. "+
					"No real address was contacted to establish this.",
				cand.how(), hit.RemoteIP),
			Request:  evidenceRequest(req),
			Observed: fmt.Sprintf("the endpoint returned %d and the canary listener was hit by %s (user agent: %q)", status, hit.RemoteIP, hit.UserAgent),
			Expected: "the URL rejected because its host is not on an allowlist, and the canary never contacted",
			// Keyed on the route and how the URL was delivered, so the same
			// weakness keeps its identity between runs.
			EvidenceKey: "ssrf-canary:" + cand.route.Endpoint() + ":" + cand.paramKey(),
		},
		Remediation: finding.Remediation{
			Guidance: "Validate the URL against an allowlist of hosts, resolve the name and reject " +
				"addresses that are loopback, link-local or private, and re-check after every redirect. " +
				"Checking the string before resolution is not enough, because a name you allow can resolve " +
				"to an internal address, and a redirect can move the destination after the check.",
			RootCauseHint: "A URL from the request is fetched without checking the address it resolves to, " +
				"so the server's network position is lent to the caller.",
			References: []string{
				"https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
			},
			FixableByGiver: true,
		},
		Status: finding.StatusOpen,
	}
	f.AssignID()

	f.Reproduction = &finding.Reproduction{
		Kind:    finding.ReproHTTP,
		Command: "vibekiller reproduce " + f.FindingID,
		Steps: []string{
			"Start a listener on loopback, for example: python -m http.server 8099 --bind 127.0.0.1",
			fmt.Sprintf("Send the request in the artifact, with %s set to http://127.0.0.1:8099/probe", cand.how()),
			"The listener logs a request for /probe, which only the application could have made.",
		},
		ArtifactPath: writeReproArtifact(env, f.FindingID, []httpx.Request{req},
			[]string{
				"The URL in this request pointed at a local listener, not at any real address.",
				"A fixed application rejects the host and never makes the request.",
			}),
	}

	return f
}

// paramKey identifies how the URL was delivered, for the evidence key.
func (c candidate) paramKey() string {
	if c.bodyField != "" {
		return "body:" + c.bodyField
	}
	return "query:" + c.param
}
