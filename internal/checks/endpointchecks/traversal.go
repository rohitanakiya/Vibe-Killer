package endpointchecks

import (
	"context"
	"fmt"
	"net/http"
	"path"
	"regexp"
	"strings"

	"github.com/rohitanakiya/Vibe-Killer/internal/check"
	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
	"github.com/rohitanakiya/Vibe-Killer/internal/httpx"
	"github.com/rohitanakiya/Vibe-Killer/internal/surface"
)

func init() { check.Register(&PathEscape{}) }

// PathEscape establishes whether a path parameter is confined to the directory
// it is supposed to stay inside.
//
// It never reads a file. The probe asks for a filename that is guaranteed not
// to exist — a random nonce — once plainly and once behind traversal
// segments. What distinguishes a confined handler from an unconfined one is
// not the file's contents but whether the request is rejected before anything
// is opened:
//
//   - a confined handler resolves the path, sees that it left the root, and
//     rejects it, typically with a 400;
//   - an unconfined handler joins the path and tries to open it, so it reports
//     that the file is missing, typically with a 404.
//
// That difference is the finding. Where the application also discloses the
// resolved path in its error, the escape is visible directly and the finding
// is confirmed; where it does not, the status differential alone supports
// "likely", and the check says which it is rather than claiming the stronger
// result.
type PathEscape struct{}

// Meta describes the check.
func (c *PathEscape) Meta() check.Meta {
	return check.Meta{
		RuleID:   "traversal.path-escape",
		Title:    "Path parameters not confined to their directory (reads nothing)",
		Layer:    check.LayerEndpoint,
		Category: finding.CategoryBrokenAccessControl,

		NeedsTarget:  true,
		NeedsSurface: true,
	}
}

// traversalPrefix is the escape sequence. Three levels is enough to leave any
// plausible upload directory and is not adjustable, because a deeper probe
// would not establish anything a shallower one does not.
const traversalPrefix = "../../../"

// maxTraversalProbes bounds the request count.
const maxTraversalProbes = 16

// fileRouteHints are path segments that suggest a handler serves a file.
var fileRouteHints = []string{
	"file", "files", "download", "attachment", "attachments", "upload",
	"uploads", "asset", "assets", "media", "image", "images", "document",
	"documents", "export", "report", "avatar", "static", "content", "blob",
}

// looksLikeFileRoute reports whether a route plausibly serves a file.
//
// Matching is per path segment, not by substring. A substring test looks fine
// until it reports /api/profiles/{id} as a file route, because "profiles"
// contains "file" — which is a finding about path traversal raised against an
// endpoint that never touches the filesystem.
func looksLikeFileRoute(route surface.Route) bool {
	for _, seg := range strings.Split(strings.ToLower(route.Path), "/") {
		if seg == "" || strings.HasPrefix(seg, "{") {
			continue
		}
		for _, h := range fileRouteHints {
			if seg == h {
				return true
			}
		}
	}

	// A parameter named after a filename is as good a signal as the path.
	for _, p := range route.PathParams {
		switch strings.ToLower(p) {
		case "name", "filename", "file", "path", "filepath", "key", "asset", "doc":
			return true
		}
	}
	return false
}

// disclosedPathRe finds an absolute filesystem path in an error response,
// POSIX or Windows. This is what lets the check show the escape directly.
//
// The POSIX branch allows a single segment, because the interesting case is
// exactly the one where traversal reached the root: a handler that resolves
// /srv/app/uploads/../../../name reports /name, which a pattern demanding two
// or more segments would miss. Matches are filtered by whether they contain
// the probe name, so loosening this cannot pick up an unrelated path.
var disclosedPathRe = regexp.MustCompile(`(?:[A-Za-z]:\\[^\s"'<>|?*]+|/(?:[\w.\-]+/)*[\w.\-]+)`)

// Detect probes each file-serving route with a plain and a traversed filename.
func (c *PathEscape) Detect(ctx context.Context, env *check.Env) ([]finding.Finding, error) {
	ruleID := c.Meta().RuleID

	var out []finding.Finding
	probes := 0
	seen := map[string]bool{}

	for _, route := range env.Surface.Routes {
		if probes >= maxTraversalProbes {
			env.Run.Log("check.note", map[string]any{
				"rule_id": ruleID,
				"note":    fmt.Sprintf("stopped after %d probes to keep the request count bounded", maxTraversalProbes),
			})
			break
		}
		// Read-only: GET alone, so nothing can be written wherever the path
		// ends up pointing.
		if !strings.EqualFold(route.Method, http.MethodGet) || route.Mutating {
			continue
		}
		if len(route.PathParams) == 0 || !looksLikeFileRoute(route) {
			continue
		}
		if seen[route.Path] {
			continue
		}
		seen[route.Path] = true

		f, sent, err := c.probeRoute(ctx, env, route)
		probes += sent
		if err != nil {
			env.Run.Log("check.note", map[string]any{
				"rule_id": ruleID, "route": route.Endpoint(),
				"note": "probe could not complete: " + err.Error(),
			})
			continue
		}
		if f != nil {
			out = append(out, *f)
		}
	}

	return out, nil
}

// probeRoute runs the plain-then-traversed pair for one route.
func (c *PathEscape) probeRoute(ctx context.Context, env *check.Env, route surface.Route) (*finding.Finding, int, error) {
	ruleID := c.Meta().RuleID
	sent := 0

	// A name that cannot exist, so neither request can read anything.
	probeName := "vk-probe-" + nonce()
	traversed := traversalPrefix + probeName

	if err := assertInertProbes(ruleID, probeName, traversed); err != nil {
		return nil, sent, err
	}

	plainURL, err := absURL(env, fillParams(route.Path, probeName))
	if err != nil {
		return nil, sent, err
	}
	traversedURL, err := absURL(env, fillParams(route.Path, traversed))
	if err != nil {
		return nil, sent, err
	}

	// Step 1: the plain name. This establishes how the handler answers a file
	// that simply is not there, which is the baseline the traversal form is
	// compared against.
	plainReq := identifiedRequest(ruleID, http.MethodGet, plainURL, env,
		"baseline: a filename that does not exist")
	plainResp, err := send(ctx, env, plainReq)
	sent++
	if err != nil {
		return nil, sent, err
	}

	// A 200 for a file that cannot exist means the handler ignores the
	// parameter, so the comparison would be meaningless.
	if plainResp.Status == http.StatusOK {
		env.Run.Log("check.note", map[string]any{
			"rule_id": ruleID, "route": route.Endpoint(),
			"note": "the baseline returned 200 for a filename that cannot exist, so this handler " +
				"does not use the parameter as a path; no conclusion drawn",
		})
		return nil, sent, nil
	}

	// Step 2: the same name behind traversal segments.
	traversedReq := identifiedRequest(ruleID, http.MethodGet, traversedURL, env,
		"probe: the same non-existent filename behind ../ segments")
	traversedResp, err := send(ctx, env, traversedReq)
	sent++
	if err != nil {
		return nil, sent, err
	}

	// The strongest evidence: the handler disclosed where it actually looked.
	plainDir := disclosedDir(plainResp.Body, probeName)
	traversedDir := disclosedDir(traversedResp.Body, probeName)

	escaped := plainDir != "" && traversedDir != "" && plainDir != traversedDir
	if escaped {
		return c.confirmedFinding(env, route, plainReq, traversedReq,
			plainResp.Status, traversedResp.Status, plainDir, traversedDir), sent, nil
	}

	// Otherwise fall back to the status differential. A handler that confines
	// the path rejects the traversal form outright; one that does not treats
	// it as just another missing file.
	rejected := traversedResp.Status == http.StatusBadRequest ||
		traversedResp.Status == http.StatusForbidden
	if rejected {
		// Correct behaviour: nothing to report.
		return nil, sent, nil
	}

	if traversedResp.Status == plainResp.Status {
		return c.likelyFinding(env, route, plainReq, traversedReq, plainResp.Status), sent, nil
	}

	env.Run.Log("check.note", map[string]any{
		"rule_id": ruleID, "route": route.Endpoint(),
		"note": fmt.Sprintf("the traversal form returned %d where the plain form returned %d, which is "+
			"neither a clear rejection nor a clear pass-through; no conclusion drawn",
			traversedResp.Status, plainResp.Status),
	})
	return nil, sent, nil
}

// disclosedDir pulls the directory of a disclosed path mentioning the probe
// name out of an error response.
func disclosedDir(body, probeName string) string {
	if !strings.Contains(body, probeName) {
		return ""
	}
	for _, m := range disclosedPathRe.FindAllString(body, -1) {
		if !strings.Contains(m, probeName) {
			continue
		}
		normalized := strings.ReplaceAll(m, `\`, "/")
		return path.Dir(normalized)
	}
	return ""
}

func (c *PathEscape) confirmedFinding(
	env *check.Env, route surface.Route,
	plainReq, traversedReq httpx.Request,
	plainStatus, traversedStatus int,
	plainDir, traversedDir string,
) *finding.Finding {
	f := finding.Finding{
		RuleID:     c.Meta().RuleID,
		Title:      fmt.Sprintf("Path parameter escapes its directory in %s", route.Endpoint()),
		Category:   finding.CategoryBrokenAccessControl,
		CWE:        "CWE-22",
		Severity:   finding.SeverityHigh,
		Confidence: finding.ConfidenceConfirmed,
		Source:     finding.SourceDAST,
		Location:   locationFor(route, env.RepoRev),
		Evidence: finding.Evidence{
			Summary: fmt.Sprintf(
				"The same non-existent filename was requested twice, plainly and behind ../ segments. "+
					"The handler's own error reported looking in %s for the plain name and in %s for the "+
					"traversed one, so the parameter is joined into the path without being resolved and "+
					"checked against the directory it must stay inside. A caller chooses which directory "+
					"the server reads from. No file was read to establish this: the name does not exist.",
				plainDir, traversedDir),
			Request:     evidenceRequest(traversedReq),
			Observed:    fmt.Sprintf("%d, and the error named a path in %s, outside %s", traversedStatus, traversedDir, plainDir),
			Expected:    "400 Bad Request, with the path rejected before anything is opened",
			EvidenceKey: "traversal:" + route.Endpoint(),
		},
		Remediation: finding.Remediation{
			Guidance: "Resolve the joined path and confirm it is still inside the intended root before " +
				"opening it, or take a database key instead of a filename. Stripping \"../\" is not " +
				"sufficient, because percent-encoding, overlong UTF-8 and symlinks all reintroduce it; " +
				"resolving first and comparing afterwards is what holds.",
			RootCauseHint: "The path is joined without being resolved, so the directory it is supposed " +
				"to be confined to is only a prefix by convention.",
			FixableByGiver: true,
		},
		Status: finding.StatusOpen,
	}
	f.AssignID()
	f.Reproduction = c.repro(env, &f, route, plainReq, traversedReq, plainStatus, traversedStatus)
	return &f
}

func (c *PathEscape) likelyFinding(
	env *check.Env, route surface.Route,
	plainReq, traversedReq httpx.Request,
	status int,
) *finding.Finding {
	f := finding.Finding{
		RuleID:   c.Meta().RuleID,
		Title:    fmt.Sprintf("Path parameter may not be confined in %s", route.Endpoint()),
		Category: finding.CategoryBrokenAccessControl,
		CWE:      "CWE-22",
		Severity: finding.SeverityMedium,
		// Not confirmed. The handler treated the traversal form as an ordinary
		// missing file rather than rejecting it, which is how an unconfined
		// handler behaves — but it never said where it looked, so the escape
		// was not observed. Claiming confirmed here would be claiming more
		// than was seen.
		Confidence: finding.ConfidenceLikely,
		Source:     finding.SourceDAST,
		Location:   locationFor(route, env.RepoRev),
		Evidence: finding.Evidence{
			Summary: fmt.Sprintf(
				"The same non-existent filename was requested plainly and behind ../ segments, and the "+
					"handler answered both with %d. A handler that resolves the path and checks it against "+
					"its root rejects the traversed form outright, usually with a 400; answering it as just "+
					"another missing file is what an unconfined handler does. The escape itself was not "+
					"observed, because this application does not disclose the path it looked in, so confirm "+
					"it by reading the handler before treating it as proven.",
				status),
			Request:     evidenceRequest(traversedReq),
			Observed:    fmt.Sprintf("%d for both the plain and the traversed filename", status),
			Expected:    "400 Bad Request for the traversed filename",
			EvidenceKey: "traversal-differential:" + route.Endpoint(),
		},
		Remediation: finding.Remediation{
			Guidance: "Resolve the joined path and confirm it is still inside the intended root before " +
				"opening it, and reject anything that is not with a 400 rather than letting it fall " +
				"through to a not-found.",
			RootCauseHint:  "The path is probably joined without being resolved and checked.",
			FixableByGiver: true,
		},
		Status: finding.StatusOpen,
	}
	f.AssignID()
	f.Reproduction = c.repro(env, &f, route, plainReq, traversedReq, status, status)
	return &f
}

func (c *PathEscape) repro(
	env *check.Env, f *finding.Finding, route surface.Route,
	plainReq, traversedReq httpx.Request,
	plainStatus, traversedStatus int,
) *finding.Reproduction {
	return &finding.Reproduction{
		Kind:    finding.ReproHTTP,
		Command: "vibekiller reproduce " + f.FindingID,
		Steps: []string{
			fmt.Sprintf("Request a filename that does not exist. It returns %d.", plainStatus),
			fmt.Sprintf("Request the same name behind ../../../. It returns %d.", traversedStatus),
			"A handler that resolves and checks the path rejects the second with a 400.",
		},
		ArtifactPath: writeReproArtifact(env, f.FindingID,
			[]httpx.Request{plainReq, traversedReq},
			[]string{
				"Both filenames are random and do not exist, so neither request reads a file.",
				"The two differ only in the leading ../ segments.",
			}),
	}
}

// Reproduce re-runs the differential for one finding.
func (c *PathEscape) Reproduce(ctx context.Context, env *check.Env, f finding.Finding) (check.Result, error) {
	if f.Evidence.Request == nil || f.Evidence.Request.Path == "" {
		return check.Result{}, fmt.Errorf("this finding carries no recorded request to replay")
	}

	ruleID := c.Meta().RuleID

	// Rebuild both halves from the route, with a fresh nonce, rather than
	// replaying the stored path: the stored nonce is from the original run and
	// re-sending it would prove nothing new.
	endpoint := f.Location.Endpoint
	routePath := endpoint
	if i := strings.IndexByte(endpoint, ' '); i >= 0 {
		routePath = endpoint[i+1:]
	}

	probeName := "vk-probe-" + nonce()
	traversed := traversalPrefix + probeName
	if err := assertInertProbes(ruleID, probeName, traversed); err != nil {
		return check.Result{}, err
	}

	plainURL, err := absURL(env, fillParams(routePath, probeName))
	if err != nil {
		return check.Result{}, err
	}
	traversedURL, err := absURL(env, fillParams(routePath, traversed))
	if err != nil {
		return check.Result{}, err
	}

	plainResp, err := send(ctx, env, identifiedRequest(ruleID, http.MethodGet, plainURL, env, "reproduction baseline"))
	if err != nil {
		return check.Result{}, err
	}
	traversedReq := identifiedRequest(ruleID, http.MethodGet, traversedURL, env, "reproduction probe")
	traversedResp, err := send(ctx, env, traversedReq)
	if err != nil {
		return check.Result{}, err
	}

	rejected := traversedResp.Status == http.StatusBadRequest ||
		traversedResp.Status == http.StatusForbidden

	if rejected {
		return check.Result{
			Reproduced: false,
			Detail: fmt.Sprintf("Not reproducible: the traversed filename is now rejected with %d, "+
				"while a plain missing filename returns %d. The path is being resolved and checked.",
				traversedResp.Status, plainResp.Status),
			Evidence: finding.Evidence{
				Summary:  "The traversal form is now rejected before anything is opened.",
				Request:  evidenceRequest(traversedReq),
				Observed: fmt.Sprintf("%d", traversedResp.Status),
				Expected: "400 Bad Request",
			},
		}, nil
	}

	return check.Result{
		Reproduced: true,
		Detail: fmt.Sprintf("Still reproducible: the traversed filename returns %d, the same as a plain "+
			"missing filename, so it is not being rejected.", traversedResp.Status),
		Evidence: finding.Evidence{
			Summary:  "The traversal form is still treated as an ordinary missing file.",
			Request:  evidenceRequest(traversedReq),
			Observed: fmt.Sprintf("%d for both forms", traversedResp.Status),
			Expected: "400 Bad Request for the traversed filename",
		},
	}, nil
}
