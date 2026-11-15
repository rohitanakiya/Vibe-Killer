// Package endpointchecks holds the checks that exercise a running instance.
//
// Every check here is read-only by default and works exclusively against
// seeded data: the identities come from seeded_users and the records it reads
// are the canary_records the operator created for the purpose. That is what
// lets a finding be marked confirmed without any real record having been
// touched.
//
// None of these checks sends a payload intended to cause an effect. They send
// ordinary requests and compare what comes back, which is enough to establish
// whether an authorization boundary exists.
package endpointchecks

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/rohitanakiya/Vibe-Killer/internal/check"
	"github.com/rohitanakiya/Vibe-Killer/internal/config"
	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
	"github.com/rohitanakiya/Vibe-Killer/internal/httpx"
	"github.com/rohitanakiya/Vibe-Killer/internal/surface"
)

// absURL builds an absolute URL for a path on the target, applying the
// configured base path for apps mounted under a sub-path.
func absURL(env *check.Env, path string) (string, error) {
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

// fillParams substitutes a concrete value into a route template's parameters.
//
// Only the last parameter is given the record id; earlier ones get the same
// value, which is the best a mapper-driven check can do for a nested route.
// A route whose earlier parameters need different values will simply not
// return the canary, and the check reports nothing rather than guessing.
func fillParams(path, value string) string {
	out := path
	for {
		start := strings.IndexByte(out, '{')
		if start < 0 {
			break
		}
		end := strings.IndexByte(out[start:], '}')
		if end < 0 {
			break
		}
		out = out[:start] + value + out[start+end+1:]
	}
	return out
}

// hasSingleParam reports whether a route takes exactly one path parameter,
// which is the shape a record-by-id route has.
func hasSingleParam(r surface.Route) bool { return len(r.PathParams) == 1 }

// authedRequest builds a request carrying a seeded user's credentials.
func authedRequest(ruleID, method, target string, u config.SeededUser, note string) (httpx.Request, error) {
	name, value, err := u.AuthHeader()
	if err != nil {
		return httpx.Request{}, err
	}
	return httpx.Request{
		RuleID:    ruleID,
		Method:    method,
		URL:       target,
		Headers:   map[string]string{name: value},
		AuthLabel: u.ID,
		Note:      note,
	}, nil
}

// anonRequest builds a request with no credentials at all.
func anonRequest(ruleID, method, target, note string) httpx.Request {
	return httpx.Request{
		RuleID:    ruleID,
		Method:    method,
		URL:       target,
		AuthLabel: "none",
		Note:      note,
	}
}

// identifiedRequest builds a request carrying a seeded identity when one is
// available, and an anonymous one otherwise.
//
// Checks that look at how a handler treats a value — injection, traversal,
// error disclosure — have to get past authentication first, because in a real
// application almost every interesting endpoint is behind it. Probing
// anonymously would reach the login wall and report that everything is fine,
// which is the worst kind of wrong answer. The identity used is a seeded
// throwaway account, so this is still a request the operator authorized.
func identifiedRequest(ruleID, method, target string, env *check.Env, note string) httpx.Request {
	for _, u := range env.Config.SeededUsers {
		name, value, err := u.AuthHeader()
		if err != nil {
			continue
		}
		return httpx.Request{
			RuleID:    ruleID,
			Method:    method,
			URL:       target,
			Headers:   map[string]string{name: value},
			AuthLabel: u.ID,
			Note:      note,
		}
	}
	return anonRequest(ruleID, method, target, note)
}

// evidenceRequest converts a sent request into the contract's evidence form.
//
// Headers are replaced with the redacted set, so the recorded evidence names
// the identity used without carrying its token.
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
		Body:    req.Body,
	}
}

// routesForResource returns the mapped routes that plausibly serve a canary's
// resource, most specific first.
//
// Matching is on the path, because a canary is declared as a resource name
// such as "order" and the route is "/api/orders/{id}". Singular and plural
// both match, and a route that takes exactly one parameter is preferred since
// that is the by-id shape.
func routesForResource(s *surface.Surface, resource string, methods ...string) []surface.Route {
	if s == nil {
		return nil
	}

	resource = strings.ToLower(strings.TrimSpace(resource))
	if resource == "" {
		return nil
	}
	singular := strings.TrimSuffix(resource, "s")

	wantMethod := map[string]bool{}
	for _, m := range methods {
		wantMethod[strings.ToUpper(m)] = true
	}

	var out []surface.Route
	for _, r := range s.Routes {
		if len(wantMethod) > 0 && !wantMethod[strings.ToUpper(r.Method)] {
			continue
		}
		if len(r.PathParams) == 0 {
			continue
		}

		lower := strings.ToLower(r.Path)
		matched := false
		for _, seg := range strings.Split(lower, "/") {
			if seg == "" || strings.HasPrefix(seg, "{") {
				continue
			}
			if seg == resource || seg == singular || seg == singular+"s" {
				matched = true
				break
			}
		}
		if !matched && !strings.Contains(lower, singular) {
			continue
		}
		out = append(out, r)
	}

	// Prefer the simplest matching route: one path parameter, shortest path.
	sort.SliceStable(out, func(i, j int) bool {
		si, sj := hasSingleParam(out[i]), hasSingleParam(out[j])
		if si != sj {
			return si
		}
		if len(out[i].PathParams) != len(out[j].PathParams) {
			return len(out[i].PathParams) < len(out[j].PathParams)
		}
		return len(out[i].Path) < len(out[j].Path)
	})
	return out
}

// pickProber returns a seeded user other than the owner, to act as the
// unauthorized caller.
func pickProber(env *check.Env, ownerID string) (config.SeededUser, bool) {
	for _, u := range env.Config.SeededUsers {
		if u.ID == ownerID {
			continue
		}
		if _, err := u.Token(); err != nil {
			continue
		}
		return u, true
	}
	return config.SeededUser{}, false
}

// locationFor builds a finding location that carries both the endpoint and the
// code position of its handler.
//
// Carrying both is what lets the reporter merge this dynamic finding with the
// static finding about the same handler: the static half knows the file and
// symbol, the dynamic half knows the route, and the merge key needs one of
// them to overlap.
func locationFor(r surface.Route, repoRev string) finding.Location {
	return finding.Location{
		Type:     finding.LocationEndpoint,
		Endpoint: r.Endpoint(),
		File:     r.File,
		Line:     r.Line,
		Symbol:   r.Handler,
		RepoRev:  repoRev,
	}
}

// bodyLooksLikeRecord reports whether a response plausibly carries a record
// rather than an error page or an empty collection.
//
// This matters because plenty of generated apps answer an unauthorized read
// with 200 and an empty body or a null, which is not a disclosure.
func bodyLooksLikeRecord(body string) bool {
	trimmed := strings.TrimSpace(body)
	if len(trimmed) < 3 {
		return false
	}
	switch trimmed {
	case "null", "[]", "{}", `""`, "0", "false":
		return false
	}
	return true
}

// writeReproArtifact stores a replayable .http file for a finding.
//
// Tokens are written as environment variable references rather than values, so
// the artifact can be attached to a ticket and still replayed by whoever has
// the seeded credentials.
func writeReproArtifact(env *check.Env, findingID string, requests []httpx.Request, notes []string) string {
	if env.Run == nil {
		return ""
	}

	var b strings.Builder
	b.WriteString("# Vibe Killer reproduction artifact\n")
	b.WriteString("# Replay with any .http client, or: vibekiller reproduce " + findingID + "\n")
	b.WriteString("# Token values are shown as environment variable references, never as values.\n")
	for _, n := range notes {
		b.WriteString("# " + n + "\n")
	}
	b.WriteString("\n")

	for i, req := range requests {
		if i > 0 {
			b.WriteString("###\n\n")
		}
		method := req.Method
		if method == "" {
			method = "GET"
		}
		fmt.Fprintf(&b, "%s %s\n", method, req.URL)

		names := make([]string, 0, len(req.Headers))
		for k := range req.Headers {
			names = append(names, k)
		}
		sort.Strings(names)

		for _, k := range names {
			value := req.Headers[k]
			// Replace the credential with the variable it came from.
			if u, ok := userByID(env, req.AuthLabel); ok {
				scheme := strings.TrimSpace(u.Scheme)
				if scheme == "" {
					scheme = "Bearer"
				}
				if strings.EqualFold(scheme, "cookie") || strings.EqualFold(scheme, "none") ||
					strings.EqualFold(scheme, "raw") {
					value = "{{$processEnv " + u.TokenEnv + "}}"
				} else {
					value = scheme + " {{$processEnv " + u.TokenEnv + "}}"
				}
			}
			fmt.Fprintf(&b, "%s: %s\n", k, value)
		}
		if req.AuthLabel == "none" {
			b.WriteString("# sent with no credentials\n")
		}
		if req.Note != "" {
			b.WriteString("# intent: " + req.Note + "\n")
		}
		if req.Body != "" {
			b.WriteString("\n" + req.Body + "\n")
		}
		b.WriteString("\n")
	}

	path, err := env.Run.WriteRepro(findingID, ".http", []byte(b.String()))
	if err != nil {
		env.Run.Errorf("could not write the reproduction artifact for %s: %v", findingID, err)
		return ""
	}
	return path
}

func userByID(env *check.Env, label string) (config.SeededUser, bool) {
	if label == "" || label == "none" {
		return config.SeededUser{}, false
	}
	return env.Config.User(label)
}

// send issues a request and tolerates a transport failure by returning nil.
//
// A check that cannot reach one endpoint should report nothing for it, not
// fail the whole check: a dev server that closes a connection mid-scan is
// ordinary.
func send(ctx context.Context, env *check.Env, req httpx.Request) (*httpx.Response, error) {
	resp, err := env.HTTP.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
