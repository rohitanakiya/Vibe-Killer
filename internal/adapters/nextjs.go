package adapters

import (
	"context"
	"path"
	"regexp"
	"strings"

	"github.com/rohitanakiya/Vibe-Killer/internal/surface"
)

// Next.js route extraction.
//
// Next.js is the one framework here whose routes are not in the source at all:
// the path is the file's location on disk and the methods are the names of the
// functions it exports. Nothing a regex can find in a file says where that
// file is served, which is why this reads the tree rather than the text, and
// why the adapter detected `next` for a long time while mapping zero routes.
//
// Two routers, which a project may use at once:
//
//	app/api/orders/[id]/route.ts   ->  /api/orders/{id}, with the methods
//	                                   taken from the exported GET, POST,
//	                                   PATCH, ... functions
//	pages/api/legacy/[id].ts       ->  /api/legacy/{id}, one handler for
//	                                   every method
//
// Only API routes are mapped. A `page.tsx` is a rendered page, and the checks
// that consume this surface probe for broken access control and injection --
// padding the route list with pages would give them nothing to act on and
// make a scan look broader than it is.
//
// The Pages Router does not declare its methods: one handler serves them all
// and reads `req.method` to decide. Where the source states which it accepts,
// that is read; where it does not, the route is GET alone. Assuming otherwise
// would hand the endpoint layer a mutating route nothing promised, which is
// the same rule the Django extractor follows and for the same reason.

var (
	// export async function GET(...) / export function POST(...) and
	// export const GET = ...
	nextMethodExportRe = regexp.MustCompile(
		`(?m)^\s*export\s+(?:async\s+)?(?:function\s+|const\s+|let\s+|var\s+)([A-Z]+)\b`)

	// req.method === 'POST', with either quote and either comparison.
	nextMethodCompareRe = regexp.MustCompile(
		`(?i)\breq(?:uest)?\s*\.\s*method\s*[!=]==?\s*['"]([A-Za-z]+)['"]`)

	// A dynamic segment: [id], [...slug] or [[...slug]].
	nextDynamicRe = regexp.MustCompile(`^\[+\.{0,3}([^\]]+)\]+$`)
)

// nextHTTPMethods are the export names the App Router treats as handlers.
var nextHTTPMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "PATCH": true,
	"DELETE": true, "HEAD": true, "OPTIONS": true,
}

// nextRouteFileNames are the App Router's handler filenames.
var nextRouteFileNames = map[string]bool{
	"route.ts": true, "route.js": true, "route.tsx": true, "route.jsx": true,
	"route.mts": true, "route.mjs": true,
}

// nextRoutes enumerates a Next.js project's API routes, or returns nil when
// the tree holds neither router.
func nextRoutes(ctx context.Context, repoRoot string, exclude []string) ([]surface.Route, error) {
	var routes []surface.Route

	err := WalkSource(ctx, repoRoot, nodeExts, exclude, func(f SourceFile) error {
		kind, urlPath, ok := nextPathFor(f.Path)
		if !ok {
			return nil
		}

		whole := strings.Join(f.Lines, "\n")
		tmpl, params := NormalizePathTemplate(urlPath)
		if tmpl == "" {
			return nil
		}

		var methods []string
		handler := ""

		switch kind {
		case "app":
			for _, m := range nextMethodExportRe.FindAllStringSubmatch(whole, -1) {
				if nextHTTPMethods[m[1]] {
					methods = appendUnique(methods, m[1])
				}
			}
			if len(methods) == 0 {
				// A route.ts exporting no handler serves nothing. Reporting a
				// route for it would invent an endpoint.
				return nil
			}

		case "pages":
			for _, m := range nextMethodCompareRe.FindAllStringSubmatch(whole, -1) {
				if up := strings.ToUpper(m[1]); nextHTTPMethods[up] {
					methods = appendUnique(methods, up)
				}
			}
			if len(methods) == 0 {
				methods = []string{"GET"}
			}
			handler = "default"
		}

		for _, method := range methods {
			name := handler
			if name == "" {
				name = method
			}
			routes = append(routes, surface.Route{
				Method:     method,
				Path:       tmpl,
				PathParams: params,
				File:       f.Path,
				Line:       nextHandlerLine(f, kind, method),
				Handler:    name,
				Mutating:   surface.IsMutating(method),
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return routes, nil
}

// nextPathFor turns a repo-relative file path into the URL it is served at.
//
// It returns the router that owns the file ("app" or "pages"), the URL path,
// and whether the file is an API route at all.
func nextPathFor(file string) (string, string, bool) {
	parts := strings.Split(path.Clean(filepathToSlash(file)), "/")

	// app/ and pages/ may sit at the repository root or under src/, and a
	// monorepo puts them under a package directory, so the marker is found
	// rather than assumed to be first.
	marker, at := "", -1
	for i, p := range parts {
		if p == "app" || p == "pages" {
			marker, at = p, i
			break
		}
	}
	if at == -1 || at == len(parts)-1 {
		return "", "", false
	}

	rest := parts[at+1:]

	switch marker {
	case "app":
		if !nextRouteFileNames[rest[len(rest)-1]] {
			return "", "", false
		}
		segs := rest[:len(rest)-1]
		return "app", nextURLFromSegments(segs), true

	case "pages":
		// Only pages/api is an endpoint. Everything else under pages is a
		// rendered page.
		if len(rest) < 2 || rest[0] != "api" {
			return "", "", false
		}
		last := rest[len(rest)-1]
		ext := path.Ext(last)
		if ext == "" {
			return "", "", false
		}
		base := strings.TrimSuffix(last, ext)

		segs := append([]string{}, rest[:len(rest)-1]...)
		// index.ts is the directory itself rather than a segment called
		// "index".
		if base != "index" {
			segs = append(segs, base)
		}
		return "pages", nextURLFromSegments(segs), true
	}
	return "", "", false
}

// nextURLFromSegments joins path segments, dropping route groups and
// rewriting dynamic ones.
func nextURLFromSegments(segs []string) string {
	var out []string
	for _, s := range segs {
		switch {
		case s == "":
			continue

		// A parenthesised directory is a route group: it organises files and
		// contributes nothing to the URL. Reporting it as a segment would
		// produce a path nothing answers.
		case strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")"):
			continue

		// @modal and the other named slots are not path segments either.
		case strings.HasPrefix(s, "@"):
			continue

		// A private directory is never routed.
		case strings.HasPrefix(s, "_"):
			return ""

		case strings.HasPrefix(s, "["):
			if m := nextDynamicRe.FindStringSubmatch(s); m != nil {
				out = append(out, "{"+m[1]+"}")
				continue
			}
			out = append(out, s)

		default:
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return "/"
	}
	return "/" + strings.Join(out, "/")
}

// nextHandlerLine finds the line a route's handler starts on, so a finding
// points at the function rather than at the top of the file.
func nextHandlerLine(f SourceFile, kind, method string) int {
	want := "export default"
	if kind == "app" {
		want = method
	}
	for i, line := range f.Lines {
		if !strings.Contains(line, "export") {
			continue
		}
		if kind == "app" {
			if m := nextMethodExportRe.FindStringSubmatch(line); m != nil && m[1] == want {
				return i + 1
			}
			continue
		}
		if strings.Contains(line, want) {
			return i + 1
		}
	}
	return 1
}

// filepathToSlash normalizes separators without pulling in path/filepath,
// since SourceFile.Path is already slash-separated and this guards against a
// caller that is not.
func filepathToSlash(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}
