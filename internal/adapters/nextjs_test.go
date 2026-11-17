package adapters

import (
	"context"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/rohitanakiya/Vibe-Killer/internal/surface"
)

// Next.js, pinned against testdata/nextjs-app.
//
// Next.js was the last framework the adapter named and could not read. Its
// routes are not in the source at all: the path is the file's location on
// disk and the methods are the names of the functions it exports, so there is
// nothing in a file for a regex to find that says where the file is served.
// A detected framework with an empty route list was at least honest about it
// -- an empty route list is a skip that names the framework -- but it meant
// every endpoint check covered nothing on a Next.js codebase.

func nextTestRoutes(t *testing.T) []surface.Route {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("testdata", "nextjs-app"))
	if err != nil {
		t.Fatal(err)
	}
	routes, err := (&Node{}).EnumerateRoutes(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) == 0 {
		t.Fatal("no routes were found in the Next.js fixture")
	}
	return routes
}

func TestNextRoutesComeFromTheFileTree(t *testing.T) {
	routes := nextTestRoutes(t)

	got := map[string]surface.Route{}
	for _, r := range routes {
		got[r.Endpoint()] = r
	}

	want := []string{
		// App Router: the directory is the path, the exports are the methods.
		"GET /api/orders",
		"POST /api/orders",
		"GET /api/orders/{id}",
		"PATCH /api/orders/{id}",
		"DELETE /api/orders/{id}",

		// A route group organises files and contributes nothing to the URL,
		// so this is /api/metrics and not /api/(internal)/metrics.
		"GET /api/metrics",

		// A catch-all segment is still one parameter.
		"GET /api/files/{path}",

		// Pages Router: the file is the last segment, and one handler serves
		// every method.
		"GET /api/health",
		"GET /api/legacy/{id}",

		// Both methods, because this handler's source states which it
		// accepts. Where one does not, GET alone is reported.
		"GET /api/legacy/orders",
		"POST /api/legacy/orders",
	}

	for _, w := range want {
		if _, ok := got[w]; !ok {
			t.Errorf("route %q was not found", w)
		}
	}
	wanted := map[string]bool{}
	for _, w := range want {
		wanted[w] = true
	}
	for endpoint := range got {
		if !wanted[endpoint] {
			t.Errorf("route %q was reported, but nothing serves it", endpoint)
		}
	}
	if t.Failed() {
		var all []string
		for e := range got {
			all = append(all, e)
		}
		sort.Strings(all)
		t.Logf("reported: %s", strings.Join(all, "\n          "))
	}
}

// A page is not an endpoint. The checks that consume this surface probe for
// broken access control and injection, and a rendered page is neither, so
// including one would make a scan look broader than it is.
func TestNextPagesAreNotEndpoints(t *testing.T) {
	for _, r := range nextTestRoutes(t) {
		if strings.HasSuffix(r.File, "page.tsx") || strings.HasSuffix(r.File, "page.jsx") {
			t.Errorf("%s came from %s, which renders a page rather than serving an endpoint",
				r.Endpoint(), r.File)
		}
		if strings.Contains(r.Path, "(") || strings.Contains(r.Path, "[") {
			t.Errorf("%s still carries file-tree syntax in its path", r.Endpoint())
		}
	}
}

// A finding has to point at the function, which for the App Router is the
// export whose name is the method.
func TestNextRoutesPointAtTheirHandler(t *testing.T) {
	byEndpoint := map[string]surface.Route{}
	for _, r := range nextTestRoutes(t) {
		byEndpoint[r.Endpoint()] = r
	}

	cases := map[string]string{
		"GET /api/orders":         "GET",
		"POST /api/orders":        "POST",
		"DELETE /api/orders/{id}": "DELETE",
		"GET /api/legacy/{id}":    "default",
		"POST /api/legacy/orders": "default",
	}
	for endpoint, handler := range cases {
		r, ok := byEndpoint[endpoint]
		if !ok {
			t.Fatalf("%s is missing", endpoint)
		}
		if r.Handler != handler {
			t.Errorf("%s handler = %q, want %q", endpoint, r.Handler, handler)
		}
		if r.Line <= 1 && strings.Contains(r.File, "route.ts") {
			t.Errorf("%s points at %s:%d, want the exported function's line",
				endpoint, r.File, r.Line)
		}
	}
}

func TestNextPathFor(t *testing.T) {
	cases := []struct {
		file   string
		kind   string
		path   string
		mapped bool
	}{
		// App Router, including the src/ layout and a monorepo package.
		{"app/api/orders/route.ts", "app", "/api/orders", true},
		{"src/app/api/orders/[id]/route.ts", "app", "/api/orders/{id}", true},
		{"packages/web/app/api/health/route.js", "app", "/api/health", true},
		{"app/api/(internal)/metrics/route.ts", "app", "/api/metrics", true},
		{"app/api/files/[...path]/route.ts", "app", "/api/files/{path}", true},
		{"app/api/files/[[...path]]/route.ts", "app", "/api/files/{path}", true},
		{"app/api/@modal/thing/route.ts", "app", "/api/thing", true},

		// A page, a layout and a component are not endpoints.
		{"app/page.tsx", "", "", false},
		{"app/layout.tsx", "", "", false},
		{"app/api/orders/helpers.ts", "", "", false},

		// Pages Router. Only pages/api is served as an endpoint.
		{"pages/api/health.ts", "pages", "/api/health", true},
		{"pages/api/legacy/[id].ts", "pages", "/api/legacy/{id}", true},
		{"pages/api/index.ts", "pages", "/api", true},
		{"src/pages/api/orders/index.ts", "pages", "/api/orders", true},
		{"pages/about.tsx", "", "", false},
		{"pages/index.tsx", "", "", false},

		// Nothing outside either router.
		{"lib/db.ts", "", "", false},
		{"server.js", "", "", false},
	}

	for _, tc := range cases {
		kind, urlPath, ok := nextPathFor(tc.file)
		if ok != tc.mapped {
			t.Errorf("nextPathFor(%q) mapped = %v, want %v", tc.file, ok, tc.mapped)
			continue
		}
		if !ok {
			continue
		}
		if kind != tc.kind {
			t.Errorf("nextPathFor(%q) kind = %q, want %q", tc.file, kind, tc.kind)
		}
		// The raw URL still carries {param} form from the segment rewrite;
		// NormalizePathTemplate is what the caller runs over it.
		normalized, _ := NormalizePathTemplate(urlPath)
		if normalized != tc.path {
			t.Errorf("nextPathFor(%q) path = %q, want %q", tc.file, normalized, tc.path)
		}
	}
}
