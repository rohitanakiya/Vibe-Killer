package adapters

import (
	"context"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/rohitanakiya/Vibe-Killer/internal/surface"
)

// The Node frameworks the adapter claims beyond Express, pinned against
// testdata/node-frameworks.
//
// All three were "implemented": the adapter had a regex for each and the
// dependency table named them. Against this fixture it reported nine routes
// of which seven were paths no server serves, because in every case the thing
// that decides the path lives somewhere other than the declaration. There was
// no fixture, so nothing said so.

func nodeFrameworkRoutes(t *testing.T) []surface.Route {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("testdata", "node-frameworks"))
	if err != nil {
		t.Fatal(err)
	}
	routes, err := (&Node{}).EnumerateRoutes(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) == 0 {
		t.Fatal("no routes were found in the Node frameworks fixture")
	}
	return routes
}

func TestNodeFrameworkRoutesAreServedWhereTheyAreReported(t *testing.T) {
	routes := nodeFrameworkRoutes(t)

	got := map[string]surface.Route{}
	for _, r := range routes {
		got[r.Endpoint()] = r
	}

	// Asserted exactly, because a route reported at the wrong path is worse
	// than a missing one: the endpoint checks probe it, get a 404, and report
	// nothing, which reads the same as an application with nothing wrong.
	want := []string{
		// fastify's shorthand, which is Express-shaped.
		"GET /fastify/orders/{id}",
		"POST /fastify/orders",

		// fastify's object form, in both key orders. url-before-method was
		// missed entirely by the single regex that preceded this.
		"GET /fastify/reports/{year}",
		"DELETE /fastify/exports",

		// koa, whose router carries its prefix at construction.
		"GET /koa/tickets/{id}",
		"POST /koa/tickets",

		// NestJS, where the path is the controller's prefix joined with the
		// decorator's argument. An argumentless @Get() is the collection.
		"GET /nest/invoices",
		"GET /nest/invoices/{id}",
		"POST /nest/invoices",
		"DELETE /nest/invoices/{id}",
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
			t.Errorf("route %q was reported, but nothing declares it at that path", endpoint)
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

// A guarded NestJS route reported as unguarded is worse than no information:
// the endpoint layer probes it expecting no credentials to be needed, and the
// static rule that looks for an endpoint without authorization has nothing to
// see either.
func TestNestGuardsAreReadAsDeclaredAuth(t *testing.T) {
	byEndpoint := map[string]surface.Route{}
	for _, r := range nodeFrameworkRoutes(t) {
		byEndpoint[r.Endpoint()] = r
	}

	for _, endpoint := range []string{"POST /nest/invoices", "DELETE /nest/invoices/{id}"} {
		r, ok := byEndpoint[endpoint]
		if !ok {
			t.Fatalf("%s is missing", endpoint)
		}
		if !r.HasAuth() {
			t.Errorf("%s reports no authorization, though its method carries @UseGuards", endpoint)
		}
		if !strings.Contains(r.DeclaredAuth, "AuthGuard") {
			t.Errorf("%s declared auth = %q, want it to name the guard", endpoint, r.DeclaredAuth)
		}
	}

	// And it must not be invented for the routes that carry no guard.
	for _, endpoint := range []string{"GET /nest/invoices", "GET /nest/invoices/{id}"} {
		if r := byEndpoint[endpoint]; r.DeclaredAuth != "" {
			t.Errorf("%s claims auth %q, though its method carries no guard", endpoint, r.DeclaredAuth)
		}
	}
}

// A finding has to point at code a person can open, and for NestJS that means
// the method the decorator sits above.
func TestNestRoutesNameTheirHandler(t *testing.T) {
	want := map[string]string{
		"GET /nest/invoices":         "findAll",
		"GET /nest/invoices/{id}":    "findOne",
		"POST /nest/invoices":        "create",
		"DELETE /nest/invoices/{id}": "remove",
	}
	for _, r := range nodeFrameworkRoutes(t) {
		expected, ok := want[r.Endpoint()]
		if !ok {
			continue
		}
		if r.Handler != expected {
			t.Errorf("%s handler = %q, want %q", r.Endpoint(), r.Handler, expected)
		}
		if !strings.HasSuffix(r.File, ".ts") || r.Line <= 0 {
			t.Errorf("%s points at %s:%d", r.Endpoint(), r.File, r.Line)
		}
	}
}

func TestBraceBlocksAfter(t *testing.T) {
	// Brace matching rather than a regex, because a regex stops at the first
	// closing brace -- cutting an object off at its first nested one -- or
	// runs to the last, swallowing every route in a file into one match.
	src := "route({ method: 'GET', url: '/a', opts: { x: 1 } });\nroute({ url: '/b', method: 'PUT' });"
	blocks := braceBlocksAfter(src, "route(")
	if len(blocks) != 2 {
		t.Fatalf("blocks = %d, want 2", len(blocks))
	}
	if !strings.Contains(blocks[0].text, "/a") || !strings.Contains(blocks[0].text, "x: 1") {
		t.Errorf("first block did not span its nested object: %q", blocks[0].text)
	}
	if strings.Contains(blocks[0].text, "/b") {
		t.Errorf("first block swallowed the second route: %q", blocks[0].text)
	}
	if !strings.Contains(blocks[1].text, "/b") {
		t.Errorf("second block = %q", blocks[1].text)
	}

	if got := braceBlocksAfter("route(", "route("); len(got) != 0 {
		t.Errorf("an unterminated block produced %d results", len(got))
	}
}
