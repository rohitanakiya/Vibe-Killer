package adapters

import (
	"context"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/rohitanakiya/Vibe-Killer/internal/surface"
)

// The Django extractor's behaviour, pinned against testdata/django-project.
//
// A testdata project rather than an application fixture, because what needs
// exercising is the URLconf tree: includes nested two deep, re_path regexes,
// a class-based view, a DRF router with two different viewset bases, and
// methods declared four different ways. One runnable app would cover a
// fraction of that.
//
// The runnable half lives in fixtures/django-{vulnerable,patched}, which the
// dynamic CI leg starts and scans. The two are complementary and neither
// replaces the other: this file proves the extractor against shapes no single
// application would contain, and the fixtures prove the endpoint checks
// against a server that actually answers.

func djangoProjectRoot(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("testdata", "django-project"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func djangoTestRoutes(t *testing.T) []surface.Route {
	t.Helper()
	routes, err := (&Python{}).EnumerateRoutes(context.Background(), djangoProjectRoot(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) == 0 {
		t.Fatal("no routes were found in the Django project")
	}
	return routes
}

func TestDjangoURLConfTreeIsResolved(t *testing.T) {
	routes := djangoTestRoutes(t)

	got := map[string]surface.Route{}
	for _, r := range routes {
		got[r.Endpoint()] = r
	}

	// The complete set, asserted exactly. A route this adapter invents is as
	// bad as one it misses: an endpoint check requesting a path the server
	// does not serve gets a 404 and reports nothing, which reads the same as
	// an application with no problems.
	want := []string{
		// A third-party mount. The admin is real exposed surface, so the
		// route is kept even though the view cannot be followed.
		"GET /admin",

		// orders/urls.py is mounted at /api/, and nothing in it says so.
		"GET /api/orders",
		"GET /api/orders/{order_id}",
		"POST /api/orders/create",

		// A class-based view declares its methods by defining them.
		"GET /api/boards",
		"POST /api/boards",

		// A DRF ModelViewSet promises all six actions.
		"GET /api/tickets",
		"POST /api/tickets",
		"GET /api/tickets/{pk}",
		"PUT /api/tickets/{pk}",
		"PATCH /api/tickets/{pk}",
		"DELETE /api/tickets/{pk}",

		// A ReadOnlyModelViewSet promises two.
		"GET /api/reports",
		"GET /api/reports/{pk}",

		// An @action is a route too, and the only thing in the source that
		// names it is the decorator. url_path wins where it is given;
		// otherwise DRF generates the segment from the method name with
		// underscores turned into hyphens, so reading the name verbatim would
		// produce a path the server answers 404 for.
		"POST /api/tickets/{pk}/mark-paid",
		"GET /api/tickets/summary",
		"GET /api/tickets/{pk}/audit-log",
		"DELETE /api/tickets/{pk}/audit-log",

		// re_path patterns, with the regex syntax stripped. legacy/urls.py is
		// reached through include(("legacy.urls", "legacy"), namespace=...),
		// the namespacing form, so these also pin that it parses.
		"GET /legacy/profiles/{profile_id}",
		"GET /legacy/reports/{param}",
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
			t.Errorf("route %q was reported but no URLconf declares it", endpoint)
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

// A view no URLconf reaches is not an endpoint. purge_orders is declared with
// @require_http_methods(["GET", "DELETE"]) and routed nowhere, so finding it
// in the surface would mean the extractor is reading views rather than routes
// -- and it would hand the endpoint layer a DELETE that does not exist.
func TestDjangoUnroutedViewsAreNotEndpoints(t *testing.T) {
	for _, r := range djangoTestRoutes(t) {
		if strings.Contains(r.Handler, "purge_orders") {
			t.Errorf("%s points at a view that no URLconf routes", r.Endpoint())
		}
		if r.Method == "DELETE" && !strings.Contains(r.Path, "tickets") {
			t.Errorf("%s is a DELETE that nothing declares; the only ones in this "+
				"project are the ticket viewset's destroy action and its "+
				"audit_log action, which states methods=[\"get\", \"delete\"]",
				r.Endpoint())
		}
	}
}

// The read-only viewset is the assertion that matters most here, because the
// failure is not a missing finding but a request the operator did not ask for:
// generating the six ModelViewSet routes for every registered viewset would
// have the endpoint layer send PUT, PATCH and DELETE to a collection that
// serves none of them.
func TestDjangoReadOnlyViewSetGetsNoWriteRoutes(t *testing.T) {
	for _, r := range djangoTestRoutes(t) {
		if !strings.Contains(r.Path, "/reports") {
			continue
		}
		if r.Method != "GET" {
			t.Errorf("%s was generated for a ReadOnlyModelViewSet", r.Endpoint())
		}
		if r.Mutating {
			t.Errorf("%s is marked mutating", r.Endpoint())
		}
	}
}

// A finding has to point at the code, not at the routing table. The URLconf
// line is the fallback for a view that cannot be followed, and admin.site.urls
// is the only one of those here.
func TestDjangoRoutesPointAtTheirView(t *testing.T) {
	for _, r := range djangoTestRoutes(t) {
		if r.Path == "/admin" {
			if !strings.HasSuffix(r.File, "urls.py") {
				t.Errorf("%s: a view that cannot be followed should fall back to the "+
					"URLconf line, got %s:%d", r.Endpoint(), r.File, r.Line)
			}
			continue
		}
		if !strings.HasSuffix(r.File, "views.py") {
			t.Errorf("%s points at %s:%d, want the views.py that defines the handler",
				r.Endpoint(), r.File, r.Line)
		}
		if r.Line <= 0 {
			t.Errorf("%s has no line number", r.Endpoint())
		}
		if r.Handler == "" {
			t.Errorf("%s has no handler", r.Endpoint())
		}
	}
}

// login_required is Django's spelling of route authorization, and the adapter
// has to see it or the static "endpoint has no auth" rule reports a protected
// view.
func TestDjangoDeclaredAuthIsRead(t *testing.T) {
	byEndpoint := map[string]surface.Route{}
	for _, r := range djangoTestRoutes(t) {
		byEndpoint[r.Endpoint()] = r
	}

	for _, endpoint := range []string{
		"GET /api/orders/{order_id}",
		"GET /legacy/profiles/{profile_id}",
	} {
		r, ok := byEndpoint[endpoint]
		if !ok {
			t.Fatalf("%s is missing", endpoint)
		}
		if !r.HasAuth() {
			t.Errorf("%s reports no authorization, though its view is @login_required", endpoint)
		}
	}

	// And it must not be invented for a view that has none.
	if r := byEndpoint["GET /api/orders"]; r.DeclaredAuth != "" {
		t.Errorf("GET /api/orders claims auth %q, though its view has no decorator", r.DeclaredAuth)
	}
}

// Path parameters have to be named, because that is what the traversal and
// IDOR checks substitute into.
func TestDjangoPathParamsAreNamed(t *testing.T) {
	byEndpoint := map[string]surface.Route{}
	for _, r := range djangoTestRoutes(t) {
		byEndpoint[r.Endpoint()] = r
	}

	cases := map[string]string{
		"GET /api/orders/{order_id}":        "order_id",
		"GET /legacy/profiles/{profile_id}": "profile_id",
		"GET /api/tickets/{pk}":             "pk",
	}
	for endpoint, param := range cases {
		r, ok := byEndpoint[endpoint]
		if !ok {
			t.Fatalf("%s is missing", endpoint)
		}
		if len(r.PathParams) != 1 || r.PathParams[0] != param {
			t.Errorf("%s params = %v, want [%s]", endpoint, r.PathParams, param)
		}
	}
}

func TestDjangoIsDetectedAsTheFramework(t *testing.T) {
	det, ok := (&Python{}).Detect(djangoProjectRoot(t))
	if !ok {
		t.Fatal("the Django project was not detected as Python at all")
	}
	if det.Framework != "django" {
		t.Errorf("framework = %q, want django", det.Framework)
	}
}

func TestDjangoPatternToTemplate(t *testing.T) {
	cases := []struct{ kind, in, want string }{
		// path() patterns are templates already.
		{"path", "orders/<int:order_id>/", "orders/<int:order_id>/"},
		{"path", "", ""},

		// re_path patterns are regexes, and normalizing one as a template
		// produces a path the server does not serve.
		{"re_path", `^profiles/(?P<profile_id>[0-9]+)/$`, "profiles/<profile_id>/"},
		{"re_path", `^reports/([0-9]{4})/$`, "reports/<param>/"},
		{"re_path", `^a/(\d+)/b/(\w+)/$`, "a/<param>/b/<param2>/"},
		{"re_path", `^files/(?P<name>[^/]+)\.json$`, "files/<name>.json"},
		{"url", `^old/$`, "old/"},
	}
	for _, tc := range cases {
		if got := djangoPatternToTemplate(tc.kind, tc.in); got != tc.want {
			t.Errorf("djangoPatternToTemplate(%q, %q) = %q, want %q", tc.kind, tc.in, got, tc.want)
		}
	}
}
