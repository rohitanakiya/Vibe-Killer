package adapters

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rohitanakiya/Vibe-Killer/internal/surface"
)

// fixturePath resolves a fixture directory, skipping the test if the fixtures
// are not present.
func fixturePath(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Skipf("fixture %s is not present", name)
	}
	return p
}

// The whole point of the adapter layer is that nothing in the engine assumes a
// stack. These tests run the same detection over two unrelated fixtures and
// check that each is identified on its own evidence.
func TestDetectionIsStackAgnostic(t *testing.T) {
	tests := []struct {
		fixture     string
		wantAdapter string
		wantLang    string
		wantFW      string
	}{
		{"express-vulnerable", "node", "javascript", "express"},
		{"express-patched", "node", "javascript", "express"},
		{"flask-vulnerable", "python", "python", "flask"},
		{"flask-patched", "python", "python", "flask"},
	}

	for _, tc := range tests {
		t.Run(tc.fixture, func(t *testing.T) {
			root := fixturePath(t, tc.fixture)

			adapter, det, _ := Default.Match(root)
			if adapter == nil {
				t.Fatalf("no adapter matched %s", tc.fixture)
			}
			if det.Adapter != tc.wantAdapter {
				t.Errorf("adapter = %q, want %q", det.Adapter, tc.wantAdapter)
			}
			if det.Language != tc.wantLang {
				t.Errorf("language = %q, want %q", det.Language, tc.wantLang)
			}
			if det.Framework != tc.wantFW {
				t.Errorf("framework = %q, want %q", det.Framework, tc.wantFW)
			}
			if len(det.Evidence) == 0 {
				t.Error("detection reported no evidence, so an operator cannot tell why it decided this")
			}
			// A framework match must outrank a bare language match, or the
			// mapper would pick the wrong adapter in a mixed repository.
			if det.Score < 50 {
				t.Errorf("score = %d, want a framework-level score", det.Score)
			}
		})
	}
}

func TestDetectionFindsNothingInAnEmptyDirectory(t *testing.T) {
	adapter, _, _ := Default.Match(t.TempDir())
	if adapter != nil {
		t.Errorf("adapter %s matched an empty directory", adapter.Name())
	}
}

func TestNodeRouteEnumeration(t *testing.T) {
	root := fixturePath(t, "express-vulnerable")

	routes, err := (&Node{}).EnumerateRoutes(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) == 0 {
		t.Fatal("no routes were found in the Express fixture")
	}

	byEndpoint := map[string]surface.Route{}
	for _, r := range routes {
		byEndpoint[r.Endpoint()] = r
	}

	// The route templates must be normalized to {param} form, so that the
	// rest of the system compares routes without knowing the framework.
	for _, want := range []string{
		"GET /api/orders/{id}",
		"GET /api/profiles/{id}",
		"POST /api/orders",
		"GET /api/files/{name}",
		"POST /api/import",
	} {
		if _, ok := byEndpoint[want]; !ok {
			t.Errorf("route %q was not found; got %v", want, endpoints(routes))
		}
	}

	order := byEndpoint["GET /api/orders/{id}"]
	if len(order.PathParams) != 1 || order.PathParams[0] != "id" {
		t.Errorf("path params = %v, want [id]", order.PathParams)
	}
	if order.File == "" || order.Line == 0 {
		t.Errorf("route has no source position: %+v", order)
	}
	// The authenticate middleware is on this route and has to be detected,
	// because the difference between "no auth" and "auth but no authz" is the
	// whole finding.
	if order.DeclaredAuth == "" {
		t.Errorf("declared auth was not detected on %s (middleware: %v)", order.Endpoint(), order.Middleware)
	}

	// The profiles route has no middleware at all.
	profile := byEndpoint["GET /api/profiles/{id}"]
	if profile.DeclaredAuth != "" {
		t.Errorf("auth was reported on a route that has none: %q", profile.DeclaredAuth)
	}

	// Mutating methods have to be flagged, so a read-only run stays read-only.
	if !byEndpoint["POST /api/orders"].Mutating {
		t.Error("POST was not marked as mutating")
	}
	if byEndpoint["GET /api/orders/{id}"].Mutating {
		t.Error("GET was marked as mutating")
	}
}

// An outbound HTTP call shares the method names a router uses. Treating
// axios.get("https://...") as a route would have the scanner probing URLs the
// application merely calls.
func TestNodeEnumerationIgnoresOutboundCalls(t *testing.T) {
	dir := t.TempDir()
	src := `const axios = require('axios');
const app = require('express')();
app.get('/api/real/:id', handler);
axios.get('https://api.example.invalid/v1/things');
const r = await client.get('/not-a-route');
fetch('https://example.invalid/data');
`
	if err := os.WriteFile(filepath.Join(dir, "server.js"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	routes, err := (&Node{}).EnumerateRoutes(context.Background(), dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 {
		t.Fatalf("got %v, want only the real route", endpoints(routes))
	}
	if routes[0].Endpoint() != "GET /api/real/{id}" {
		t.Errorf("route = %q", routes[0].Endpoint())
	}
}

func TestPythonRouteEnumeration(t *testing.T) {
	root := fixturePath(t, "flask-vulnerable")

	routes, err := (&Python{}).EnumerateRoutes(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) == 0 {
		t.Fatal("no routes were found in the Flask fixture")
	}

	byEndpoint := map[string]surface.Route{}
	for _, r := range routes {
		byEndpoint[r.Endpoint()] = r
	}

	// Flask's <int:order_id> must normalize to the same {param} form the Node
	// adapter produces from :id.
	for _, want := range []string{
		"GET /api/orders/{order_id}",
		"GET /api/profiles/{profile_id}",
		"POST /api/orders",
		"GET /api/search",
		"POST /api/import",
	} {
		if _, ok := byEndpoint[want]; !ok {
			t.Errorf("route %q was not found; got %v", want, endpoints(routes))
		}
	}

	order := byEndpoint["GET /api/orders/{order_id}"]
	if order.Handler != "get_order" {
		t.Errorf("handler = %q, want get_order (read from the def below the decorator)", order.Handler)
	}
	// require_auth sits between the route decorator and the def, which is
	// where a decorator stack puts it.
	if order.DeclaredAuth == "" {
		t.Errorf("the require_auth decorator was not detected (decorators: %v)", order.Middleware)
	}

	profile := byEndpoint["GET /api/profiles/{profile_id}"]
	if profile.DeclaredAuth != "" {
		t.Errorf("auth was reported on a route that has none: %q", profile.DeclaredAuth)
	}
}

func TestPythonAndNodeProduceTheSameTemplateShape(t *testing.T) {
	// The same logical route written in two frameworks must normalize
	// identically, because the findings contract compares them by endpoint.
	tests := []struct {
		in   string
		want string
	}{
		{"/api/orders/:id", "/api/orders/{id}"},
		{"/api/orders/<int:id>", "/api/orders/{id}"},
		{"/api/orders/{id}", "/api/orders/{id}"},
		{"/api/orders/<id>", "/api/orders/{id}"},
		{"/api/orders/:id?", "/api/orders/{id}"},
		{"/files/*path", "/files/{wildcard}"},
		{"api/orders", "/api/orders"},
		{"/api/orders/", "/api/orders"},
		{"", ""},
	}
	for _, tc := range tests {
		got, _ := NormalizePathTemplate(tc.in)
		if got != tc.want {
			t.Errorf("NormalizePathTemplate(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizePathTemplateReportsParamNames(t *testing.T) {
	_, params := NormalizePathTemplate("/api/users/<int:user_id>/orders/:orderId")
	if len(params) != 2 || params[0] != "user_id" || params[1] != "orderId" {
		t.Errorf("params = %v, want [user_id orderId]", params)
	}
}

func TestJoinPrefix(t *testing.T) {
	tests := []struct{ prefix, path, want string }{
		{"/api", "/orders", "/api/orders"},
		{"/api/", "/orders", "/api/orders"},
		{"", "/orders", "/orders"},
		{"/api", "", "/api"},
		{"/api", "/", "/api"},
		{"/api", "orders", "/api/orders"},
	}
	for _, tc := range tests {
		if got := JoinPrefix(tc.prefix, tc.path); got != tc.want {
			t.Errorf("JoinPrefix(%q, %q) = %q, want %q", tc.prefix, tc.path, got, tc.want)
		}
	}
}

func TestBlueprintAndRouterPrefixesAreApplied(t *testing.T) {
	dir := t.TempDir()
	src := `from flask import Blueprint
bp = Blueprint("api", __name__, url_prefix="/api/v2")

@bp.route("/orders/<int:order_id>", methods=["GET"])
def get_order(order_id):
    return {}
`
	if err := os.WriteFile(filepath.Join(dir, "views.py"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	routes, err := (&Python{}).EnumerateRoutes(context.Background(), dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 {
		t.Fatalf("got %v", endpoints(routes))
	}
	if routes[0].Endpoint() != "GET /api/v2/orders/{order_id}" {
		t.Errorf("the blueprint prefix was not applied: %q", routes[0].Endpoint())
	}
}

func TestDependencyManifestsAreFound(t *testing.T) {
	node := (&Node{}).DependencyManifests(fixturePath(t, "express-vulnerable"))
	if !contains(node, "package.json") {
		t.Errorf("node manifests = %v", node)
	}

	py := (&Python{}).DependencyManifests(fixturePath(t, "flask-vulnerable"))
	if !contains(py, "requirements.txt") {
		t.Errorf("python manifests = %v", py)
	}
}

func TestWalkSourceSkipsVendorDirectories(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{
		"app.js",
		"node_modules/pkg/index.js",
		"dist/bundle.js",
		".git/hooks/pre-commit.js",
		"src/routes.js",
	} {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("// x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var seen []string
	err := WalkSource(context.Background(), dir, []string{".js"}, nil, func(f SourceFile) error {
		seen = append(seen, f.Path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(seen) != 2 {
		t.Fatalf("visited %v, want only app.js and src/routes.js", seen)
	}
	for _, p := range seen {
		if strings.Contains(p, "node_modules") || strings.Contains(p, "dist") || strings.Contains(p, ".git") {
			t.Errorf("visited a directory that should be skipped: %s", p)
		}
	}
}

func TestWalkSourceHonoursExcludePatterns(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{"keep.js", "generated/out.js", "skip.js"} {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("// x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var seen []string
	err := WalkSource(context.Background(), dir, []string{".js"}, []string{"generated/**", "skip.js"}, func(f SourceFile) error {
		seen = append(seen, f.Path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0] != "keep.js" {
		t.Errorf("visited %v, want only keep.js", seen)
	}
}

func TestSecretUsageFlagsClientBundles(t *testing.T) {
	dir := t.TempDir()
	for path, src := range map[string]string{
		"server/config.js":             "const key = process.env.STRIPE_SECRET_KEY;\n",
		"client/src/pages/Checkout.js": "const key = process.env.STRIPE_API_KEY;\n",
		"server/plain.js":              "const port = process.env.PORT;\n",
	} {
		full := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	usages, err := (&Node{}).SecretUsages(context.Background(), dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	var clientSide, serverSide int
	for _, u := range usages {
		if u.ClientBundle {
			clientSide++
			continue
		}
		serverSide++
	}

	if clientSide != 1 {
		t.Errorf("client-bundle usages = %d, want 1; got %+v", clientSide, usages)
	}
	if serverSide != 1 {
		t.Errorf("server-side usages = %d, want 1 (PORT is not a credential); got %+v", serverSide, usages)
	}
}

// --- helpers ---------------------------------------------------------------

func endpoints(routes []surface.Route) []string {
	out := make([]string, 0, len(routes))
	for _, r := range routes {
		out = append(out, r.Endpoint())
	}
	return out
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
