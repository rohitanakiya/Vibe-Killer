// Package surface holds Vibe Killer's model of the application under test:
// what stack it is, what endpoints it exposes, what it declares about
// authorization, and where it reads secrets and calls outward.
//
// The model is what makes the dynamic half targeted rather than speculative.
// An endpoint check does not guess at URLs; it works from routes that were
// read out of the target's own source.
package surface

import "strings"

// Surface is the whole model, serialized to app_surface.json.
type Surface struct {
	SchemaVersion string `json:"schema_version"`
	GeneratedAt   string `json:"generated_at"`
	RepoRoot      string `json:"repo_root"`
	RepoRev       string `json:"repo_rev,omitempty"`

	Stack Stack `json:"stack"`

	Routes        []Route        `json:"routes"`
	AuthLayers    []AuthLayer    `json:"auth_layers"`
	Models        []Model        `json:"models"`
	SecretUsages  []SecretUsage  `json:"secret_usages"`
	ExternalCalls []ExternalCall `json:"external_calls"`
	Manifests     []string       `json:"dependency_manifests"`

	// Notes records what the mapper could not determine, so that a thin
	// surface is visibly thin rather than looking like a clean result.
	Notes []string `json:"notes,omitempty"`
}

// SurfaceSchemaVersion versions app_surface.json independently of the
// findings contract.
const SurfaceSchemaVersion = "1.0"

// Stack is the detected technology of the target.
type Stack struct {
	// Adapter is the StackAdapter that matched, e.g. "node-express".
	Adapter string `json:"adapter"`

	Language       string `json:"language"`
	Framework      string `json:"framework,omitempty"`
	PackageManager string `json:"package_manager,omitempty"`
	Database       string `json:"database,omitempty"`

	// Confidence is how sure the detection is: a repo can hold several
	// languages, and the mapper says so rather than picking silently.
	Confidence string `json:"confidence"`

	// Evidence lists the files that drove the detection.
	Evidence []string `json:"evidence,omitempty"`

	// Others names additional stacks present in the repo.
	Others []string `json:"others,omitempty"`
}

// Detection is what an adapter returns from Detect.
type Detection struct {
	Adapter        string
	Language       string
	Framework      string
	PackageManager string
	Database       string

	// Score lets the mapper choose between adapters that both matched. A
	// framework match should outrank a bare language match.
	Score int

	Evidence []string
}

// Route is one endpoint the application exposes.
type Route struct {
	Method string `json:"method"`

	// Path is the route template as the framework declares it, normalized to
	// {param} form, e.g. /api/orders/{id}.
	Path string `json:"path"`

	Handler string `json:"handler,omitempty"`
	File    string `json:"file,omitempty"`
	Line    int    `json:"line,omitempty"`

	// PathParams are the template's parameter names.
	PathParams []string `json:"path_params,omitempty"`

	// Middleware lists the names applied at the route, in order.
	Middleware []string `json:"middleware,omitempty"`

	// DeclaredAuth is the authorization the source appears to apply. It is
	// what the code claims; whether the claim holds is what the endpoint
	// checks determine.
	DeclaredAuth string `json:"declared_auth,omitempty"`

	// Mutating is true for methods that change state. The orchestrator uses
	// this to keep read-only runs read-only.
	Mutating bool `json:"mutating"`
}

// Endpoint renders the route in the contract's "METHOD /path" form.
func (r Route) Endpoint() string {
	return strings.ToUpper(r.Method) + " " + r.Path
}

// HasAuth reports whether any authorization was detected at this route.
func (r Route) HasAuth() bool {
	return r.DeclaredAuth != "" || len(r.Middleware) > 0
}

// AuthLayer is an authentication or authorization mechanism found in the
// source.
type AuthLayer struct {
	// Kind is e.g. "jwt", "session", "api-key", "middleware".
	Kind string `json:"kind"`

	Name string `json:"name,omitempty"`
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`

	// Global is true when the layer is mounted application-wide rather than
	// per route, which is the safer arrangement.
	Global bool `json:"global"`

	Notes string `json:"notes,omitempty"`
}

// Model is a persisted data type.
type Model struct {
	Name   string   `json:"name"`
	File   string   `json:"file,omitempty"`
	Line   int      `json:"line,omitempty"`
	Fields []string `json:"fields,omitempty"`

	// OwnerField is the field that ties a record to a principal, if one was
	// found. Its absence is itself a signal for access-control review.
	OwnerField string `json:"owner_field,omitempty"`
}

// SecretUsage is a place the application reads a credential.
type SecretUsage struct {
	Name string `json:"name"`
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`

	// Source is "env", "literal", "file" or "unknown". A literal is the one
	// that matters.
	Source string `json:"source"`

	// ClientBundle is true when the usage is in code shipped to the browser,
	// where a secret is readable by anyone.
	ClientBundle bool `json:"client_bundle"`
}

// ExternalCall is an outbound request the application makes.
type ExternalCall struct {
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`

	// Target is the destination if it is a literal, or "<dynamic>" when the
	// URL is built at runtime, which is the interesting case.
	Target string `json:"target"`

	// FromRequestData is true when the URL derives from request input, which
	// is the shape of an unsafe fetch.
	FromRequestData bool `json:"from_request_data"`
}

// RoutesByMethod groups routes for reporting.
func (s *Surface) RoutesByMethod() map[string][]Route {
	out := map[string][]Route{}
	for _, r := range s.Routes {
		m := strings.ToUpper(r.Method)
		out[m] = append(out[m], r)
	}
	return out
}

// ReadRoutes returns the routes that do not change state. Read-only runs
// exercise only these.
func (s *Surface) ReadRoutes() []Route {
	var out []Route
	for _, r := range s.Routes {
		if !r.Mutating {
			out = append(out, r)
		}
	}
	return out
}

// RoutesWithParams returns routes carrying a path parameter, which are the
// candidates for an ownership-check failure.
func (s *Surface) RoutesWithParams() []Route {
	var out []Route
	for _, r := range s.Routes {
		if len(r.PathParams) > 0 {
			out = append(out, r)
		}
	}
	return out
}

// MutatingMethods are the HTTP methods treated as state-changing.
var MutatingMethods = map[string]bool{
	"POST": true, "PUT": true, "PATCH": true, "DELETE": true,
}

// IsMutating reports whether a method changes state.
func IsMutating(method string) bool {
	return MutatingMethods[strings.ToUpper(strings.TrimSpace(method))]
}
