package adapters

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/rohitanakiya/Vibe-Killer/internal/surface"
)

func init() { Register(&Node{}) }

// Node is the adapter for JavaScript and TypeScript HTTP services: Express,
// Fastify, Koa, NestJS and the hand-rolled routers generated code tends to
// produce.
type Node struct{}

// Name identifies the adapter.
func (n *Node) Name() string { return "node" }

var nodeExts = []string{".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}

// packageJSON is the subset of a Node manifest the adapter reads.
type packageJSON struct {
	Name            string            `json:"name"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
	Scripts         map[string]string `json:"scripts"`
}

// Detect looks for a Node manifest and works out which framework it uses.
func (n *Node) Detect(repoRoot string) (surface.Detection, bool) {
	raw := ReadFileString(repoRoot, "package.json")
	if raw == "" {
		return surface.Detection{}, false
	}

	var pkg packageJSON
	if err := json.Unmarshal([]byte(raw), &pkg); err != nil {
		// A malformed manifest is still evidence that this is a Node project.
		return surface.Detection{
			Adapter: "node", Language: "javascript", Score: 10,
			Evidence: []string{"package.json (unparseable)"},
		}, true
	}

	det := surface.Detection{
		Adapter:  "node",
		Language: "javascript",
		Score:    20,
		Evidence: []string{"package.json"},
	}

	deps := map[string]bool{}
	for k := range pkg.Dependencies {
		deps[strings.ToLower(k)] = true
	}
	for k := range pkg.DevDependencies {
		deps[strings.ToLower(k)] = true
	}

	if deps["typescript"] || FileExists(repoRoot, "tsconfig.json") {
		det.Language = "typescript"
		det.Evidence = append(det.Evidence, "tsconfig.json")
	}

	// A framework match is much stronger evidence than a bare manifest,
	// because it tells the mapper how to read routes.
	for _, fw := range []struct {
		dep, name string
	}{
		{"express", "express"},
		{"fastify", "fastify"},
		{"@nestjs/core", "nestjs"},
		{"koa", "koa"},
		{"hapi", "hapi"},
		{"@hapi/hapi", "hapi"},
		{"next", "next.js"},
	} {
		if deps[fw.dep] {
			det.Framework = fw.name
			det.Score = 60
			det.Evidence = append(det.Evidence, "dependency: "+fw.dep)
			break
		}
	}

	for _, db := range []struct {
		dep, name string
	}{
		{"mongoose", "mongodb"},
		{"mongodb", "mongodb"},
		{"pg", "postgresql"},
		{"postgres", "postgresql"},
		{"mysql", "mysql"},
		{"mysql2", "mysql"},
		{"sqlite3", "sqlite"},
		{"better-sqlite3", "sqlite"},
		{"sequelize", "sql (sequelize)"},
		{"knex", "sql (knex)"},
		{"typeorm", "sql (typeorm)"},
		{"prisma", "sql (prisma)"},
		{"@prisma/client", "sql (prisma)"},
	} {
		if deps[db.dep] {
			det.Database = db.name
			det.Evidence = append(det.Evidence, "dependency: "+db.dep)
			break
		}
	}

	det.PackageManager = "npm"
	switch {
	case FileExists(repoRoot, "pnpm-lock.yaml"):
		det.PackageManager = "pnpm"
	case FileExists(repoRoot, "yarn.lock"):
		det.PackageManager = "yarn"
	case FileExists(repoRoot, "bun.lockb"), FileExists(repoRoot, "bun.lock"):
		det.PackageManager = "bun"
	}

	return det, true
}

var (
	// app.get('/x', mw, handler) and router.post("/y", handler).
	nodeRouteRe = regexp.MustCompile(
		`(?i)\b([A-Za-z_$][\w$]*)\s*\.\s*(get|post|put|patch|delete|options|head|all)\s*\(\s*(['"` + "`" + `])([^'"` + "`" + `]*)['"` + "`" + `]\s*(,([^)]*))?`)

	// app.use('/api', router) — a mount prefix.
	nodeMountRe = regexp.MustCompile(
		`\b([A-Za-z_$][\w$]*)\s*\.\s*use\s*\(\s*(['"` + "`" + `])(/[^'"` + "`" + `]*)['"` + "`" + `]\s*,\s*([A-Za-z_$][\w$]*)`)

	// NestJS decorators: @Get(':id')
	nodeNestRe = regexp.MustCompile(
		`@(Get|Post|Put|Patch|Delete|Options|Head)\s*\(\s*(?:['"]([^'"]*)['"])?\s*\)`)

	// Middleware names that look like authorization.
	nodeAuthNameRe = regexp.MustCompile(
		`(?i)(auth|authn|authz|authenticate|authorize|requireauth|requiresauth|isauthenticated|ensureauth|verifytoken|checkjwt|jwt|passport|protect|guard|session|login|requireuser|currentuser|admin|permission|role|acl|can)`)
)

// nodeHTTPMethods maps the router method name to an HTTP method.
var nodeHTTPMethods = map[string]string{
	"get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH",
	"delete": "DELETE", "options": "OPTIONS", "head": "HEAD", "all": "GET",
}

// EnumerateRoutes reads route declarations out of the source.
func (n *Node) EnumerateRoutes(ctx context.Context, repoRoot string, exclude []string) ([]surface.Route, error) {
	var routes []surface.Route

	// Mount prefixes are resolved per file: a router mounted at /api in
	// app.js gives every route in the router file that prefix. Tracking this
	// across files needs module resolution, so the adapter applies prefixes
	// found in the same file and records the limitation rather than guessing.
	err := WalkSource(ctx, repoRoot, nodeExts, exclude, func(f SourceFile) error {
		whole := strings.Join(f.Lines, "\n")

		// Construction-time prefixes first -- koa routers carry theirs there
		// rather than taking one at use() time -- then mount-time ones, which
		// override: where a router declares a prefix and is also mounted under
		// a path, the mount is where it is actually served.
		prefixes := nodeRouterPrefixes(whole)
		for _, m := range nodeMountRe.FindAllStringSubmatch(whole, -1) {
			routerVar, prefix := m[4], m[3]
			prefixes[routerVar] = prefix
		}

		for i, line := range f.Lines {
			lineNo := i + 1
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
				continue
			}

			for _, m := range nodeRouteRe.FindAllStringSubmatch(line, -1) {
				recv, method, rawPath, args := m[1], strings.ToLower(m[2]), m[4], m[6]

				httpMethod, ok := nodeHTTPMethods[method]
				if !ok {
					continue
				}
				// Skip outbound HTTP client calls, which share the method
				// names: axios.get("https://...") is not a route.
				if isClientCall(recv) || strings.Contains(rawPath, "://") {
					continue
				}

				full := JoinPrefix(prefixes[recv], rawPath)
				path, params := NormalizePathTemplate(full)
				if path == "" {
					continue
				}

				middleware := parseNodeMiddleware(args)
				routes = append(routes, surface.Route{
					Method:       httpMethod,
					Path:         path,
					PathParams:   params,
					File:         f.Path,
					Line:         lineNo,
					Handler:      nodeHandlerName(args),
					Middleware:   middleware,
					DeclaredAuth: authFromMiddleware(middleware),
					Mutating:     surface.IsMutating(httpMethod),
				})
			}

		}

		// NestJS and fastify object routes are handled in
		// node_frameworks.go. Neither can be read a line at a time: a NestJS
		// route's path is the controller's prefix joined with the decorator's
		// argument, and a fastify route object spans lines and promises no
		// key order.
		routes = append(routes, nodeNestRoutes(f)...)
		routes = append(routes, nodeFastifyObjectRoutes(f)...)

		return nil
	})
	if err != nil {
		return nil, err
	}

	// Next.js is handled separately because its routes are not in the
	// source at all: the path is the file's location on disk and the
	// methods are the names of the functions it exports. See nextjs.go.
	fromNext, nerr := nextRoutes(ctx, repoRoot, exclude)
	if nerr != nil {
		return nil, nerr
	}
	routes = append(routes, fromNext...)

	return DedupeRoutes(routes), nil
}

// isClientCall reports whether a receiver name looks like an HTTP client
// rather than a router.
func isClientCall(recv string) bool {
	switch strings.ToLower(recv) {
	case "axios", "fetch", "got", "http", "https", "request", "superagent",
		"client", "api", "instance", "supertest", "agent":
		return true
	}
	return false
}

// parseNodeMiddleware pulls identifier names from a route's argument list,
// dropping the final handler.
func parseNodeMiddleware(args string) []string {
	args = strings.TrimSpace(args)
	if args == "" {
		return nil
	}

	// An inline handler means there is no named middleware to read.
	if strings.Contains(args, "=>") || strings.HasPrefix(args, "function") ||
		strings.HasPrefix(args, "async") {
		if !strings.Contains(args, ",") {
			return nil
		}
	}

	var out []string
	for _, part := range splitTopLevel(args) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "=>") || strings.HasPrefix(part, "function") ||
			strings.HasPrefix(part, "async") {
			continue
		}
		// Keep call expressions like requireAuth('admin') as their name.
		if i := strings.IndexByte(part, '('); i > 0 {
			part = part[:i]
		}
		part = strings.TrimSpace(part)
		if part == "" || strings.ContainsAny(part, `'"`+"`") {
			continue
		}
		out = append(out, part)
	}

	// The last identifier is normally the handler, not middleware.
	if len(out) > 1 {
		return out[:len(out)-1]
	}
	return nil
}

// nodeHandlerName returns the handler identifier if the route names one.
func nodeHandlerName(args string) string {
	parts := splitTopLevel(args)
	if len(parts) == 0 {
		return ""
	}
	last := strings.TrimSpace(parts[len(parts)-1])
	if last == "" || strings.Contains(last, "=>") || strings.HasPrefix(last, "function") ||
		strings.HasPrefix(last, "async") {
		return ""
	}
	if i := strings.IndexByte(last, '('); i > 0 {
		last = last[:i]
	}
	last = strings.TrimSpace(last)
	if strings.ContainsAny(last, `'"`+"`"+` {}`) {
		return ""
	}
	return last
}

// splitTopLevel splits an argument list on commas that are not nested inside
// brackets or a string.
func splitTopLevel(s string) []string {
	var out []string
	depth := 0
	var quote rune
	start := 0

	for i, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '\'' || r == '"' || r == '`':
			quote = r
		case r == '(' || r == '[' || r == '{':
			depth++
		case r == ')' || r == ']' || r == '}':
			depth--
		case r == ',' && depth == 0:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

// authFromMiddleware reports which middleware names look like authorization.
func authFromMiddleware(mw []string) string {
	var hits []string
	for _, m := range mw {
		if nodeAuthNameRe.MatchString(m) {
			hits = append(hits, m)
		}
	}
	return strings.Join(hits, ", ")
}

var nodeGlobalUseRe = regexp.MustCompile(
	`\b([A-Za-z_$][\w$]*)\s*\.\s*use\s*\(\s*([A-Za-z_$][\w$.]*)\s*(\(|\))`)

// LocateAuth finds authentication mechanisms and whether they are global.
func (n *Node) LocateAuth(ctx context.Context, repoRoot string, exclude []string) ([]surface.AuthLayer, error) {
	var layers []surface.AuthLayer

	err := WalkSource(ctx, repoRoot, nodeExts, exclude, func(f SourceFile) error {
		for i, line := range f.Lines {
			lineNo := i + 1
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}

			// A middleware mounted application-wide is the arrangement that
			// protects routes added later, so it is worth distinguishing.
			for _, m := range nodeGlobalUseRe.FindAllStringSubmatch(line, -1) {
				name := m[2]
				if !nodeAuthNameRe.MatchString(name) {
					continue
				}
				layers = append(layers, surface.AuthLayer{
					Kind: "middleware", Name: name, File: f.Path, Line: lineNo,
					Global: true,
					Notes:  "mounted application-wide, so it applies to routes added later",
				})
			}

			switch {
			case strings.Contains(line, "jwt.verify("):
				layers = append(layers, surface.AuthLayer{
					Kind: "jwt", Name: "jwt.verify", File: f.Path, Line: lineNo,
					Notes: "signature is verified",
				})
			case strings.Contains(line, "jwt.decode("):
				layers = append(layers, surface.AuthLayer{
					Kind: "jwt", Name: "jwt.decode", File: f.Path, Line: lineNo,
					Notes: "decodes without verifying the signature",
				})
			case strings.Contains(line, "passport.authenticate("):
				layers = append(layers, surface.AuthLayer{
					Kind: "session", Name: "passport.authenticate", File: f.Path, Line: lineNo,
				})
			case strings.Contains(line, "express-session"), strings.Contains(line, "cookieSession("):
				layers = append(layers, surface.AuthLayer{
					Kind: "session", Name: "express-session", File: f.Path, Line: lineNo,
				})
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return layers, nil
}

// DependencyManifests lists the Node manifests present.
func (n *Node) DependencyManifests(repoRoot string) []string {
	var out []string
	for _, f := range []string{
		"package.json", "package-lock.json", "yarn.lock",
		"pnpm-lock.yaml", "npm-shrinkwrap.json", "bun.lockb",
	} {
		if FileExists(repoRoot, f) {
			out = append(out, f)
		}
	}
	return out
}

var nodeEnvRe = regexp.MustCompile(`process\.env\.([A-Z_][A-Z0-9_]*)|process\.env\[['"]([A-Z_][A-Z0-9_]*)['"]\]`)

// secretNameRe matches identifiers that name a credential.
var secretNameRe = regexp.MustCompile(`(?i)(secret|token|password|passwd|pwd|api_?key|apikey|private_?key|credential|auth|access_?key|client_?secret|dsn|connection_?string)`)

// SecretUsages finds where credentials are read, and flags any that live in
// code shipped to the browser.
func (n *Node) SecretUsages(ctx context.Context, repoRoot string, exclude []string) ([]surface.SecretUsage, error) {
	var out []surface.SecretUsage

	err := WalkSource(ctx, repoRoot, nodeExts, exclude, func(f SourceFile) error {
		clientSide := isClientBundlePath(f.Path)

		for i, line := range f.Lines {
			lineNo := i + 1
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}

			for _, m := range nodeEnvRe.FindAllStringSubmatch(line, -1) {
				name := m[1]
				if name == "" {
					name = m[2]
				}
				if !secretNameRe.MatchString(name) {
					continue
				}
				out = append(out, surface.SecretUsage{
					Name: name, File: f.Path, Line: lineNo,
					Source: "env", ClientBundle: clientSide,
				})
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// isClientBundlePath reports whether a path is code that ships to the browser,
// where anything embedded is readable by anyone.
func isClientBundlePath(p string) bool {
	p = strings.ToLower(p)
	for _, marker := range []string{
		"client/", "frontend/", "web/src/", "src/components/", "src/pages/",
		"public/", "static/", "/app/", "pages/", "components/",
	} {
		if strings.Contains(p, marker) {
			return true
		}
	}
	return false
}
