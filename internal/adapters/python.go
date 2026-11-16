package adapters

import (
	"context"
	"regexp"
	"strings"

	"github.com/rohitanakiya/Vibe-Killer/internal/surface"
)

func init() { Register(&Python{}) }

// Python is the adapter for Python HTTP services: Flask, FastAPI, Django and
// the small blueprint-based apps generated code tends to produce.
type Python struct{}

// Name identifies the adapter.
func (p *Python) Name() string { return "python" }

var pythonExts = []string{".py"}

// Detect looks for Python packaging files and works out the framework from the
// declared dependencies.
func (p *Python) Detect(repoRoot string) (surface.Detection, bool) {
	manifests := []string{
		"requirements.txt", "pyproject.toml", "Pipfile",
		"setup.py", "setup.cfg", "requirements-dev.txt", "poetry.lock",
	}

	var present []string
	var combined strings.Builder
	for _, m := range manifests {
		if !FileExists(repoRoot, m) {
			continue
		}
		present = append(present, m)
		combined.WriteString(strings.ToLower(ReadFileString(repoRoot, m)))
		combined.WriteString("\n")
	}

	// A repo with .py files but no manifest is still a Python project; the
	// generated ones often have no packaging at all.
	if len(present) == 0 {
		if !FileExists(repoRoot, "app.py") && !FileExists(repoRoot, "main.py") &&
			!FileExists(repoRoot, "manage.py") && !FileExists(repoRoot, "wsgi.py") {
			return surface.Detection{}, false
		}
	}

	det := surface.Detection{
		Adapter:        "python",
		Language:       "python",
		PackageManager: "pip",
		Score:          20,
		Evidence:       present,
	}
	if len(present) == 0 {
		det.Score = 12
		det.Evidence = []string{"python entry point present, no dependency manifest"}
	}

	deps := combined.String()
	switch {
	case FileExists(repoRoot, "manage.py"), strings.Contains(deps, "django"):
		det.Framework = "django"
		det.Score = 60
	case strings.Contains(deps, "fastapi"):
		det.Framework = "fastapi"
		det.Score = 60
	case strings.Contains(deps, "flask"):
		det.Framework = "flask"
		det.Score = 60
	case strings.Contains(deps, "starlette"):
		det.Framework = "starlette"
		det.Score = 50
	case strings.Contains(deps, "aiohttp"):
		det.Framework = "aiohttp"
		det.Score = 50
	}

	// Fall back to imports when there is no manifest to read.
	if det.Framework == "" {
		for _, entry := range []string{"app.py", "main.py", "server.py", "wsgi.py"} {
			src := strings.ToLower(ReadFileString(repoRoot, entry))
			if src == "" {
				continue
			}
			switch {
			case strings.Contains(src, "from flask"), strings.Contains(src, "import flask"):
				det.Framework = "flask"
				det.Score = 50
				det.Evidence = append(det.Evidence, entry+" imports flask")
			case strings.Contains(src, "from fastapi"), strings.Contains(src, "import fastapi"):
				det.Framework = "fastapi"
				det.Score = 50
				det.Evidence = append(det.Evidence, entry+" imports fastapi")
			}
			if det.Framework != "" {
				break
			}
		}
	}

	for _, db := range []struct {
		needle, name string
	}{
		{"psycopg", "postgresql"},
		{"asyncpg", "postgresql"},
		{"pymysql", "mysql"},
		{"mysqlclient", "mysql"},
		{"pymongo", "mongodb"},
		{"motor", "mongodb"},
		{"sqlalchemy", "sql (sqlalchemy)"},
		{"flask-sqlalchemy", "sql (sqlalchemy)"},
		{"sqlite3", "sqlite"},
		{"peewee", "sql (peewee)"},
	} {
		if strings.Contains(deps, db.needle) {
			det.Database = db.name
			break
		}
	}
	if det.Database == "" && det.Framework == "django" {
		det.Database = "sql (django orm)"
	}

	if FileExists(repoRoot, "poetry.lock") || strings.Contains(deps, "[tool.poetry]") {
		det.PackageManager = "poetry"
	} else if FileExists(repoRoot, "Pipfile") {
		det.PackageManager = "pipenv"
	}

	return det, true
}

var (
	// @app.route("/x", methods=["GET", "POST"]) and @bp.route(...)
	pyRouteRe = regexp.MustCompile(
		`@\s*([A-Za-z_][\w.]*)\s*\.\s*route\s*\(\s*(['"])([^'"]*)['"]\s*(?:,\s*methods\s*=\s*\[([^\]]*)\])?`)

	// @app.get("/x") — FastAPI and Flask 2.x shorthands.
	pyMethodRouteRe = regexp.MustCompile(
		`@\s*([A-Za-z_][\w.]*)\s*\.\s*(get|post|put|patch|delete|options|head)\s*\(\s*(['"])([^'"]*)['"]`)

	// Blueprint("name", __name__, url_prefix="/api")
	pyBlueprintRe = regexp.MustCompile(
		`([A-Za-z_]\w*)\s*=\s*Blueprint\s*\([^)]*url_prefix\s*=\s*(['"])([^'"]*)['"]`)

	// APIRouter(prefix="/api")
	pyAPIRouterRe = regexp.MustCompile(
		`([A-Za-z_]\w*)\s*=\s*APIRouter\s*\([^)]*prefix\s*=\s*(['"])([^'"]*)['"]`)

	// register_blueprint(bp, url_prefix="/api")
	pyRegisterBPRe = regexp.MustCompile(
		`register_blueprint\s*\(\s*([A-Za-z_][\w.]*)\s*(?:,\s*url_prefix\s*=\s*(['"])([^'"]*)['"])?`)

	// include_router(router, prefix="/api")
	pyIncludeRouterRe = regexp.MustCompile(
		`include_router\s*\(\s*([A-Za-z_][\w.]*)\s*(?:,\s*prefix\s*=\s*(['"])([^'"]*)['"])?`)

	// Matched on substrings rather than on a list of exact names, because the
	// naming is not standardized: require_auth, auth_required, requires_auth
	// and login_required all appear, and an exact list silently misses
	// whichever ordering the author happened to use.
	//
	// This errs towards recognizing a decorator as authorization. The
	// consequence of a wrong guess in that direction is that this adapter
	// reports the route as protected and the static "route has no auth" rule
	// stays quiet, leaving the dynamic checks to establish the truth by
	// actually calling the endpoint. The opposite error would manufacture a
	// finding about a route that is in fact protected.
	pyAuthDecoratorRe = regexp.MustCompile(
		`(?i)@\s*[\w.]*(auth|login|logout|jwt|token|permission|role|admin|protect|guard|depends|verified|current_user)[\w.]*`)
)

// EnumerateRoutes reads route declarations from Python source.
//
// Decorators sit above the function they decorate, so the adapter looks ahead
// for the def to name the handler, and collects any other decorators in the
// stack as the route's middleware.
func (p *Python) EnumerateRoutes(ctx context.Context, repoRoot string, exclude []string) ([]surface.Route, error) {
	var routes []surface.Route

	err := WalkSource(ctx, repoRoot, pythonExts, exclude, func(f SourceFile) error {
		whole := strings.Join(f.Lines, "\n")

		// Collect router prefixes declared in this file.
		prefixes := map[string]string{}
		for _, re := range []*regexp.Regexp{pyBlueprintRe, pyAPIRouterRe} {
			for _, m := range re.FindAllStringSubmatch(whole, -1) {
				prefixes[m[1]] = m[3]
			}
		}
		// A prefix supplied at registration time overrides the declaration.
		for _, re := range []*regexp.Regexp{pyRegisterBPRe, pyIncludeRouterRe} {
			for _, m := range re.FindAllStringSubmatch(whole, -1) {
				if m[3] != "" {
					name := m[1]
					if i := strings.LastIndex(name, "."); i >= 0 {
						name = name[i+1:]
					}
					prefixes[name] = m[3]
				}
			}
		}

		for i, line := range f.Lines {
			lineNo := i + 1
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}

			addRoute := func(recv, rawPath string, methods []string) {
				prefixName := recv
				if idx := strings.LastIndex(prefixName, "."); idx >= 0 {
					prefixName = prefixName[idx+1:]
				}
				full := JoinPrefix(prefixes[prefixName], rawPath)
				path, params := NormalizePathTemplate(full)
				if path == "" {
					return
				}

				handler, decorators := pythonHandlerAndDecorators(f, lineNo)
				declaredAuth := pythonAuthFromDecorators(decorators)

				for _, method := range methods {
					method = strings.ToUpper(strings.TrimSpace(method))
					if method == "" {
						continue
					}
					routes = append(routes, surface.Route{
						Method:       method,
						Path:         path,
						PathParams:   params,
						File:         f.Path,
						Line:         lineNo,
						Handler:      handler,
						Middleware:   decorators,
						DeclaredAuth: declaredAuth,
						Mutating:     surface.IsMutating(method),
					})
				}
			}

			for _, m := range pyRouteRe.FindAllStringSubmatch(line, -1) {
				methods := []string{"GET"}
				if m[4] != "" {
					methods = parsePythonMethodList(m[4])
				}
				addRoute(m[1], m[3], methods)
			}

			for _, m := range pyMethodRouteRe.FindAllStringSubmatch(line, -1) {
				addRoute(m[1], m[4], []string{strings.ToUpper(m[2])})
			}

		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Django is handled separately because it cannot be read a line at a
	// time: the full path of a route is the concatenation of every include()
	// between the root URLconf and the entry that declares it, and the view
	// that decides which methods it accepts lives in another module. See
	// django.go.
	fromDjango, err := djangoRoutes(ctx, repoRoot, exclude)
	if err != nil {
		return nil, err
	}
	routes = append(routes, fromDjango...)

	return DedupeRoutes(routes), nil
}

// parsePythonMethodList reads the methods= list from a route decorator.
func parsePythonMethodList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		part = strings.Trim(part, `'"`)
		if part != "" {
			out = append(out, strings.ToUpper(part))
		}
	}
	return out
}

// pythonHandlerAndDecorators looks below a route decorator for the function it
// decorates, collecting any other decorators in between.
func pythonHandlerAndDecorators(f SourceFile, decoratorLine int) (string, []string) {
	var decorators []string

	// A decorator stack can be several lines, and the route decorator may not
	// be the innermost one.
	for n := decoratorLine + 1; n <= decoratorLine+12 && n <= len(f.Lines); n++ {
		line := strings.TrimSpace(f.LineAt(n))
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "@") {
			name := strings.TrimPrefix(line, "@")
			if i := strings.IndexByte(name, '('); i > 0 {
				name = name[:i]
			}
			decorators = append(decorators, strings.TrimSpace(name))
			continue
		}

		if strings.HasPrefix(line, "def ") || strings.HasPrefix(line, "async def ") {
			rest := strings.TrimPrefix(strings.TrimPrefix(line, "async "), "def ")
			if i := strings.IndexByte(rest, '('); i > 0 {
				return strings.TrimSpace(rest[:i]), decorators
			}
			return "", decorators
		}

		// Anything else means the decorator was not attached to a function in
		// the expected shape.
		break
	}

	return "", decorators
}

// pythonAuthFromDecorators reports which decorators look like authorization.
func pythonAuthFromDecorators(decorators []string) string {
	var hits []string
	for _, d := range decorators {
		if pyAuthDecoratorRe.MatchString("@" + d) {
			hits = append(hits, d)
		}
	}
	return strings.Join(hits, ", ")
}

// LocateAuth finds Python authentication mechanisms.
func (p *Python) LocateAuth(ctx context.Context, repoRoot string, exclude []string) ([]surface.AuthLayer, error) {
	var layers []surface.AuthLayer

	err := WalkSource(ctx, repoRoot, pythonExts, exclude, func(f SourceFile) error {
		for i, line := range f.Lines {
			lineNo := i + 1
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}

			switch {
			case strings.Contains(line, "jwt.decode(") && strings.Contains(line, "verify=False"):
				layers = append(layers, surface.AuthLayer{
					Kind: "jwt", Name: "jwt.decode", File: f.Path, Line: lineNo,
					Notes: "signature verification is disabled",
				})
			case strings.Contains(line, "jwt.decode("):
				layers = append(layers, surface.AuthLayer{
					Kind: "jwt", Name: "jwt.decode", File: f.Path, Line: lineNo,
				})
			case strings.Contains(line, "LoginManager("):
				layers = append(layers, surface.AuthLayer{
					Kind: "session", Name: "flask-login", File: f.Path, Line: lineNo, Global: true,
				})
			case strings.Contains(line, "before_request"):
				layers = append(layers, surface.AuthLayer{
					Kind: "middleware", Name: "before_request", File: f.Path, Line: lineNo,
					Global: true,
					Notes:  "runs before every request in its scope, so it applies to routes added later",
				})
			case strings.Contains(line, "HTTPBearer("), strings.Contains(line, "OAuth2PasswordBearer("):
				layers = append(layers, surface.AuthLayer{
					Kind: "jwt", Name: "fastapi security scheme", File: f.Path, Line: lineNo,
				})
			case strings.Contains(line, "AuthenticationMiddleware"):
				layers = append(layers, surface.AuthLayer{
					Kind: "middleware", Name: "AuthenticationMiddleware", File: f.Path, Line: lineNo, Global: true,
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

// DependencyManifests lists the Python manifests present.
func (p *Python) DependencyManifests(repoRoot string) []string {
	var out []string
	for _, f := range []string{
		"requirements.txt", "requirements-dev.txt", "pyproject.toml",
		"poetry.lock", "Pipfile", "Pipfile.lock", "setup.py", "setup.cfg",
	} {
		if FileExists(repoRoot, f) {
			out = append(out, f)
		}
	}
	return out
}

var pyEnvRe = regexp.MustCompile(
	`os\.environ\.get\s*\(\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]|os\.environ\s*\[\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*\]|os\.getenv\s*\(\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]`)

// SecretUsages finds where Python code reads credentials.
func (p *Python) SecretUsages(ctx context.Context, repoRoot string, exclude []string) ([]surface.SecretUsage, error) {
	var out []surface.SecretUsage

	err := WalkSource(ctx, repoRoot, pythonExts, exclude, func(f SourceFile) error {
		for i, line := range f.Lines {
			lineNo := i + 1
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			for _, m := range pyEnvRe.FindAllStringSubmatch(line, -1) {
				name := firstNonEmptyString(m[1], m[2], m[3])
				if name == "" || !secretNameRe.MatchString(name) {
					continue
				}
				out = append(out, surface.SecretUsage{
					Name: name, File: f.Path, Line: lineNo, Source: "env",
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

func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
