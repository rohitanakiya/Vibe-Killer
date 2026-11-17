package adapters

import (
	"regexp"
	"strings"

	"github.com/rohitanakiya/Vibe-Killer/internal/surface"
)

// The Node frameworks whose route path is not where the route is declared.
//
// Express puts the whole path in the call, so one regex over one line is
// enough and node.go handles it. The three frameworks here do not, and the
// adapter claimed all three while reading none of them correctly. Measured
// against internal/adapters/testdata/node-frameworks before any of this
// existed, it reported nine routes of which seven were paths no server
// serves:
//
//	NestJS   @Controller('nest/invoices') was ignored entirely, so
//	         @Get(':id') came out as "/{id}" and @Get() as "/". Four routes,
//	         four wrong paths. This is Django's include() defect again: the
//	         prefix lives somewhere other than the declaration, so reading
//	         the declaration alone produces a 404 for every probe.
//
//	koa      new Router({ prefix: '/koa' }) was ignored, so /koa/tickets/:id
//	         came out as "/tickets/{id}". A koa router carries its prefix at
//	         construction rather than taking one at use() time, which is why
//	         the Express mount regex does not see it.
//
//	fastify  the object form was matched by a single regex requiring method
//	         before url. Fastify promises no key order, and
//	         { url: ..., method: 'DELETE' } was missed completely -- a route
//	         that exists and is never probed, which reads in the output
//	         exactly like a route with nothing wrong.

var (
	// @Controller('orders') — the prefix every route in the class hangs off.
	// An argumentless @Controller() is a controller at the root.
	nodeNestControllerRe = regexp.MustCompile(
		`@Controller\s*\(\s*(?:['"]([^'"]*)['"])?\s*\)`)

	// A method's name, on the first line after its decorator stack.
	nodeNestMethodRe = regexp.MustCompile(
		`^\s*(?:public|private|protected)?\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*\(`)

	// @UseGuards(AuthGuard) and the decorators that accompany it. A guarded
	// route reported as unguarded is worse than no information: the endpoint
	// layer probes it expecting no credentials to be needed.
	nodeNestGuardRe = regexp.MustCompile(
		`@(UseGuards|Roles|Permissions|RequirePermissions|Auth)\s*\(([^)]*)\)`)

	// new Router({ prefix: '/api' }) — koa-router and @koa/router.
	nodeRouterPrefixRe = regexp.MustCompile(
		`([A-Za-z_$][\w$]*)\s*=\s*new\s+[\w.]*Router\s*\(\s*\{[^}]*prefix\s*:\s*(['"])([^'"]*)['"]`)

	// The keys read out of a fastify route object, each on its own.
	nodeFastifyMethodRe = regexp.MustCompile(`\bmethod\s*:\s*\[?\s*['"]([A-Za-z]+)['"]`)
	nodeFastifyURLRe    = regexp.MustCompile(`\burl\s*:\s*['"]([^'"]+)['"]`)
)

// nodeRouterPrefixes returns the construction-time prefixes declared in a
// file, keyed by the variable holding the router.
func nodeRouterPrefixes(whole string) map[string]string {
	out := map[string]string{}
	for _, m := range nodeRouterPrefixRe.FindAllStringSubmatch(whole, -1) {
		if m[3] != "" {
			out[m[1]] = m[3]
		}
	}
	return out
}

// nodeNestRoutes extracts a NestJS controller's routes, joined to the prefix
// the controller declares.
func nodeNestRoutes(f SourceFile) []surface.Route {
	var out []surface.Route

	// The controller in scope for a line is the nearest @Controller above it.
	// One controller per file is the convention, but a file may hold several
	// and getting that wrong would attach routes to the wrong prefix.
	type controller struct {
		line   int
		prefix string
	}
	var controllers []controller
	for i, line := range f.Lines {
		for _, m := range nodeNestControllerRe.FindAllStringSubmatch(line, -1) {
			controllers = append(controllers, controller{line: i + 1, prefix: m[1]})
		}
	}

	prefixFor := func(lineNo int) string {
		prefix := ""
		for _, c := range controllers {
			if c.line <= lineNo {
				prefix = c.prefix
				continue
			}
			break
		}
		return prefix
	}

	for i, line := range f.Lines {
		lineNo := i + 1
		for _, m := range nodeNestRe.FindAllStringSubmatch(line, -1) {
			method := strings.ToUpper(m[1])

			full := JoinPrefix(prefixFor(lineNo), m[2])
			path, params := NormalizePathTemplate(full)
			if path == "" {
				path = "/"
			}

			handler, decorators := nodeNestHandlerAndDecorators(f, lineNo)
			out = append(out, surface.Route{
				Method:       method,
				Path:         path,
				PathParams:   params,
				File:         f.Path,
				Line:         lineNo,
				Handler:      handler,
				Middleware:   decorators,
				DeclaredAuth: nodeNestAuth(decorators),
				Mutating:     surface.IsMutating(method),
			})
		}
	}
	return out
}

// nodeNestHandlerAndDecorators looks below a route decorator for the method it
// decorates, collecting the other decorators in the stack on the way.
func nodeNestHandlerAndDecorators(f SourceFile, decoratorLine int) (string, []string) {
	var decorators []string

	for i := decoratorLine; i < len(f.Lines) && i < decoratorLine+12; i++ {
		trimmed := strings.TrimSpace(f.Lines[i])
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}
		if strings.HasPrefix(trimmed, "@") {
			decorators = append(decorators, trimmed)
			continue
		}
		if m := nodeNestMethodRe.FindStringSubmatch(f.Lines[i]); m != nil {
			return m[1], decorators
		}
		break
	}
	return "", decorators
}

// nodeNestAuth reports the authorization a decorator stack declares.
func nodeNestAuth(decorators []string) string {
	for _, d := range decorators {
		if m := nodeNestGuardRe.FindStringSubmatch(d); m != nil {
			arg := strings.TrimSpace(m[2])
			if arg == "" {
				return m[1]
			}
			return m[1] + "(" + arg + ")"
		}
	}
	// A decorator that merely looks like authorization still counts, for the
	// reason the Python adapter records: reporting a route as protected when
	// it is not leaves the dynamic checks to establish the truth, while the
	// opposite error manufactures a finding about a protected route.
	return authFromMiddleware(decorators)
}

// nodeFastifyObjectRoutes extracts fastify's object form, reading method and
// url independently so their order in the object does not matter.
func nodeFastifyObjectRoutes(f SourceFile) []surface.Route {
	whole := strings.Join(f.Lines, "\n")
	var out []surface.Route

	for _, block := range braceBlocksAfter(whole, "route(") {
		mm := nodeFastifyMethodRe.FindStringSubmatch(block.text)
		um := nodeFastifyURLRe.FindStringSubmatch(block.text)
		if mm == nil || um == nil {
			continue
		}
		method := strings.ToUpper(mm[1])
		path, params := NormalizePathTemplate(um[1])
		if path == "" {
			continue
		}
		out = append(out, surface.Route{
			Method:     method,
			Path:       path,
			PathParams: params,
			File:       f.Path,
			Line:       1 + strings.Count(whole[:block.start], "\n"),
			Mutating:   surface.IsMutating(method),
		})
	}
	return out
}

// block is one brace-delimited span of a file.
type block struct {
	start int
	text  string
}

// braceBlocksAfter returns the balanced {...} blocks that follow each
// occurrence of marker.
//
// Brace matching rather than a regex, because a regex either stops at the
// first closing brace -- cutting the object off at its first nested one -- or
// runs to the last, swallowing every route in the file into one match.
func braceBlocksAfter(s, marker string) []block {
	var out []block

	for i := 0; i < len(s); {
		j := strings.Index(s[i:], marker)
		if j < 0 {
			break
		}
		j += i + len(marker)

		open := strings.IndexByte(s[j:], '{')
		if open < 0 {
			break
		}
		open += j

		depth := 0
		end := -1
		for k := open; k < len(s); k++ {
			switch s[k] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					end = k
				}
			}
			if end >= 0 {
				break
			}
		}
		if end < 0 {
			break
		}
		out = append(out, block{start: open, text: s[open : end+1]})
		i = end + 1
	}
	return out
}
