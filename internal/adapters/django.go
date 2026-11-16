package adapters

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/rohitanakiya/Vibe-Killer/internal/surface"
)

// Django route extraction.
//
// Django is the only supported framework whose routes are not declared where
// the handler lives. Flask and FastAPI put the path in a decorator above the
// function, so one pass over one file yields a complete route; Django puts the
// path in a urls.py that names a view in another module, and the full path of
// any route is the concatenation of every include() between the root URLconf
// and the entry that declares it. Nothing about that can be read a line at a
// time.
//
// What was here before was a single regex over each line, and it was wrong in
// four ways that all pointed the same direction -- it under-reported, while
// the adapter claimed Django support:
//
//   - `path("api/", include("orders.urls"))` matched it, so `include` was
//     recorded as a view and `/api` as a route. The app's real routes were
//     then emitted without the `/api` prefix, so every one of them was a path
//     the server does not serve. An endpoint check requesting them gets 404s
//     and reports nothing, which is indistinguishable from an application
//     with no problems.
//   - Every route was recorded as GET, because a URLconf does not state the
//     method. A POST-only view probed with GET answers 405.
//   - The handler was the view reference and the location was the urls.py
//     line, so a finding pointed at the routing table rather than at the code.
//   - re_path and url patterns are regexes, and were normalized as though
//     they were path() templates.
//
// So this walks the URLconf tree instead: parse every urls.py, find the root,
// then resolve includes depth-first accumulating prefixes, and look the view
// up in its own module to get its file, its line and the methods it actually
// accepts.
//
// Methods are only ever taken from something the source says -- a
// require_http_methods or api_view decorator, the def names in a class-based
// view, a DRF action. A plain function view that inspects request.method
// itself reports GET alone, which is the conservative direction on purpose:
// this adapter's output is what the endpoint checks request, and inventing a
// DELETE that the URLconf never promised would have them send a destructive
// request to an endpoint that might honour it.

var (
	// path("api/", include("orders.urls")) -- and re_path/url, and the
	// namespace and app_name arguments that may follow.
	//
	// The optional paren before the module allows the namespacing form,
	// include(("orders.urls", "orders"), namespace="orders"), which is
	// common enough that not matching it would drop a whole app's routes.
	djangoIncludeRe = regexp.MustCompile(
		`\b(?:path|re_path|url)\s*\(\s*(?:r|b|f|u)?(['"])([^'"]*)['"]\s*,\s*include\s*\(\s*\(?\s*(?:r|b|f|u)?(['"])([^'"]*)['"]`)

	// path("api/", include(router.urls)) -- a DRF router mounted as a whole.
	djangoIncludeRouterRe = regexp.MustCompile(
		`\b(?:path|re_path|url)\s*\(\s*(?:r|b|f|u)?(['"])([^'"]*)['"]\s*,\s*include\s*\(\s*([A-Za-z_]\w*)\s*\.\s*urls\s*\)`)

	// path("orders/<int:pk>/", views.detail) and
	// path("orders/", OrderList.as_view())
	djangoEntryRe = regexp.MustCompile(
		`\b(path|re_path|url)\s*\(\s*(?:r|b|f|u)?(['"])([^'"]*)['"]\s*,\s*([A-Za-z_][\w.]*)\s*(\.\s*as_view\s*\(\s*\))?`)

	// router.register("orders", OrderViewSet) -- basename is optional and
	// irrelevant to the paths.
	djangoRouterRegisterRe = regexp.MustCompile(
		`\b([A-Za-z_]\w*)\s*\.\s*register\s*\(\s*(?:r|b|f|u)?(['"])([^'"]*)['"]\s*,\s*([A-Za-z_][\w.]*)`)

	// ROOT_URLCONF = "project.urls"
	djangoRootURLConfRe = regexp.MustCompile(
		`\bROOT_URLCONF\s*=\s*(['"])([^'"]*)['"]`)

	// A named group in an re_path pattern: (?P<pk>[0-9]+)
	djangoNamedGroupRe = regexp.MustCompile(`\(\?P<(\w+)>[^)]*\)`)

	// An unnamed group in an re_path pattern.
	djangoBareGroupRe = regexp.MustCompile(`\((?:\?:)?[^)]*\)`)

	// def get(self, request, ...) inside a class-based view.
	djangoCBVMethodRe = regexp.MustCompile(
		`(?m)^\s+(?:async\s+)?def\s+(get|post|put|patch|delete|head|options)\s*\(`)

	// http_method_names = ["get", "post"]
	djangoHTTPMethodNamesRe = regexp.MustCompile(
		`http_method_names\s*=\s*\[([^\]]*)\]`)

	// @require_http_methods(["POST"]) / @api_view(["GET", "POST"])
	djangoMethodDecoratorRe = regexp.MustCompile(
		`@\s*(?:[\w.]*\.)?(require_http_methods|api_view)\s*\(\s*\[([^\]]*)\]`)

	// @require_POST and friends.
	djangoShorthandDecoratorRe = regexp.MustCompile(
		`@\s*(?:[\w.]*\.)?require_(POST|GET|safe)\b`)

	// A DRF action method on a ViewSet.
	djangoViewSetActionRe = regexp.MustCompile(
		`(?m)^\s+(?:async\s+)?def\s+(list|create|retrieve|update|partial_update|destroy)\s*\(`)

	// @action(detail=True, methods=["post"], url_path="mark-paid")
	// def mark_paid(self, request, pk=None)
	//
	// A router generates a route per extra action as well as per standard
	// one, so a viewset with three @action methods exposes three endpoints
	// that nothing else in the source names.
	djangoExtraActionRe = regexp.MustCompile(
		`(?ms)@\s*action\s*\(([^)]*)\)\s*\n\s+(?:async\s+)?def\s+(\w+)\s*\(`)

	djangoActionMethodsRe = regexp.MustCompile(`methods\s*=\s*[\[(]([^\])]*)[\])]`)
	djangoActionDetailRe  = regexp.MustCompile(`detail\s*=\s*(True|False)`)
	djangoActionURLPathRe = regexp.MustCompile(`url_path\s*=\s*(?:r|b|f|u)?(['"])([^'"]*)['"]`)
)

// djangoEntry is one line of a urlpatterns list.
type djangoEntry struct {
	kind    string // path, re_path or url
	pattern string // the raw pattern as written
	line    int

	// view is the dotted reference to the view, empty for an include.
	view   string
	asView bool

	// include is the dotted module an include() names, empty otherwise.
	include string

	// router is the local name of a DRF router mounted here, empty otherwise.
	router string
}

// djangoConf is one parsed urls.py.
type djangoConf struct {
	module  string // dotted module path, e.g. "orders.urls"
	file    SourceFile
	entries []djangoEntry

	// routers maps a local router name to the viewsets registered on it.
	routers map[string][]djangoRegistration
}

// djangoRegistration is one router.register call.
type djangoRegistration struct {
	prefix  string
	viewSet string
	line    int
}

// djangoProject is everything the extractor needs to resolve a URLconf tree.
type djangoProject struct {
	// pyRoot is the directory dotted module paths are relative to: the one
	// holding manage.py, which is not always the repository root.
	pyRoot string

	confs map[string]*djangoConf

	// modules indexes every Python file by its dotted module path, so a view
	// reference can be resolved to the file that defines it.
	modules map[string]SourceFile

	rootURLConf string
}

// djangoRoutes enumerates a Django project's routes, or returns nil when the
// repository has no URLconf.
func djangoRoutes(ctx context.Context, repoRoot string, exclude []string) ([]surface.Route, error) {
	proj, err := loadDjangoProject(ctx, repoRoot, exclude)
	if err != nil || proj == nil {
		return nil, err
	}

	root := proj.confs[proj.rootURLConf]
	if root == nil {
		return nil, nil
	}

	var routes []surface.Route
	proj.walk(root, "", map[string]bool{}, &routes)
	return routes, nil
}

// loadDjangoProject parses every urls.py and indexes every module. It returns
// nil when nothing looks like a Django URLconf, so a Flask or FastAPI
// repository costs one walk and no routes.
func loadDjangoProject(ctx context.Context, repoRoot string, exclude []string) (*djangoProject, error) {
	proj := &djangoProject{
		confs:   map[string]*djangoConf{},
		modules: map[string]SourceFile{},
	}

	var settingsFiles []SourceFile
	var urlFiles []SourceFile

	err := WalkSource(ctx, repoRoot, pythonExts, exclude, func(f SourceFile) error {
		base := path.Base(f.Path)
		switch base {
		case "manage.py":
			// The directory holding manage.py is what Django's dotted module
			// paths are relative to, and it is not always the repository root
			// -- "backend/manage.py" is a common layout.
			if dir := path.Dir(f.Path); dir != "." {
				proj.pyRoot = dir
			} else {
				proj.pyRoot = ""
			}
		case "settings.py":
			settingsFiles = append(settingsFiles, f)
		case "urls.py":
			urlFiles = append(urlFiles, f)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(urlFiles) == 0 {
		return nil, nil
	}

	// The module index needs a second walk, because it has to be keyed on
	// pyRoot and pyRoot is only known once manage.py has been seen.
	err = WalkSource(ctx, repoRoot, pythonExts, exclude, func(f SourceFile) error {
		if mod := proj.moduleOf(f.Path); mod != "" {
			proj.modules[mod] = f
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	for _, f := range urlFiles {
		conf := parseDjangoURLConf(f, proj.moduleOf(f.Path))
		if conf != nil {
			proj.confs[conf.module] = conf
		}
	}
	if len(proj.confs) == 0 {
		return nil, nil
	}

	proj.rootURLConf = proj.findRootURLConf(settingsFiles, urlFiles)
	return proj, nil
}

// moduleOf turns a repo-relative file path into the dotted module path Django
// would use for it.
func (p *djangoProject) moduleOf(file string) string {
	rel := file
	if p.pyRoot != "" {
		if !strings.HasPrefix(rel, p.pyRoot+"/") {
			// Outside the Django project directory, so it has no dotted name
			// that an include() could name.
			return ""
		}
		rel = strings.TrimPrefix(rel, p.pyRoot+"/")
	}
	rel = strings.TrimSuffix(rel, ".py")
	rel = strings.TrimSuffix(rel, "/__init__")
	if rel == "" {
		return ""
	}
	return strings.ReplaceAll(rel, "/", ".")
}

// findRootURLConf picks the URLconf the tree starts from.
//
// ROOT_URLCONF in settings is the authority. Failing that, the urls.py beside
// a settings.py is the project one by Django's own convention. Failing that,
// any URLconf that nothing else includes.
func (p *djangoProject) findRootURLConf(settingsFiles, urlFiles []SourceFile) string {
	for _, f := range settingsFiles {
		for _, m := range djangoRootURLConfRe.FindAllStringSubmatch(strings.Join(f.Lines, "\n"), -1) {
			if conf := p.confs[m[2]]; conf != nil {
				return conf.module
			}
		}
	}

	for _, s := range settingsFiles {
		dir := path.Dir(s.Path)
		for _, u := range urlFiles {
			if path.Dir(u.Path) == dir {
				if mod := p.moduleOf(u.Path); p.confs[mod] != nil {
					return mod
				}
			}
		}
	}

	included := map[string]bool{}
	for _, conf := range p.confs {
		for _, e := range conf.entries {
			if e.include != "" {
				included[e.include] = true
			}
		}
	}
	var candidates []string
	for mod := range p.confs {
		if !included[mod] {
			candidates = append(candidates, mod)
		}
	}
	sort.Strings(candidates)
	if len(candidates) > 0 {
		return candidates[0]
	}
	return ""
}

// parseDjangoURLConf reads one urls.py.
func parseDjangoURLConf(f SourceFile, module string) *djangoConf {
	if module == "" {
		return nil
	}
	conf := &djangoConf{module: module, file: f, routers: map[string][]djangoRegistration{}}

	for i, line := range f.Lines {
		lineNo := i + 1
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		for _, m := range djangoRouterRegisterRe.FindAllStringSubmatch(line, -1) {
			name := m[1]
			conf.routers[name] = append(conf.routers[name], djangoRegistration{
				prefix: m[3], viewSet: m[4], line: lineNo,
			})
		}

		if m := djangoIncludeRouterRe.FindStringSubmatch(line); m != nil {
			conf.entries = append(conf.entries, djangoEntry{
				kind: "path", pattern: m[2], line: lineNo, router: m[3],
			})
			continue
		}

		if m := djangoIncludeRe.FindStringSubmatch(line); m != nil {
			conf.entries = append(conf.entries, djangoEntry{
				kind: "path", pattern: m[2], line: lineNo, include: m[4],
			})
			continue
		}

		for _, m := range djangoEntryRe.FindAllStringSubmatch(line, -1) {
			if m[4] == "include" {
				// An include this file's regexes could not read, such as
				// include([...]) with an inline list. Skipping it is right:
				// emitting the prefix as a route would invent an endpoint.
				continue
			}
			// The reference pattern allows dots, so it swallows the
			// ".as_view" of a class-based view and the optional group after
			// it never matches. Trimming it here rather than making the
			// pattern lazy keeps the spaced form -- `BoardList . as_view()`
			// -- working too.
			view, asView := m[4], strings.TrimSpace(m[5]) != ""
			if strings.HasSuffix(view, ".as_view") {
				view = strings.TrimSuffix(view, ".as_view")
				asView = true
			}
			conf.entries = append(conf.entries, djangoEntry{
				kind:    m[1],
				pattern: m[3],
				line:    lineNo,
				view:    view,
				asView:  asView,
			})
		}
	}

	if len(conf.entries) == 0 && len(conf.routers) == 0 {
		return nil
	}
	return conf
}

// walk resolves one URLconf, depth-first, accumulating the prefix.
//
// visiting guards against a cycle, which a URLconf can express by including
// itself through two modules; Django would recurse forever too, but this runs
// over source that may not even import.
func (p *djangoProject) walk(conf *djangoConf, prefix string, visiting map[string]bool, out *[]surface.Route) {
	if conf == nil || visiting[conf.module] {
		return
	}
	visiting[conf.module] = true
	defer delete(visiting, conf.module)

	for _, e := range conf.entries {
		segment := djangoPatternToTemplate(e.kind, e.pattern)
		full := JoinPrefix(prefix, segment)

		switch {
		case e.include != "":
			p.walk(p.confs[e.include], full, visiting, out)

		case e.router != "":
			for _, reg := range conf.routers[e.router] {
				p.appendViewSetRoutes(conf, reg, full, out)
			}

		case e.view != "":
			p.appendViewRoutes(conf, e, full, out)
		}
	}
}

// appendViewRoutes emits the routes for one view reference.
func (p *djangoProject) appendViewRoutes(conf *djangoConf, e djangoEntry, full string, out *[]surface.Route) {
	tmpl, params := NormalizePathTemplate(full)
	if tmpl == "" {
		return
	}

	view := p.resolveView(conf, e.view)
	methods := view.methods
	if len(methods) == 0 {
		methods = []string{"GET"}
	}

	file, line := view.file, view.line
	if file == "" {
		// The view could not be found, so the URLconf line is the only
		// location there is. Better than none: it is where the route is
		// declared, and it is where a reader would start.
		file, line = conf.file.Path, e.line
	}

	for _, method := range methods {
		*out = append(*out, surface.Route{
			Method:       method,
			Path:         tmpl,
			PathParams:   params,
			File:         file,
			Line:         line,
			Handler:      view.name,
			Middleware:   view.decorators,
			DeclaredAuth: view.auth,
			Mutating:     surface.IsMutating(method),
		})
	}
}

// drfActionMethods maps a DRF viewset action to the method and path shape the
// default router gives it.
var drfActionMethods = []struct {
	action string
	method string
	detail bool
}{
	{"list", "GET", false},
	{"create", "POST", false},
	{"retrieve", "GET", true},
	{"update", "PUT", true},
	{"partial_update", "PATCH", true},
	{"destroy", "DELETE", true},
}

// drfBaseActions is what a viewset inherits from the base class it declares.
// Only the two bases that promise a fixed set are listed: anything else has
// to define its actions in the class body, where they can be read.
var drfBaseActions = map[string][]string{
	"ModelViewSet":         {"list", "create", "retrieve", "update", "partial_update", "destroy"},
	"ReadOnlyModelViewSet": {"list", "retrieve"},
}

// appendViewSetRoutes emits the routes a DRF router generates for one
// registered viewset.
func (p *djangoProject) appendViewSetRoutes(conf *djangoConf, reg djangoRegistration, prefix string, out *[]surface.Route) {
	view := p.resolveView(conf, reg.viewSet)

	actions := map[string]bool{}
	for _, a := range view.actions {
		actions[a] = true
	}
	for _, base := range view.bases {
		for _, a := range drfBaseActions[base] {
			actions[a] = true
		}
	}
	if len(actions) == 0 {
		// Nothing says what this viewset serves, and a router mount is not
		// licence to guess at a DELETE.
		return
	}

	listPath := JoinPrefix(prefix, reg.prefix)
	detailPath := JoinPrefix(listPath, "{pk}")

	file, line := view.file, view.line
	if file == "" {
		file, line = conf.file.Path, reg.line
	}

	emit := func(raw, handler, method string) {
		tmpl, params := NormalizePathTemplate(raw)
		if tmpl == "" {
			return
		}
		*out = append(*out, surface.Route{
			Method:       method,
			Path:         tmpl,
			PathParams:   params,
			File:         file,
			Line:         line,
			Handler:      handler,
			Middleware:   view.decorators,
			DeclaredAuth: view.auth,
			Mutating:     surface.IsMutating(method),
		})
	}

	for _, a := range drfActionMethods {
		if !actions[a.action] {
			continue
		}
		raw := listPath
		if a.detail {
			raw = detailPath
		}
		emit(raw, view.name+"."+a.action, a.method)
	}

	// An @action method is a route too, and its methods are stated in the
	// decorator rather than inherited from a base class.
	for _, extra := range view.extras {
		base := listPath
		if extra.detail {
			base = detailPath
		}
		for _, method := range extra.methods {
			emit(JoinPrefix(base, extra.urlPath), view.name+"."+extra.name, method)
		}
	}
}

// djangoExtraActions reads the @action-decorated methods out of a viewset
// body.
//
// url_path overrides the generated segment; without it DRF uses the method
// name with underscores turned into hyphens, so mark_paid is served at
// mark-paid and reading the name verbatim would produce a path the server
// answers 404 for.
func djangoExtraActions(body string) []djangoExtraAction {
	var out []djangoExtraAction

	for _, m := range djangoExtraActionRe.FindAllStringSubmatch(body, -1) {
		args, name := m[1], m[2]

		extra := djangoExtraAction{name: name, urlPath: strings.ReplaceAll(name, "_", "-")}
		if u := djangoActionURLPathRe.FindStringSubmatch(args); u != nil {
			extra.urlPath = u[2]
		}
		if d := djangoActionDetailRe.FindStringSubmatch(args); d != nil {
			extra.detail = d[1] == "True"
		}
		if mm := djangoActionMethodsRe.FindStringSubmatch(args); mm != nil {
			for _, part := range strings.Split(mm[1], ",") {
				part = strings.ToUpper(strings.Trim(strings.TrimSpace(part), `'"`))
				if part != "" {
					extra.methods = appendUnique(extra.methods, part)
				}
			}
		}
		if len(extra.methods) == 0 {
			// DRF's own default when methods is omitted.
			extra.methods = []string{"GET"}
		}
		out = append(out, extra)
	}
	return out
}

// djangoView is what could be learned about a view from its own module.
type djangoView struct {
	name       string
	file       string
	line       int
	methods    []string
	decorators []string
	auth       string

	// bases and actions are the class-based-view details, used for DRF
	// viewsets.
	bases   []string
	actions []string

	// extras are the @action methods a router exposes beyond the standard
	// six.
	extras []djangoExtraAction
}

// djangoExtraAction is one @action-decorated method on a viewset.
type djangoExtraAction struct {
	name    string
	urlPath string
	detail  bool
	methods []string
}

// resolveView finds the module a view reference names and reads what it says.
//
// A URLconf reaches its views through an import, and the import is almost
// always `from . import views` or `from .views import OrderList`, so the
// reference resolves against the URLconf's own package. A dotted reference
// such as orders.views.detail names the module outright.
func (p *djangoProject) resolveView(conf *djangoConf, ref string) djangoView {
	// The full dotted reference is the fallback name. A reference this
	// adapter cannot follow is usually a mount provided by a library, such as
	// admin.site.urls, and "admin.site.urls" tells a reader what it is where
	// the bare last segment, "urls", tells them nothing.
	out := djangoView{name: ref}

	parts := strings.Split(ref, ".")
	symbol := parts[len(parts)-1]

	var candidates []string
	pkg := conf.module
	if i := strings.LastIndex(pkg, "."); i >= 0 {
		pkg = pkg[:i] // orders.urls -> orders
	} else {
		pkg = ""
	}

	switch {
	case len(parts) > 1:
		// A dotted reference: everything before the symbol is a module, which
		// may be absolute or relative to this URLconf's package.
		mod := strings.Join(parts[:len(parts)-1], ".")
		candidates = append(candidates, mod)
		if pkg != "" {
			candidates = append(candidates, pkg+"."+mod)
		}
	default:
		// A bare name, imported from somewhere. views.py is where Django puts
		// them, so look there first and then anywhere in the package.
		if pkg != "" {
			candidates = append(candidates, pkg+".views", pkg+".api", pkg+".viewsets")
		}
		candidates = append(candidates, "views")
	}

	for _, mod := range candidates {
		f, ok := p.modules[mod]
		if !ok {
			continue
		}
		if found := readDjangoView(f, symbol); found != nil {
			found.name = symbol
			return *found
		}
	}
	return out
}

// readDjangoView looks for a function or class by name and reads the methods
// it accepts, its decorators and, for a class, its bases and DRF actions.
func readDjangoView(f SourceFile, symbol string) *djangoView {
	funcRe := regexp.MustCompile(`^\s*(?:async\s+)?def\s+` + regexp.QuoteMeta(symbol) + `\s*\(`)
	classRe := regexp.MustCompile(`^\s*class\s+` + regexp.QuoteMeta(symbol) + `\s*(?:\(([^)]*)\))?\s*:`)

	for i, line := range f.Lines {
		lineNo := i + 1

		if m := classRe.FindStringSubmatch(line); m != nil {
			view := &djangoView{name: symbol, file: f.Path, line: lineNo}
			for _, b := range strings.Split(m[1], ",") {
				b = strings.TrimSpace(b)
				if b == "" {
					continue
				}
				if j := strings.LastIndex(b, "."); j >= 0 {
					b = b[j+1:]
				}
				view.bases = append(view.bases, b)
			}

			body := djangoClassBody(f, i)
			for _, mm := range djangoCBVMethodRe.FindAllStringSubmatch(body, -1) {
				view.methods = appendUnique(view.methods, strings.ToUpper(mm[1]))
			}
			for _, mm := range djangoViewSetActionRe.FindAllStringSubmatch(body, -1) {
				view.actions = appendUnique(view.actions, mm[1])
			}
			view.extras = djangoExtraActions(body)
			if mm := djangoHTTPMethodNamesRe.FindStringSubmatch(body); mm != nil {
				var declared []string
				for _, part := range strings.Split(mm[1], ",") {
					part = strings.ToUpper(strings.Trim(strings.TrimSpace(part), `'"`))
					if part != "" {
						declared = append(declared, part)
					}
				}
				if len(declared) > 0 {
					view.methods = declared
				}
			}

			view.decorators = djangoDecoratorsAbove(f, i)
			view.auth = pythonAuthFromDecorators(view.decorators)
			if view.auth == "" {
				for _, b := range view.bases {
					if strings.Contains(b, "LoginRequired") || strings.Contains(b, "PermissionRequired") {
						view.auth = b
						break
					}
				}
			}
			return view
		}

		if funcRe.MatchString(line) {
			view := &djangoView{name: symbol, file: f.Path, line: lineNo}
			view.decorators = djangoDecoratorsAbove(f, i)
			joined := strings.Join(view.decorators, "\n")
			for _, mm := range djangoMethodDecoratorRe.FindAllStringSubmatch(joined, -1) {
				for _, part := range strings.Split(mm[2], ",") {
					part = strings.ToUpper(strings.Trim(strings.TrimSpace(part), `'"`))
					if part != "" {
						view.methods = appendUnique(view.methods, part)
					}
				}
			}
			for _, mm := range djangoShorthandDecoratorRe.FindAllStringSubmatch(joined, -1) {
				switch mm[1] {
				case "POST":
					view.methods = appendUnique(view.methods, "POST")
				case "GET":
					view.methods = appendUnique(view.methods, "GET")
				case "safe":
					view.methods = appendUnique(view.methods, "GET")
					view.methods = appendUnique(view.methods, "HEAD")
				}
			}
			view.auth = pythonAuthFromDecorators(view.decorators)
			return view
		}
	}
	return nil
}

// djangoClassBody returns the indented block belonging to a class declared at
// the given 0-based line.
func djangoClassBody(f SourceFile, classLine int) string {
	var b strings.Builder
	for i := classLine + 1; i < len(f.Lines); i++ {
		line := f.Lines[i]
		if strings.TrimSpace(line) == "" {
			b.WriteString("\n")
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			break // dedented out of the class
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

// djangoDecoratorsAbove collects the decorator stack immediately above a
// declaration at the given 0-based line.
func djangoDecoratorsAbove(f SourceFile, declLine int) []string {
	var out []string
	for i := declLine - 1; i >= 0; i-- {
		trimmed := strings.TrimSpace(f.Lines[i])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.HasPrefix(trimmed, "@") {
			break
		}
		out = append([]string{trimmed}, out...)
	}
	return out
}

// djangoPatternToTemplate turns one URLconf pattern into a path template.
//
// path() patterns use converters that NormalizePathTemplate already reads.
// re_path and url patterns are regexes, and normalizing one as though it were
// a template produces a path the server does not serve, so the regex syntax is
// stripped first: named groups become their names, anchors and escapes go, and
// an unnamed group becomes a parameter because its position still matters even
// though its name is not recorded.
func djangoPatternToTemplate(kind, pattern string) string {
	if kind == "path" {
		return pattern
	}

	out := pattern
	out = djangoNamedGroupRe.ReplaceAllString(out, "<$1>")

	// Unnamed groups are numbered, because two of them in one pattern would
	// otherwise produce the same parameter name twice and a template cannot
	// say which position is which.
	n := 0
	out = djangoBareGroupRe.ReplaceAllStringFunc(out, func(string) string {
		n++
		if n == 1 {
			return "<param>"
		}
		return fmt.Sprintf("<param%d>", n)
	})
	out = strings.TrimPrefix(out, "^")
	out = strings.TrimSuffix(out, "$")
	out = strings.ReplaceAll(out, `\.`, ".")
	out = strings.ReplaceAll(out, `\/`, "/")
	return out
}

func appendUnique(list []string, v string) []string {
	for _, existing := range list {
		if existing == v {
			return list
		}
	}
	return append(list, v)
}
