// Package adapters holds the per-stack logic, behind one interface.
//
// Vibe Killer is meant to work against whatever the target was generated in,
// so nothing in the engine may assume a language or framework. Everything
// stack-specific lives in a StackAdapter: detecting the stack, enumerating
// routes, finding the authorization layer, locating dependency manifests, and
// attaching a runtime observer. Supporting a new stack is a new adapter, never
// a change to the core.
//
// Route enumeration here reads source text rather than running the target, so
// it is necessarily approximate. Adapters are expected to under-report rather
// than invent: a route the mapper missed costs coverage, while a route it
// imagined would produce a finding against an endpoint that does not exist.
package adapters

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rohitanakiya/Vibe-Killer/internal/surface"
)

// StackAdapter is the per-stack contract.
type StackAdapter interface {
	// Name identifies the adapter, e.g. "node-express".
	Name() string

	// Detect reports whether this adapter matches the repository, and with
	// what confidence. A repository can match several adapters; the mapper
	// picks the highest score and records the rest.
	Detect(repoRoot string) (surface.Detection, bool)

	// EnumerateRoutes reads the endpoints the application exposes.
	EnumerateRoutes(ctx context.Context, repoRoot string, exclude []string) ([]surface.Route, error)

	// LocateAuth finds the authentication and authorization mechanisms.
	LocateAuth(ctx context.Context, repoRoot string, exclude []string) ([]surface.AuthLayer, error)

	// DependencyManifests lists the manifest and lockfiles present.
	DependencyManifests(repoRoot string) []string

	// SecretUsages finds where the application reads credentials.
	SecretUsages(ctx context.Context, repoRoot string, exclude []string) ([]surface.SecretUsage, error)
}

// Registry holds the available adapters.
type Registry struct {
	adapters []StackAdapter
}

// Default is the registry adapters register into at init time.
var Default = &Registry{}

// Register adds an adapter.
func Register(a StackAdapter) { Default.adapters = append(Default.adapters, a) }

// All returns the registered adapters, ordered by name for determinism.
func (r *Registry) All() []StackAdapter {
	out := append([]StackAdapter(nil), r.adapters...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// Match picks the best adapter for a repository, and reports the other stacks
// that were also detected.
//
// Reporting the others matters: a repo with a Python backend and a Node
// frontend will match twice, and an operator should see that the scan modelled
// one of them rather than silently assuming.
func (r *Registry) Match(repoRoot string) (StackAdapter, surface.Detection, []string) {
	var best StackAdapter
	var bestDet surface.Detection
	var others []string

	for _, a := range r.All() {
		det, ok := a.Detect(repoRoot)
		if !ok {
			continue
		}
		if best == nil || det.Score > bestDet.Score {
			if best != nil {
				others = append(others, bestDet.Adapter)
			}
			best, bestDet = a, det
			continue
		}
		others = append(others, det.Adapter)
	}

	sort.Strings(others)
	return best, bestDet, others
}

// --- shared helpers for adapters -------------------------------------------

// SourceFile is one file an adapter is scanning.
type SourceFile struct {
	// Path is repo-relative with forward slashes.
	Path string

	// Abs is the absolute path.
	Abs string

	// Lines is the file split on newlines, 0-indexed.
	Lines []string
}

// LineAt returns a line by 1-based number, or "".
func (f SourceFile) LineAt(n int) string {
	if n < 1 || n > len(f.Lines) {
		return ""
	}
	return f.Lines[n-1]
}

// MaxFileBytes bounds how large a file an adapter will read. A generated
// bundle or a checked-in dataset is not worth parsing for routes, and reading
// it would dominate the scan.
const MaxFileBytes = 2 << 20 // 2 MiB

// DefaultExclude are directories never worth scanning for application code.
var DefaultExclude = []string{
	"node_modules", "vendor", ".git", "dist", "build", "out", "coverage",
	".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache",
	"target", ".next", ".nuxt", ".svelte-kit", "bin", "obj", ".tox",
	".idea", ".vscode", "site-packages",
}

// WalkSource visits every source file with one of the given extensions.
//
// It skips the directories in DefaultExclude plus anything matching the
// operator's exclude patterns, and it stops on context cancellation so that
// Ctrl-C during mapping returns promptly.
func WalkSource(ctx context.Context, repoRoot string, exts []string, exclude []string, fn func(SourceFile) error) error {
	wantExt := map[string]bool{}
	for _, e := range exts {
		wantExt[strings.ToLower(e)] = true
	}

	skipDir := map[string]bool{}
	for _, d := range DefaultExclude {
		skipDir[d] = true
	}

	return filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable directory is not a reason to abandon the scan.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		name := d.Name()
		if d.IsDir() {
			if skipDir[name] || (strings.HasPrefix(name, ".") && name != "." && path != repoRoot) {
				return fs.SkipDir
			}
			return nil
		}

		if !wantExt[strings.ToLower(filepath.Ext(name))] {
			return nil
		}

		rel, relErr := filepath.Rel(repoRoot, path)
		if relErr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)

		if matchesAny(rel, exclude) {
			return nil
		}

		info, statErr := d.Info()
		if statErr != nil || info.Size() > MaxFileBytes {
			return nil
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}

		return fn(SourceFile{
			Path:  rel,
			Abs:   path,
			Lines: strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n"),
		})
	})
}

// matchesAny reports whether a repo-relative path matches any glob pattern.
func matchesAny(rel string, patterns []string) bool {
	for _, p := range patterns {
		p = filepath.ToSlash(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		// Support the common "dir/**" form by matching on the prefix.
		if strings.HasSuffix(p, "/**") {
			if strings.HasPrefix(rel, strings.TrimSuffix(p, "/**")+"/") {
				return true
			}
			continue
		}
		if ok, err := filepath.Match(p, rel); err == nil && ok {
			return true
		}
		if ok, err := filepath.Match(p, filepath.Base(rel)); err == nil && ok {
			return true
		}
	}
	return false
}

// FileExists reports whether a path exists under the repo root.
func FileExists(repoRoot, rel string) bool {
	_, err := os.Stat(filepath.Join(repoRoot, filepath.FromSlash(rel)))
	return err == nil
}

// ReadFileString reads a repo-relative file, returning "" if it cannot be
// read.
func ReadFileString(repoRoot, rel string) string {
	data, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(rel)))
	if err != nil || len(data) > MaxFileBytes {
		return ""
	}
	return string(data)
}

// FindFiles returns repo-relative paths of files with the given base names.
func FindFiles(ctx context.Context, repoRoot string, names []string, exclude []string) []string {
	want := map[string]bool{}
	for _, n := range names {
		want[strings.ToLower(n)] = true
	}

	skipDir := map[string]bool{}
	for _, d := range DefaultExclude {
		skipDir[d] = true
	}

	var out []string
	_ = filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			name := d.Name()
			if skipDir[name] || (strings.HasPrefix(name, ".") && path != repoRoot) {
				return fs.SkipDir
			}
			return nil
		}
		if !want[strings.ToLower(d.Name())] {
			return nil
		}
		rel, relErr := filepath.Rel(repoRoot, path)
		if relErr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if matchesAny(rel, exclude) {
			return nil
		}
		out = append(out, rel)
		return nil
	})

	sort.Strings(out)
	return out
}

// NormalizePathTemplate rewrites a framework's route syntax into the {param}
// form the findings contract uses, and returns the parameter names.
//
// Express writes :id, Flask writes <int:id>, FastAPI and Spring write {id}.
// Normalizing here means the rest of the system compares routes without
// knowing which framework produced them.
func NormalizePathTemplate(path string) (string, []string) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", nil
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	segs := strings.Split(path, "/")
	var params []string

	for i, s := range segs {
		switch {
		case s == "":
			continue

		case strings.HasPrefix(s, ":"):
			// Express / Sinatra style.
			name := strings.TrimSuffix(strings.TrimPrefix(s, ":"), "?")
			params = append(params, name)
			segs[i] = "{" + name + "}"

		case strings.HasPrefix(s, "<") && strings.HasSuffix(s, ">"):
			// Flask style, optionally with a converter prefix.
			inner := strings.TrimSuffix(strings.TrimPrefix(s, "<"), ">")
			if idx := strings.LastIndex(inner, ":"); idx >= 0 {
				inner = inner[idx+1:]
			}
			params = append(params, inner)
			segs[i] = "{" + inner + "}"

		case strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}"):
			inner := strings.TrimSuffix(strings.TrimPrefix(s, "{"), "}")
			if idx := strings.Index(inner, ":"); idx >= 0 {
				inner = inner[:idx]
			}
			params = append(params, inner)
			segs[i] = "{" + inner + "}"

		case strings.HasPrefix(s, "*"):
			params = append(params, "wildcard")
			segs[i] = "{wildcard}"
		}
	}

	out := strings.Join(segs, "/")
	if len(out) > 1 {
		out = strings.TrimSuffix(out, "/")
	}
	if out == "" {
		out = "/"
	}
	return out, params
}

// JoinPrefix combines a router mount prefix with a route path.
func JoinPrefix(prefix, path string) string {
	prefix = strings.TrimSuffix(strings.TrimSpace(prefix), "/")
	path = strings.TrimSpace(path)
	if prefix == "" {
		return path
	}
	if path == "/" || path == "" {
		return prefix
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return prefix + path
}

// DedupeRoutes removes duplicate method-and-path pairs, keeping the first
// occurrence, which is the one with a real file and line.
func DedupeRoutes(routes []surface.Route) []surface.Route {
	seen := map[string]bool{}
	var out []surface.Route
	for _, r := range routes {
		key := strings.ToUpper(r.Method) + " " + r.Path
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Method < out[j].Method
	})
	return out
}
