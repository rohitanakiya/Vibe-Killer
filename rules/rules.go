// Package rules carries Vibe Killer's first-party Semgrep rule pack.
//
// The pack is embedded in the binary so that `go install` produces a single
// self-contained executable: a scan must not depend on the operator having
// cloned the repository to get the rules. Materialize writes the pack to disk
// at scan time, because Semgrep takes rules as files.
package rules

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed vibekiller/*.yaml
var packFS embed.FS

// PackDir is the subdirectory holding the first-party rules.
const PackDir = "vibekiller"

// Files lists the rule files in the embedded pack.
func Files() ([]string, error) {
	entries, err := fs.ReadDir(packFS, PackDir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// Read returns one embedded rule file.
func Read(name string) ([]byte, error) {
	return packFS.ReadFile(filepath.ToSlash(filepath.Join(PackDir, name)))
}

// Materialize writes the embedded pack into dir and returns the directory
// path, which can be handed to Semgrep as a --config value.
func Materialize(dir string) (string, error) {
	target := filepath.Join(dir, PackDir)
	if err := os.MkdirAll(target, 0o755); err != nil {
		return "", fmt.Errorf("creating rule directory: %w", err)
	}

	names, err := Files()
	if err != nil {
		return "", fmt.Errorf("listing embedded rules: %w", err)
	}
	if len(names) == 0 {
		return "", fmt.Errorf("the embedded rule pack is empty")
	}

	for _, name := range names {
		data, err := Read(name)
		if err != nil {
			return "", fmt.Errorf("reading embedded rule %s: %w", name, err)
		}
		if err := os.WriteFile(filepath.Join(target, name), data, 0o644); err != nil {
			return "", fmt.Errorf("writing rule %s: %w", name, err)
		}
	}
	return target, nil
}

// Rule is the subset of a Semgrep rule that Vibe Killer validates. Semgrep
// owns the full schema; this exists so that a malformed first-party rule is
// caught by `go test` rather than at scan time on someone else's machine.
type Rule struct {
	ID        string   `yaml:"id"`
	Message   string   `yaml:"message"`
	Severity  string   `yaml:"severity"`
	Languages []string `yaml:"languages"`
	Mode      string   `yaml:"mode"`
	Metadata  struct {
		Category   string          `yaml:"category"`
		CWE        []string        `yaml:"cwe"`
		OWASP      []string        `yaml:"owasp"`
		Confidence string          `yaml:"confidence"`
		References []string        `yaml:"references"`
		VibeKiller *VibeKillerMeta `yaml:"vibekiller"`
	} `yaml:"metadata"`

	// The matcher keys. Only their presence is checked here, since Semgrep
	// owns the shape of each one, so they decode into any rather than into a
	// typed tree.
	Pattern        any `yaml:"pattern"`
	Patterns       any `yaml:"patterns"`
	PatternEither  any `yaml:"pattern-either"`
	PatternRegex   any `yaml:"pattern-regex"`
	PatternSources any `yaml:"pattern-sources"`
	PatternSinks   any `yaml:"pattern-sinks"`
}

// VibeKillerMeta is the first-party metadata block each rule declares. It is
// what lets a rule state its own contract fields instead of having them
// inferred from its name.
type VibeKillerMeta struct {
	RuleID        string `yaml:"rule_id"`
	Category      string `yaml:"category"`
	Severity      string `yaml:"severity"`
	Confidence    string `yaml:"confidence"`
	Fixable       *bool  `yaml:"fixable_by_giver"`
	HumanRequired string `yaml:"human_required_reason"`
	RootCause     string `yaml:"root_cause_hint"`
	Guidance      string `yaml:"guidance"`
	DynamicRule   string `yaml:"dynamic_rule"`
}

// File is one parsed rule file.
type File struct {
	Name  string `yaml:"-"`
	Rules []Rule `yaml:"rules"`
}

// Parse reads every embedded rule file.
func Parse() ([]File, error) {
	names, err := Files()
	if err != nil {
		return nil, err
	}

	var out []File
	for _, name := range names {
		data, err := Read(name)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", name, err)
		}
		var f File
		if err := yaml.Unmarshal(data, &f); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", name, err)
		}
		f.Name = name
		out = append(out, f)
	}
	return out, nil
}

// DynamicRules lists the endpoint-check rule ids the pack refers to.
//
// A static rule that names a dynamic_rule is promising that an endpoint check
// exists which can try to confirm it. The orchestrator uses this to pair the
// two, and a test checks that every promise is kept.
func DynamicRules() (map[string]string, error) {
	files, err := Parse()
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, f := range files {
		for _, r := range f.Rules {
			if vk := r.Metadata.VibeKiller; vk != nil && vk.DynamicRule != "" {
				out[vk.DynamicRule] = vk.RuleID
			}
		}
	}
	return out, nil
}
