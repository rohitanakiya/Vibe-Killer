package scanners

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
	"github.com/rohitanakiya/Vibe-Killer/internal/tool"
)

// OSV wraps osv-scanner, which resolves the dependency tree from lockfiles and
// manifests and matches it against the OSV vulnerability database.
type OSV struct {
	runner *tool.Runner
}

// NewOSV builds the wrapper.
func NewOSV(runner *tool.Runner) *OSV { return &OSV{runner: runner} }

// Available reports whether osv-scanner can run.
func (o *OSV) Available() bool { return o.runner.Available() }

// Name identifies the scanner.
func (o *OSV) Name() string { return "osv-scanner" }

type osvOutput struct {
	Results []struct {
		Source struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"source"`
		Packages []struct {
			Package struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Vulnerabilities []osvVuln `json:"vulnerabilities"`
			Groups          []struct {
				IDs         []string `json:"ids"`
				Aliases     []string `json:"aliases"`
				MaxSeverity string   `json:"max_severity"`
			} `json:"groups"`
		} `json:"packages"`
	} `json:"results"`
}

type osvVuln struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	Affected []struct {
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

// Run invokes osv-scanner over the repo.
func (o *OSV) Run(ctx context.Context, sc ScanContext) ([]finding.Finding, []byte, error) {
	args, err := o.args(ctx)
	if err != nil {
		return nil, nil, err
	}

	res, err := o.runner.Run(ctx, sc.RepoRoot, args...)
	if res == nil {
		return nil, nil, err
	}
	// osv-scanner exits non-zero when it finds vulnerabilities, which the
	// Spec already allows, but it also exits non-zero when a repo simply has
	// no lockfile. Treat parseable output as success regardless.
	fs, parseErr := o.parse(res.Stdout, sc)
	if parseErr == nil {
		return fs, res.Stdout, nil
	}
	if err != nil {
		return nil, res.Stdout, err
	}
	return nil, res.Stdout, parseErr
}

// args picks the invocation for the installed osv-scanner major version.
// v2 moved scanning behind a `scan source` subcommand; v1 took the directory
// directly.
func (o *OSV) args(ctx context.Context) ([]string, error) {
	version, err := o.runner.Version(ctx)
	if err != nil {
		// If the version cannot be read, prefer the v2 form: it is what a
		// fresh install gets.
		return []string{"scan", "source", "--format", "json", "--recursive", "."}, nil
	}

	if major := majorVersion(version); major >= 2 {
		return []string{"scan", "source", "--format", "json", "--recursive", "."}, nil
	}
	return []string{"--format", "json", "--recursive", "."}, nil
}

// majorVersion pulls the leading major version number out of a version banner.
func majorVersion(s string) int {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return !(r >= '0' && r <= '9') && r != '.'
	})
	for _, f := range fields {
		parts := strings.Split(f, ".")
		if n, err := strconv.Atoi(parts[0]); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

func (o *OSV) parse(data []byte, sc ScanContext) ([]finding.Finding, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, nil
	}

	var out osvOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("parsing osv-scanner output: %w", err)
	}

	var fs []finding.Finding
	for _, result := range out.Results {
		manifest := relPath(sc.RepoRoot, result.Source.Path)

		for _, pkg := range result.Packages {
			// A package often has several advisories that osv-scanner groups
			// as aliases of one another. Report the group once, keyed on the
			// representative id, rather than three findings for one upgrade.
			reported := map[string]bool{}
			groupOf := func(id string) []string {
				for _, g := range pkg.Groups {
					for _, gid := range g.IDs {
						if gid == id {
							return g.IDs
						}
					}
				}
				return []string{id}
			}

			for _, v := range pkg.Vulnerabilities {
				if reported[v.ID] {
					continue
				}
				group := groupOf(v.ID)
				for _, id := range group {
					reported[id] = true
				}

				f := finding.Finding{
					RuleID:   "deps.known-vulnerability",
					Title:    osvTitle(v, pkg.Package.Name, pkg.Package.Version),
					Category: finding.CategoryVulnerableDep,
					CWE:      "CWE-1395",
					Severity: osvSeverity(v),
					// The advisory database is authoritative that this version
					// is affected, but whether the vulnerable code path is
					// reachable from this app is not something a dependency
					// scan can know.
					Confidence: finding.ConfidenceLikely,
					Source:     finding.SourceDeps,
					Location: finding.Location{
						Type:      finding.LocationDependency,
						File:      manifest,
						Package:   pkg.Package.Name,
						Ecosystem: pkg.Package.Ecosystem,
						Version:   pkg.Package.Version,
						RepoRev:   sc.RepoRev,
					},
					Evidence: finding.Evidence{
						Summary: fmt.Sprintf("%s %s is affected by %s. %s",
							pkg.Package.Name, pkg.Package.Version,
							strings.Join(group, ", "),
							truncate(firstNonEmpty(v.Summary, v.Details), 500)),
						Observed:    fmt.Sprintf("%s resolves to %s in %s", pkg.Package.Name, pkg.Package.Version, manifest),
						Expected:    osvExpected(v),
						EvidenceKey: "osv:" + v.ID,
					},
					Reproduction: &finding.Reproduction{
						Kind: finding.ReproStatic,
						Steps: []string{
							fmt.Sprintf("Resolve dependencies from %s.", manifest),
							fmt.Sprintf("Observe %s at version %s.", pkg.Package.Name, pkg.Package.Version),
							fmt.Sprintf("Compare against advisory %s.", v.ID),
						},
					},
					Remediation: finding.Remediation{
						Guidance:       osvGuidance(v, pkg.Package.Name),
						RootCauseHint:  "A dependency is pinned to a version with a published advisory.",
						References:     osvReferences(v),
						FixableByGiver: true,
					},
					Status: finding.StatusOpen,
				}
				f.AssignID()
				fs = append(fs, f)
			}
		}
	}

	// Deterministic order keeps findings.json diffable between runs.
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Location.Package != fs[j].Location.Package {
			return fs[i].Location.Package < fs[j].Location.Package
		}
		return fs[i].Evidence.EvidenceKey < fs[j].Evidence.EvidenceKey
	})
	return fs, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

func osvTitle(v osvVuln, pkg, version string) string {
	summary := strings.TrimSpace(v.Summary)
	if summary == "" {
		return fmt.Sprintf("%s %s has a known vulnerability (%s)", pkg, version, v.ID)
	}
	return fmt.Sprintf("%s %s: %s", pkg, version, truncate(summary, 120))
}

// osvSeverity maps an advisory to a contract severity, preferring the
// database's own qualitative rating and falling back to the CVSS base score.
func osvSeverity(v osvVuln) finding.Severity {
	switch strings.ToUpper(strings.TrimSpace(v.DatabaseSpecific.Severity)) {
	case "CRITICAL":
		return finding.SeverityCritical
	case "HIGH":
		return finding.SeverityHigh
	case "MODERATE", "MEDIUM":
		return finding.SeverityMedium
	case "LOW":
		return finding.SeverityLow
	}

	for _, s := range v.Severity {
		if score, ok := cvssBaseScore(s.Score); ok {
			switch {
			case score >= 9.0:
				return finding.SeverityCritical
			case score >= 7.0:
				return finding.SeverityHigh
			case score >= 4.0:
				return finding.SeverityMedium
			case score > 0:
				return finding.SeverityLow
			}
		}
	}

	// An advisory with no rating is still worth reporting, but not worth
	// failing a CI gate over on its own.
	return finding.SeverityMedium
}

// cvssBaseScore reads a numeric score, accepting either a bare number or a
// CVSS vector string with no numeric score attached.
func cvssBaseScore(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f, true
	}
	return 0, false
}

// osvExpected states the fixed version when the advisory names one.
func osvExpected(v osvVuln) string {
	var fixes []string
	for _, a := range v.Affected {
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					fixes = append(fixes, e.Fixed)
				}
			}
		}
	}
	if len(fixes) == 0 {
		return "a version not covered by this advisory"
	}
	sort.Strings(fixes)
	return "at least " + fixes[0]
}

func osvGuidance(v osvVuln, pkg string) string {
	if e := osvExpected(v); strings.HasPrefix(e, "at least ") {
		return fmt.Sprintf("Upgrade %s to %s, then re-resolve the lockfile.", pkg, strings.TrimPrefix(e, "at least "))
	}
	return fmt.Sprintf("Upgrade %s to a version this advisory does not cover, or remove the dependency.", pkg)
}

func osvReferences(v osvVuln) []string {
	refs := []string{"https://osv.dev/vulnerability/" + v.ID}
	for _, r := range v.References {
		if strings.EqualFold(r.Type, "ADVISORY") && r.URL != "" {
			refs = append(refs, r.URL)
		}
	}
	if len(refs) > 4 {
		refs = refs[:4]
	}
	return refs
}
