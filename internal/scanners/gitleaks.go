package scanners

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
	"github.com/rohitanakiya/Vibe-Killer/internal/tool"
)

// Gitleaks wraps gitleaks, which finds credentials in a working tree and in
// git history.
//
// The git-history half matters more than it looks: a secret deleted from the
// working tree is still disclosed to anyone with the repository, and that is
// exactly the mistake a generated commit sequence tends to make.
type Gitleaks struct {
	runner *tool.Runner
}

// NewGitleaks builds the wrapper.
func NewGitleaks(runner *tool.Runner) *Gitleaks { return &Gitleaks{runner: runner} }

// Available reports whether gitleaks can run.
func (g *Gitleaks) Available() bool { return g.runner.Available() }

// Name identifies the scanner.
func (g *Gitleaks) Name() string { return "gitleaks" }

// gitleaksHit is one entry of a gitleaks JSON report.
//
// The Secret field is deliberately absent from this struct. gitleaks is
// invoked with --redact so the value never reaches disk, and omitting the
// field means no code path here can copy a credential into a finding even if
// that flag were dropped.
type gitleaksHit struct {
	RuleID      string   `json:"RuleID"`
	Description string   `json:"Description"`
	File        string   `json:"File"`
	StartLine   int      `json:"StartLine"`
	EndLine     int      `json:"EndLine"`
	Commit      string   `json:"Commit"`
	Author      string   `json:"Author"`
	Date        string   `json:"Date"`
	Entropy     float64  `json:"Entropy"`
	Tags        []string `json:"Tags"`
	Fingerprint string   `json:"Fingerprint"`
	Match       string   `json:"Match"`
}

// Run scans the working tree, and git history when the repo has one.
func (g *Gitleaks) Run(ctx context.Context, sc ScanContext, hasGit bool, reportDir string) ([]finding.Finding, []byte, error) {
	var all []gitleaksHit
	var raws [][]byte
	var firstErr error

	modes := []struct {
		name    string
		inGit   bool
		history bool
	}{
		{name: "worktree", history: false},
	}
	if hasGit {
		modes = append(modes, struct {
			name    string
			inGit   bool
			history bool
		}{name: "history", history: true})
	}

	for _, m := range modes {
		hits, raw, err := g.runOne(ctx, sc, reportDir, m.name, m.history)
		if raw != nil {
			raws = append(raws, raw)
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
		all = append(all, hits...)
	}

	if len(all) == 0 && firstErr != nil {
		return nil, joinRaw(raws), firstErr
	}
	return g.toFindings(all, sc, hasGit), joinRaw(raws), nil
}

func joinRaw(raws [][]byte) []byte {
	if len(raws) == 0 {
		return nil
	}
	return []byte("[" + strings.Join(mapStrings(raws), ",\n") + "]")
}

func mapStrings(raws [][]byte) []string {
	out := make([]string, 0, len(raws))
	for _, r := range raws {
		s := strings.TrimSpace(string(r))
		if s == "" {
			s = "[]"
		}
		out = append(out, s)
	}
	return out
}

// runOne invokes gitleaks once, in either worktree or history mode.
//
// gitleaks reports to a file rather than stdout, so the report lands in the
// run's raw directory and is read back from there.
func (g *Gitleaks) runOne(ctx context.Context, sc ScanContext, reportDir, mode string, history bool) ([]gitleaksHit, []byte, error) {
	reportPath := filepath.Join(reportDir, "gitleaks-"+mode+".json")

	args := g.subcommand(ctx, history)
	args = append(args,
		"--report-format", "json",
		"--report-path", reportPath,
		"--no-banner",
		// --redact replaces the credential value in gitleaks' own output, so
		// nothing in the run directory contains a usable secret.
		"--redact",
		"--exit-code", "0",
	)

	_, runErr := g.runner.Run(ctx, sc.RepoRoot, args...)

	data, readErr := os.ReadFile(reportPath)
	if readErr != nil {
		if runErr != nil {
			return nil, nil, runErr
		}
		// No report file and no error means gitleaks found nothing.
		if os.IsNotExist(readErr) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("reading gitleaks report: %w", readErr)
	}

	hits, err := parseGitleaks(data)
	if err != nil {
		if runErr != nil {
			return nil, data, runErr
		}
		return nil, data, err
	}
	return hits, data, nil
}

// subcommand picks the invocation for the installed gitleaks version. v8.19
// introduced `git` and `dir` subcommands and deprecated `detect`.
func (g *Gitleaks) subcommand(ctx context.Context, history bool) []string {
	version, err := g.runner.Version(ctx)
	modern := true
	if err == nil {
		if major, minor := majorMinor(version); major > 0 && (major < 8 || (major == 8 && minor < 19)) {
			modern = false
		}
	}

	if modern {
		if history {
			return []string{"git", "."}
		}
		return []string{"dir", "."}
	}
	if history {
		return []string{"detect", "--source", "."}
	}
	return []string{"detect", "--source", ".", "--no-git"}
}

func majorMinor(s string) (int, int) {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return !(r >= '0' && r <= '9') && r != '.'
	})
	for _, f := range fields {
		parts := strings.Split(strings.TrimPrefix(f, "v"), ".")
		if len(parts) < 2 {
			continue
		}
		major, minor := 0, 0
		if _, err := fmt.Sscanf(parts[0], "%d", &major); err != nil {
			continue
		}
		_, _ = fmt.Sscanf(parts[1], "%d", &minor)
		if major > 0 {
			return major, minor
		}
	}
	return 0, 0
}

func parseGitleaks(data []byte) ([]gitleaksHit, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}
	var hits []gitleaksHit
	if err := json.Unmarshal(data, &hits); err != nil {
		return nil, fmt.Errorf("parsing gitleaks report: %w", err)
	}
	return hits, nil
}

func (g *Gitleaks) toFindings(hits []gitleaksHit, sc ScanContext, hasGit bool) []finding.Finding {
	// The same credential usually appears in both the worktree scan and the
	// history scan, and often in several commits. Collapse to one finding per
	// credential per file, recording whether history is involved, because the
	// remediation differs: a secret in history cannot be fixed by an edit.
	type key struct{ file, rule, fp string }
	type agg struct {
		hit        gitleaksHit
		inWorktree bool
		inHistory  bool
		commits    map[string]bool
	}

	grouped := map[key]*agg{}
	for _, h := range hits {
		file := relPath(sc.RepoRoot, h.File)
		// The grouping fingerprint is derived from the rule and the file, not
		// from the line number, so that a secret moving within a file stays
		// one finding. It is never derived from the credential value.
		fpKey := fingerprint(h.RuleID, file, strings.Join(h.Tags, ","))
		k := key{file: file, rule: h.RuleID, fp: fpKey}

		a, ok := grouped[k]
		if !ok {
			a = &agg{hit: h, commits: map[string]bool{}}
			grouped[k] = a
		}
		if h.Commit == "" {
			a.inWorktree = true
		} else {
			a.inHistory = true
			a.commits[h.Commit] = true
		}
	}

	var fs []finding.Finding
	for k, a := range grouped {
		h := a.hit

		severity := finding.SeverityHigh
		if a.inHistory {
			// A credential that is also in history has been distributed to
			// every clone of the repository.
			severity = finding.SeverityCritical
		}

		var where []string
		if a.inWorktree {
			where = append(where, "the working tree")
		}
		if a.inHistory {
			where = append(where, fmt.Sprintf("git history (%d commit(s))", len(a.commits)))
		}

		guidance := "Rotate this credential at the provider, then remove it from the code and load it from the environment or a secret manager instead."
		humanReason := "an exposed credential has to be rotated by a person at the provider; deleting it from the code does not undo the disclosure"
		if a.inHistory {
			guidance += " Because it is also in git history, rewriting history does not undo the disclosure: assume it is compromised and rotate it first."
		}

		loc := finding.Location{
			Type:    finding.LocationCode,
			File:    k.file,
			Line:    h.StartLine,
			EndLine: h.EndLine,
			RepoRev: sc.RepoRev,
		}

		f := finding.Finding{
			RuleID:   "secrets." + sanitizeRuleSegment(h.RuleID),
			Title:    secretTitle(h, k.file),
			Category: finding.CategorySecretsExposure,
			CWE:      "CWE-798",
			Severity: severity,
			// gitleaks matched a credential pattern with measured entropy;
			// whether the credential is still live is not something a scan can
			// tell, so this stays below confirmed.
			Confidence: finding.ConfidenceLikely,
			Source:     finding.SourceSecrets,
			Location:   loc,
			Evidence: finding.Evidence{
				Summary: fmt.Sprintf("%s detected in %s. Found in %s.",
					firstNonEmpty(h.Description, h.RuleID), k.file, strings.Join(where, " and ")),
				Observed: fmt.Sprintf("match %q (value withheld; entropy %.2f)", maskSecret(h.Match), h.Entropy),
				Expected: "the credential loaded from the environment or a secret manager, and absent from the repository",
				// The evidence key is a hash, never the credential, so this
				// file is safe to attach to a ticket.
				EvidenceKey: "gitleaks:" + k.fp,
			},
			Reproduction: &finding.Reproduction{
				Kind:  finding.ReproStatic,
				Steps: secretReproSteps(k.file, h, a.inHistory),
			},
			Remediation: finding.Remediation{
				Guidance:      guidance,
				RootCauseHint: "A credential was committed to the repository instead of being injected at runtime.",
				// Contract rule: a secrets finding is never auto-fixable. Only
				// a human can rotate a credential, and an automated edit that
				// merely deletes the line would leave the operator exposed
				// while looking resolved.
				FixableByGiver:      false,
				HumanRequiredReason: humanReason,
			},
			Status: finding.StatusOpen,
		}
		f.AssignID()
		fs = append(fs, f)
	}

	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Location.File != fs[j].Location.File {
			return fs[i].Location.File < fs[j].Location.File
		}
		return fs[i].Evidence.EvidenceKey < fs[j].Evidence.EvidenceKey
	})
	return fs
}

func secretTitle(h gitleaksHit, file string) string {
	desc := strings.TrimSpace(h.Description)
	if desc == "" {
		desc = h.RuleID
	}
	return fmt.Sprintf("%s committed to the repository (%s)", truncate(desc, 90), file)
}

func secretReproSteps(file string, h gitleaksHit, inHistory bool) []string {
	steps := []string{
		fmt.Sprintf("Open %s at line %d.", file, h.StartLine),
		"The credential is on that line; its value is withheld from this report.",
	}
	if inHistory && h.Commit != "" {
		steps = append(steps, fmt.Sprintf("It is also reachable from git history: git show %s -- %s", shortCommit(h.Commit), file))
	}
	return steps
}

func shortCommit(c string) string {
	if len(c) > 12 {
		return c[:12]
	}
	return c
}

// sanitizeRuleSegment makes a third-party rule name fit the contract's
// rule_id pattern.
func sanitizeRuleSegment(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	lastDash := true
	for _, r := range s {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			lastDash = false
		case r == '-' || r == '.' || r == '_' || r == ' ' || r == '/':
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-.")
	if out == "" {
		return "credential"
	}
	return out
}
