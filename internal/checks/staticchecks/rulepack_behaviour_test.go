package staticchecks

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/rohitanakiya/Vibe-Killer/internal/tool"
)

// Executes the annotations in rules/testdata.
//
// TestEveryRuleHasABehaviourFixture in the rules package checks that every
// rule is named by a `ruleid:` and an `ok:` annotation. This test runs them,
// which is what turns them from documentation into a gate: a `ruleid:` line
// that stops matching, or an `ok:` line that starts, fails here.
//
// Semgrep's own test runner does the matching, so the expectations are written
// in the form a Semgrep rule author would recognise rather than in a Go table.

// semgrepTestOutput is the subset of `semgrep --test --json` that matters.
type semgrepTestOutput struct {
	ConfigMissingTests []string `json:"config_missing_tests"`
	ConfigWithErrors   []struct {
		Filename string `json:"filename"`
		Error    string `json:"error"`
	} `json:"config_with_errors"`
	Results map[string]struct {
		Checks map[string]struct {
			Passed  bool `json:"passed"`
			Matches map[string]struct {
				ExpectedLines []int `json:"expected_lines"`
				ReportedLines []int `json:"reported_lines"`
			} `json:"matches"`
		} `json:"checks"`
	} `json:"results"`
}

func rulesDirOnDisk(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "..", "rules"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(p, "testdata")); err != nil {
		t.Skipf("rules/testdata is not present: %v", err)
	}
	return p
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	body, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, body, 0o644); err != nil {
		t.Fatal(err)
	}
}

// runSemgrepTest runs one rule file against its own fixtures, in a directory
// holding nothing else.
//
// One rule file per invocation is deliberate. Given a directory of rule files
// Semgrep's test runner forks a worker per file, and on Windows those workers
// race each other opening the user's settings file: one of them loses with a
// PermissionError, its rule file is reported under config_with_errors, and the
// overall exit status stays 0. A rule file silently not running is the exact
// failure this test exists to catch, so it is not allowed to happen to the
// test itself.
func runSemgrepTest(t *testing.T, rulesDir, ruleFile string) semgrepTestOutput {
	t.Helper()

	stem := strings.TrimSuffix(ruleFile, filepath.Ext(ruleFile))
	work := t.TempDir()
	cfgDir := filepath.Join(work, "config")
	testDir := filepath.Join(work, "tests")
	for _, d := range []string{cfgDir, testDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	copyFile(t, filepath.Join(rulesDir, "vibekiller", ruleFile), filepath.Join(cfgDir, ruleFile))

	entries, err := os.ReadDir(filepath.Join(rulesDir, "testdata"))
	if err != nil {
		t.Fatal(err)
	}
	fixtures := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || strings.TrimSuffix(name, filepath.Ext(name)) != stem {
			continue
		}
		copyFile(t, filepath.Join(rulesDir, "testdata", name), filepath.Join(testDir, name))
		fixtures++
	}
	if fixtures == 0 {
		t.Fatalf("%s has no behaviour fixture in rules/testdata", ruleFile)
	}

	res, err := tool.New(tool.SemgrepSpec, "", nil).Run(context.Background(), work,
		"--test", "--json",
		"--metrics", "off",
		"--disable-version-check",
		"--config", cfgDir,
		testDir,
	)
	if res == nil || len(res.Stdout) == 0 {
		t.Fatalf("semgrep --test produced no output for %s: %v", ruleFile, err)
	}

	var out semgrepTestOutput
	if jerr := json.Unmarshal(res.Stdout, &out); jerr != nil {
		t.Fatalf("parsing semgrep --test output for %s: %v\n%s", ruleFile, jerr, res.Stdout)
	}
	return out
}

func TestRulePackBehaviourFixturesPass(t *testing.T) {
	requireSemgrep(t)
	rulesDir := rulesDirOnDisk(t)

	entries, err := os.ReadDir(filepath.Join(rulesDir, "vibekiller"))
	if err != nil {
		t.Fatal(err)
	}

	var ruleFiles []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
			ruleFiles = append(ruleFiles, e.Name())
		}
	}
	sort.Strings(ruleFiles)
	if len(ruleFiles) == 0 {
		t.Fatal("no rule files on disk")
	}

	total := 0
	for _, ruleFile := range ruleFiles {
		t.Run(ruleFile, func(t *testing.T) {
			out := runSemgrepTest(t, rulesDir, ruleFile)

			for _, bad := range out.ConfigWithErrors {
				t.Errorf("semgrep could not run %s: %s", bad.Filename, firstLines(bad.Error, 3))
			}
			for _, missing := range out.ConfigMissingTests {
				t.Errorf("%s has no paired fixture, so none of its rules were exercised", missing)
			}
			if len(out.Results) == 0 {
				t.Fatalf("semgrep reported no results for %s; it did not run", ruleFile)
			}

			for _, res := range out.Results {
				ids := make([]string, 0, len(res.Checks))
				for id := range res.Checks {
					ids = append(ids, id)
				}
				sort.Strings(ids)

				for _, id := range ids {
					chk := res.Checks[id]
					total++
					if chk.Passed {
						continue
					}
					for file, m := range chk.Matches {
						missed := missingFrom(m.ExpectedLines, m.ReportedLines)
						extra := missingFrom(m.ReportedLines, m.ExpectedLines)
						if len(missed) > 0 {
							t.Errorf("%s: expected a match on %s lines %v and got none; "+
								"the rule no longer fires on code it is meant to report",
								id, filepath.Base(file), missed)
						}
						if len(extra) > 0 {
							t.Errorf("%s: matched %s lines %v, which are annotated as correct code; "+
								"the rule reports a false positive",
								id, filepath.Base(file), extra)
						}
					}
				}
			}
		})
	}

	t.Logf("executed the annotations for %d rules across %d rule files", total, len(ruleFiles))
}

func missingFrom(want, have []int) []int {
	present := map[int]bool{}
	for _, h := range have {
		present[h] = true
	}
	var out []int
	for _, w := range want {
		if !present[w] {
			out = append(out, w)
		}
	}
	return out
}

func firstLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = append(lines[:n], "...")
	}
	return strings.Join(lines, "\n")
}

// container-runs-as-root is the one rule whose two verdicts cannot both be
// annotated: its match spans the whole file, and Semgrep pairs one fixture per
// extension with each rule file, so a second Dockerfile has nowhere to live.
//
// The negative case is the one that matters here. The rule used to pair a
// one-line FROM regex with a pattern-not-regex for USER, and pattern-not-regex
// is evaluated against the matched range rather than the file, so the USER
// exclusion had nothing to look at and the rule fired on every Dockerfile it
// saw -- a guaranteed false positive on exactly the images that had dropped
// privileges correctly.
func TestDockerfileRuleOnlyFiresWhenTheImageStaysRoot(t *testing.T) {
	requireSemgrep(t)
	rulesDir := rulesDirOnDisk(t)

	const base = "FROM python:3.12-slim\nRUN pip install --no-cache-dir flask\n"
	const cmd = "CMD [\"python\", \"app.py\"]\n"

	cases := []struct {
		name       string
		dockerfile string
		wantFiring bool
	}{
		{
			name:       "no USER instruction",
			dockerfile: base + cmd,
			wantFiring: true,
		},
		{
			name:       "drops to an unprivileged user",
			dockerfile: base + "RUN useradd --create-home app\nUSER app\n" + cmd,
			wantFiring: false,
		},
		{
			name:       "USER root is still root",
			dockerfile: base + "USER root\n" + cmd,
			wantFiring: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "Dockerfile")
			if err := os.WriteFile(path, []byte(tc.dockerfile), 0o644); err != nil {
				t.Fatal(err)
			}

			res, err := tool.New(tool.SemgrepSpec, "", nil).Run(context.Background(), dir,
				"--json", "--quiet",
				"--no-rewrite-rule-ids",
				"--metrics", "off",
				"--disable-version-check",
				"--config", filepath.Join(rulesDir, "vibekiller", "misconfiguration.yaml"),
				path,
			)
			if res == nil || len(res.Stdout) == 0 {
				t.Fatalf("semgrep produced no output: %v", err)
			}

			var out struct {
				Results []struct {
					CheckID string `json:"check_id"`
				} `json:"results"`
				Errors []any `json:"errors"`
			}
			if jerr := json.Unmarshal(res.Stdout, &out); jerr != nil {
				t.Fatalf("parsing semgrep output: %v\n%s", jerr, res.Stdout)
			}
			if len(out.Errors) != 0 {
				t.Errorf("semgrep reported %d errors", len(out.Errors))
			}

			fired := 0
			for _, r := range out.Results {
				if r.CheckID == "container-runs-as-root" {
					fired++
				}
			}
			switch {
			case tc.wantFiring && fired == 0:
				t.Error("container-runs-as-root did not fire on an image that runs as root")
			case !tc.wantFiring && fired > 0:
				t.Errorf("container-runs-as-root fired %d times on an image that drops privileges", fired)
			}
		})
	}
}
