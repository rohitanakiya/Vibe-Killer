package staticchecks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
)

// A scan has to measure the operator's code and not their dependencies.
//
// express-vulnerable has 81 packages installed, which is what makes this
// fixture the right place to assert it. With the pack's previous default
// exclude list the same scan returned 34 findings, 17 of them inside
// node_modules, reported under rule ids that describe the operator's own code.
// The pattern was "node_modules/**": it matches nothing in Semgrep, and
// naming the directory in it switched off Semgrep's own default skip, so the
// list was the reason dependencies were read rather than the reason they were
// not.
//
// Both halves are asserted here, because a pattern can fail the other way
// round just as quietly. This repository's committed config said
// "fixtures/*/node_modules/**", and a scan of the repository with it returned
// zero findings -- the whole fixtures tree was pruned and nothing said so.
func TestAScanMeasuresTheRepositoryAndNotItsDependencies(t *testing.T) {
	requireSemgrep(t)

	// A synthetic tree rather than a fixture, so this runs anywhere: the
	// express fixture's node_modules is not committed, and a test that skips
	// in CI would not have caught this.
	const weakness = "const https = require('https');\n" +
		"const agent = new https.Agent({ rejectUnauthorized: false });\n" +
		"module.exports = agent;\n"

	root := t.TempDir()
	for _, rel := range []string{"src/app.js", "node_modules/dep/index.js", "dist/bundle.js"} {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(weakness), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	fs := (func() []finding.Finding {
		env := semgrepEnv(t, root)
		out, err := (&SemgrepEngine{}).Detect(context.Background(), env)
		if err != nil {
			t.Fatalf("semgrep failed: %v", err)
		}
		return out
	})()

	var paths []string
	for _, f := range fs {
		paths = append(paths, filepath.ToSlash(f.Location.File))
	}

	if len(fs) == 0 {
		t.Fatal("the scan reported nothing at all, on a file written to be reported; " +
			"an exclude pattern is pruning the code under test")
	}
	for _, p := range paths {
		if strings.Contains(p, "node_modules/") || strings.Contains(p, "dist/") {
			t.Errorf("a finding was reported at %s; that is a dependency or a build output, "+
				"and the dependency check owns it", p)
		}
	}
	t.Logf("reported %d findings at %v", len(fs), paths)
}
