package rules

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The coverage gate for the rule pack.
//
// This is the test whose absence let a dead rule ship.
// TestRulePackFiresOnVulnerableFixtures checks a hand-written list of expected
// rules per application fixture, so a rule on nobody's list was
// indistinguishable from a rule that matched nothing at all --
// crypto.tls-verification-disabled matched nothing on Python for as long as it
// existed, silently, with errors: 0, and no test noticed.
//
// rules/testdata holds one behaviour fixture per rule file, annotated in
// Semgrep's own `ruleid:` / `ok:` form. The annotations are executed by
// TestRulePackBehaviourFixturesPass, which needs Semgrep installed. This test
// needs nothing: it checks that every rule is named by at least one of each
// kind of annotation, so it runs on every platform in the matrix and fails the
// moment a rule is added without one.
//
// Requiring an `ok:` as well as a `ruleid:` is the half that matters. A rule
// that matches nothing and a rule that matches everything both look healthy in
// a scan of deliberately vulnerable code; only a negative case separates them.

const testDataDir = "testdata"

// A rule whose behaviour cannot be expressed as an annotated fixture, with the
// test that pins it instead. Semgrep pairs one fixture file per extension with
// each rule file, and this rule's match spans the whole file, so its two
// verdicts cannot both live in one Dockerfile.
//
// The point of the map is that a gap has to be written down as a decision.
var pinnedByAGoTestInstead = map[string]string{
	"container-runs-as-root": "TestDockerfileRuleOnlyFiresWhenTheImageStaysRoot " +
		"in internal/checks/staticchecks",
}

// Semgrep's annotation forms. todoruleid/todook mark a known gap and are
// accepted here so that recording one does not break the gate, but they do not
// count as coverage.
var annotationPattern = regexp.MustCompile(`(?m)^[\t ]*(?://|#)[\t ]*(ruleid|ok|todoruleid|todook):[\t ]*(\S.*)$`)

type annotations struct {
	fires  map[string][]string // rule id -> fixture files asserting it matches
	silent map[string][]string // rule id -> fixture files asserting it does not
	files  []string
}

// readAnnotations collects the annotations in every fixture paired with one
// rule file. Semgrep pairs by basename, so misconfiguration.yaml is exercised
// by testdata/misconfiguration.py and testdata/misconfiguration.js.
func readAnnotations(t *testing.T, ruleFile string) annotations {
	t.Helper()

	stem := strings.TrimSuffix(ruleFile, filepath.Ext(ruleFile))
	entries, err := os.ReadDir(testDataDir)
	if err != nil {
		t.Fatalf("reading %s: %v", testDataDir, err)
	}

	out := annotations{fires: map[string][]string{}, silent: map[string][]string{}}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.TrimSuffix(name, filepath.Ext(name)) != stem {
			continue
		}
		out.files = append(out.files, name)

		body, err := os.ReadFile(filepath.Join(testDataDir, name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		for _, m := range annotationPattern.FindAllStringSubmatch(string(body), -1) {
			kind, ids := m[1], m[2]
			// A trailing explanation after the ids is allowed, and the ids
			// themselves are comma separated.
			for _, id := range strings.Split(ids, ",") {
				id = strings.TrimSpace(id)
				if id == "" || strings.ContainsAny(id, " \t") {
					continue
				}
				switch kind {
				case "ruleid":
					out.fires[id] = append(out.fires[id], name)
				case "ok":
					out.silent[id] = append(out.silent[id], name)
				}
			}
		}
	}
	return out
}

func TestEveryRuleHasABehaviourFixture(t *testing.T) {
	files, err := Parse()
	if err != nil {
		t.Fatal(err)
	}

	covered, pinned := 0, 0
	for _, f := range files {
		ann := readAnnotations(t, f.Name)
		if len(ann.files) == 0 {
			t.Errorf("%s has no behaviour fixture in rules/%s; "+
				"add %s.py and/or %s.js there",
				f.Name, testDataDir,
				strings.TrimSuffix(f.Name, filepath.Ext(f.Name)),
				strings.TrimSuffix(f.Name, filepath.Ext(f.Name)))
			continue
		}

		declared := map[string]bool{}
		for _, r := range f.Rules {
			declared[r.ID] = true
		}

		for _, r := range f.Rules {
			if why, ok := pinnedByAGoTestInstead[r.ID]; ok {
				pinned++
				if len(ann.fires[r.ID]) > 0 {
					t.Errorf("%s/%s is listed as pinned by %s but also has a ruleid: "+
						"annotation; remove it from pinnedByAGoTestInstead", f.Name, r.ID, why)
				}
				continue
			}
			if len(ann.fires[r.ID]) == 0 {
				t.Errorf("%s/%s has no `ruleid: %s` annotation in rules/%s/%v, "+
					"so nothing asserts it matches anything at all",
					f.Name, r.ID, r.ID, testDataDir, ann.files)
				continue
			}
			if len(ann.silent[r.ID]) == 0 {
				t.Errorf("%s/%s has no `ok: %s` annotation in rules/%s/%v, "+
					"so nothing asserts it stays quiet on correct code",
					f.Name, r.ID, r.ID, testDataDir, ann.files)
				continue
			}
			covered++
		}

		// An annotation naming a rule that is not in this file is a typo or a
		// rename, and Semgrep's own runner rejects the whole file for it.
		var stray []string
		for _, set := range []map[string][]string{ann.fires, ann.silent} {
			for id := range set {
				if !declared[id] {
					stray = append(stray, id+" (in "+strings.Join(set[id], ", ")+")")
				}
			}
		}
		sort.Strings(stray)
		for _, s := range stray {
			t.Errorf("%s: annotation names %s, which is not a rule in that file", f.Name, s)
		}
	}

	t.Logf("%d rules pinned by annotated fixtures, %d pinned by a Go test", covered, pinned)
	if covered == 0 {
		t.Error("no rule is pinned by a fixture; the coverage gate is not measuring anything")
	}
}

// A finding has to mean the same thing whatever the stack it came from, and
// for a while it did not.
//
// The pack grew JavaScript-first, so ten of its contract rule ids existed in
// one language only: a scan of a Flask application could not report mass
// assignment, and a scan of an Express application could not report debug
// mode, with nothing in the output saying which rules had no spelling for the
// language it was looking at. That is the per-rule version of the gap the
// skipped-check array closed at the layer level -- a quiet absence rather
// than a wrong answer, which is the harder kind to notice.
//
// So the invariant is asserted rather than described: every rule id the pack
// declares for one of its two application languages has to be declared for
// the other, and an exception has to be written down here with its reason.
var singleLanguageByDesign = map[string]string{
	"misconfig.container-root-user": "a Dockerfile is neither JavaScript nor Python, " +
		"so this rule is `generic` and belongs to neither side",
}

func TestEveryWeaknessIsCoveredInBothLanguages(t *testing.T) {
	files, err := Parse()
	if err != nil {
		t.Fatal(err)
	}

	isJS := func(lang string) bool { return lang == "javascript" || lang == "typescript" }

	type coverage struct {
		js, py bool
		rules  []string
	}
	byRuleID := map[string]*coverage{}

	for _, f := range files {
		for _, r := range f.Rules {
			vk := r.Metadata.VibeKiller
			if vk == nil || vk.RuleID == "" {
				continue // TestVibeKillerMetadataMatchesTheContract owns this
			}
			c := byRuleID[vk.RuleID]
			if c == nil {
				c = &coverage{}
				byRuleID[vk.RuleID] = c
			}
			c.rules = append(c.rules, r.ID)
			for _, lang := range r.Languages {
				switch {
				case isJS(lang):
					c.js = true
				case lang == "python":
					c.py = true
				}
			}
		}
	}

	ids := make([]string, 0, len(byRuleID))
	for id := range byRuleID {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	both, excepted := 0, 0
	for _, id := range ids {
		c := byRuleID[id]
		if why, ok := singleLanguageByDesign[id]; ok {
			excepted++
			if c.js && c.py {
				t.Errorf("%s is listed in singleLanguageByDesign (%s) but now covers both "+
					"languages; remove the exception", id, why)
			}
			continue
		}
		switch {
		case c.js && c.py:
			both++
		case c.js:
			t.Errorf("%s has no Python rule, only %v. A finding should mean the same thing "+
				"whatever the stack; write the Python spelling or add the id to "+
				"singleLanguageByDesign with a reason", id, c.rules)
		case c.py:
			t.Errorf("%s has no JavaScript rule, only %v. A finding should mean the same thing "+
				"whatever the stack; write the JavaScript spelling or add the id to "+
				"singleLanguageByDesign with a reason", id, c.rules)
		default:
			t.Errorf("%s covers neither JavaScript nor Python (%v); if that is deliberate, "+
				"add it to singleLanguageByDesign with a reason", id, c.rules)
		}
	}

	t.Logf("%d rule ids cover both languages, %d excepted by design", both, excepted)
	if both == 0 {
		t.Error("no rule id covers both languages; the invariant is not measuring anything")
	}
}
