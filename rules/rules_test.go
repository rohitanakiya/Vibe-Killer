package rules

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	validSeverities   = map[string]bool{"INFO": true, "WARNING": true, "ERROR": true}
	validLanguages    = map[string]bool{"javascript": true, "typescript": true, "python": true, "go": true, "java": true, "ruby": true, "generic": true, "yaml": true, "json": true, "dockerfile": true}
	validVKSeverity   = map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}
	validVKConfidence = map[string]bool{"heuristic": true, "likely": true}
	validVKCategory   = map[string]bool{
		"broken-access-control": true, "cryptographic-failure": true, "injection": true,
		"insecure-design": true, "security-misconfiguration": true, "vulnerable-dependency": true,
		"identification-and-authentication-failure": true, "software-and-data-integrity-failure": true,
		"logging-and-monitoring-failure": true, "server-side-request-forgery": true,
		"secrets-exposure": true, "cross-service-exposure": true,
	}
	ruleIDPattern = regexp.MustCompile(`^[a-z0-9]+(?:[-.][a-z0-9]+)*$`)
)

func TestPackIsNotEmpty(t *testing.T) {
	names, err := Files()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) == 0 {
		t.Fatal("the embedded rule pack has no files; the go:embed pattern is not matching")
	}
	t.Logf("embedded rule files: %v", names)
}

func TestEveryRuleIsWellFormed(t *testing.T) {
	files, err := Parse()
	if err != nil {
		t.Fatal(err)
	}

	total := 0
	seenSemgrepID := map[string]string{}

	for _, f := range files {
		if len(f.Rules) == 0 {
			t.Errorf("%s declares no rules", f.Name)
		}
		for _, r := range f.Rules {
			total++
			where := f.Name + "/" + r.ID

			if r.ID == "" {
				t.Errorf("%s: a rule has no id", f.Name)
				continue
			}
			if prev, dup := seenSemgrepID[r.ID]; dup {
				t.Errorf("%s: semgrep rule id %q is also used in %s", where, r.ID, prev)
			}
			seenSemgrepID[r.ID] = f.Name

			if strings.TrimSpace(r.Message) == "" {
				t.Errorf("%s: has no message", where)
			}
			if !validSeverities[r.Severity] {
				t.Errorf("%s: severity %q is not INFO, WARNING or ERROR", where, r.Severity)
			}
			if len(r.Languages) == 0 {
				t.Errorf("%s: declares no languages", where)
			}
			for _, lang := range r.Languages {
				if !validLanguages[lang] {
					t.Errorf("%s: language %q is not one this pack supports", where, lang)
				}
			}

			// A rule needs a matcher, and a taint rule needs both ends of the
			// flow or Semgrep rejects it at load time.
			hasPatternFamily := r.Pattern != nil || r.Patterns != nil || r.PatternEither != nil || r.PatternRegex != nil
			if r.Mode == "taint" {
				if r.PatternSources == nil || r.PatternSinks == nil {
					t.Errorf("%s: mode is taint but it is missing pattern-sources or pattern-sinks", where)
				}
			} else if !hasPatternFamily {
				t.Errorf("%s: has no pattern, patterns, pattern-either or pattern-regex", where)
			}

			if r.Metadata.Category != "security" {
				t.Errorf("%s: metadata.category is %q; the wrapper filters on \"security\"", where, r.Metadata.Category)
			}
		}
	}

	t.Logf("validated %d rules across %d files", total, len(files))
	if total < 15 {
		t.Errorf("the pack has only %d rules; it is meant to cover the common generated-code weaknesses", total)
	}
}

// The vibekiller metadata block is what the Semgrep wrapper reads to fill in
// the findings contract, so a rule that declares it wrongly produces a finding
// that fails validation at write time, on the operator's machine. Catch it
// here instead.
func TestVibeKillerMetadataMatchesTheContract(t *testing.T) {
	files, err := Parse()
	if err != nil {
		t.Fatal(err)
	}

	withMeta := 0
	for _, f := range files {
		for _, r := range f.Rules {
			vk := r.Metadata.VibeKiller
			if vk == nil {
				t.Errorf("%s/%s: has no vibekiller metadata block, so its contract fields would be guessed", f.Name, r.ID)
				continue
			}
			withMeta++
			where := f.Name + "/" + r.ID

			if !ruleIDPattern.MatchString(vk.RuleID) {
				t.Errorf("%s: rule_id %q does not match the contract pattern", where, vk.RuleID)
			}
			if !validVKCategory[vk.Category] {
				t.Errorf("%s: category %q is not a contract category", where, vk.Category)
			}
			if !validVKSeverity[vk.Severity] {
				t.Errorf("%s: severity %q is not a contract severity", where, vk.Severity)
			}
			// A static rule may never declare itself confirmed: only a check
			// that actually reproduced the issue earns that.
			if !validVKConfidence[vk.Confidence] {
				t.Errorf("%s: confidence %q is not heuristic or likely (a static rule cannot be confirmed)", where, vk.Confidence)
			}
			if strings.TrimSpace(vk.Guidance) == "" {
				t.Errorf("%s: has no guidance, so a consumer has nothing to act on", where)
			}
			if strings.TrimSpace(vk.RootCause) == "" {
				t.Errorf("%s: has no root_cause_hint", where)
			}

			// Contract rule: anything not auto-fixable has to say why.
			if vk.Fixable != nil && !*vk.Fixable && strings.TrimSpace(vk.HumanRequired) == "" {
				t.Errorf("%s: declares fixable_by_giver false without a human_required_reason", where)
			}
			if vk.Fixable == nil {
				t.Errorf("%s: does not state fixable_by_giver", where)
			}
		}
	}

	if withMeta == 0 {
		t.Fatal("no rule carries first-party metadata")
	}
}

// Rules written for the same weakness in different languages should share one
// contract rule_id, so that a finding means the same thing regardless of the
// target's stack.
func TestRuleIDsAreSharedAcrossLanguages(t *testing.T) {
	files, err := Parse()
	if err != nil {
		t.Fatal(err)
	}

	byRuleID := map[string][]string{}
	for _, f := range files {
		for _, r := range f.Rules {
			if vk := r.Metadata.VibeKiller; vk != nil {
				byRuleID[vk.RuleID] = append(byRuleID[vk.RuleID], strings.Join(r.Languages, "+"))
			}
		}
	}

	shared := 0
	for id, langs := range byRuleID {
		if len(langs) > 1 {
			shared++
			t.Logf("%s covers %v", id, langs)
		}
	}
	if shared == 0 {
		t.Error("no contract rule_id is covered in more than one language; the pack should not be single-stack")
	}
}

func TestMaterializeWritesThePack(t *testing.T) {
	dir := t.TempDir()

	target, err := Materialize(dir)
	if err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(target)
	if err != nil {
		t.Fatal(err)
	}
	names, err := Files()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(names) {
		t.Errorf("wrote %d files, expected %d", len(entries), len(names))
	}

	// The written files must be the embedded bytes, not a re-serialization.
	for _, name := range names {
		want, err := Read(name)
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(target, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Errorf("%s was altered on the way to disk", name)
		}
	}
}

func TestDynamicRuleReferences(t *testing.T) {
	dynamic, err := DynamicRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(dynamic) == 0 {
		t.Fatal("no static rule names a dynamic check, so nothing can ever be upgraded to confirmed")
	}
	for dyn, static := range dynamic {
		if !ruleIDPattern.MatchString(dyn) {
			t.Errorf("dynamic_rule %q (from %s) does not match the contract rule_id pattern", dyn, static)
		}
	}
	t.Logf("static rules reference %d dynamic checks", len(dynamic))
}
