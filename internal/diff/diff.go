// Package diff compares two runs.
//
// This is what makes the Killer-to-Giver loop measurable. A fix is not
// "applied", it is "no longer reproducible", and that distinction only exists
// if two runs can be compared by stable finding identity. Everything here
// rests on finding_id being stable for the same underlying issue, which is why
// that id deliberately excludes line numbers and revisions.
package diff

import (
	"fmt"
	"sort"

	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
)

// Change is how one finding differs between two runs.
type Change string

const (
	// ChangeNew appeared in the later run.
	ChangeNew Change = "new"

	// ChangeStillOpen is present in both.
	ChangeStillOpen Change = "still-open"

	// ChangeFixed was in the earlier run and is no longer reported. For a
	// dynamic finding this means it is no longer reproducible.
	ChangeFixed Change = "fixed"

	// ChangeRegressed was marked fixed and is reported again.
	ChangeRegressed Change = "regressed"

	// ChangeUnchecked was open in the earlier run, is absent from the later
	// one, and the check that would have found it did not run. Its absence is
	// evidence of nothing, so it is neither fixed nor still open.
	//
	// This bucket exists because the alternative is worse than useless: for
	// as long as it did not, a run that simply skipped a layer reported every
	// finding from that layer as fixed, and the verdict line said "better".
	ChangeUnchecked Change = "unchecked"
)

// Entry is one finding's change between runs.
type Entry struct {
	Change  Change          `json:"change"`
	Finding finding.Finding `json:"finding"`

	// PreviousSeverity is set when the severity changed between runs, which is
	// worth seeing even for a still-open finding.
	PreviousSeverity finding.Severity `json:"previous_severity,omitempty"`

	// PreviousConfidence is set when confidence changed. A finding that moved
	// from likely to confirmed has not got worse; it has been proven.
	PreviousConfidence finding.Confidence `json:"previous_confidence,omitempty"`

	// Reason is why the later run could not speak to this finding, whether
	// its check was skipped or failed. It is set only on an unchecked entry,
	// and it is the whole value of that entry: "absent" is not actionable,
	// "absent because semgrep exited 7" is.
	Reason string `json:"reason,omitempty"`
}

// Result is the whole comparison.
type Result struct {
	FromRun string `json:"from_run"`
	ToRun   string `json:"to_run"`

	New       []Entry `json:"new"`
	StillOpen []Entry `json:"still_open"`
	Fixed     []Entry `json:"fixed"`
	Regressed []Entry `json:"regressed"`
	Unchecked []Entry `json:"unchecked"`

	Counts Counts `json:"counts"`
}

// Counts summarizes the comparison.
type Counts struct {
	New       int `json:"new"`
	StillOpen int `json:"still_open"`
	Fixed     int `json:"fixed"`
	Regressed int `json:"regressed"`
	Unchecked int `json:"unchecked"`
}

// Compare diffs an earlier run against a later one.
func Compare(from, to *finding.Document) *Result {
	res := &Result{FromRun: from.RunID, ToRun: to.RunID}

	fromByID := map[string]finding.Finding{}
	for _, f := range from.Findings {
		fromByID[f.FindingID] = f
	}
	toByID := map[string]finding.Finding{}
	for _, f := range to.Findings {
		toByID[f.FindingID] = f
	}

	unchecked := suppressedBy(to)

	for _, f := range to.Findings {
		prev, existed := fromByID[f.FindingID]

		switch {
		case !existed:
			res.New = append(res.New, Entry{Change: ChangeNew, Finding: f})

		case prev.Status == finding.StatusFixed:
			// It was fixed and is back. That is the signal a regression test
			// would have caught, which is why it gets its own bucket.
			res.Regressed = append(res.Regressed, Entry{
				Change:             ChangeRegressed,
				Finding:            f,
				PreviousSeverity:   severityIfChanged(prev, f),
				PreviousConfidence: confidenceIfChanged(prev, f),
			})

		default:
			res.StillOpen = append(res.StillOpen, Entry{
				Change:             ChangeStillOpen,
				Finding:            f,
				PreviousSeverity:   severityIfChanged(prev, f),
				PreviousConfidence: confidenceIfChanged(prev, f),
			})
		}
	}

	for _, f := range from.Findings {
		if _, stillThere := toByID[f.FindingID]; stillThere {
			continue
		}
		// Accepted and false-positive findings were deliberately set aside;
		// their absence is not a fix.
		if f.Status == finding.StatusAccepted || f.Status == finding.StatusFalsePositive {
			continue
		}
		if f.Status == finding.StatusFixed {
			continue
		}

		// Absence only means "fixed" if something actually looked. When the
		// later run skipped the check that would have found this, the honest
		// answer is that we do not know, and the status is left as it was.
		if reason, ok := unchecked(f); ok {
			res.Unchecked = append(res.Unchecked, Entry{
				Change:  ChangeUnchecked,
				Finding: f,
				Reason:  reason,
			})
			continue
		}

		fixed := f
		fixed.Status = finding.StatusFixed
		res.Fixed = append(res.Fixed, Entry{Change: ChangeFixed, Finding: fixed})
	}

	for _, bucket := range [][]Entry{res.New, res.StillOpen, res.Fixed, res.Regressed, res.Unchecked} {
		sortEntries(bucket)
	}

	res.Counts = Counts{
		New:       len(res.New),
		StillOpen: len(res.StillOpen),
		Fixed:     len(res.Fixed),
		Regressed: len(res.Regressed),
		Unchecked: len(res.Unchecked),
	}
	return res
}

// suppressedBy returns a predicate saying whether a finding's absence from the
// later run is explained by a check that did not produce results -- skipped or
// failed -- and if so why.
//
// Two joins are needed, because a check's rule_id is not always the rule_id of
// the findings it produces. The endpoint, runtime and exposure checks emit
// findings under their own rule_id, so matching on that is exact. The scanner
// engines do not: engine.osv-scanner produces deps.known-vulnerability, so its
// skip can only be connected through the layer it belongs to -- and a scanner
// missing on a CI box is the likeliest way this situation arises at all.
//
// The layer join is then narrowed by "and the later run produced nothing from
// that source", which keeps a partly skipped layer from masking real fixes.
// If a source produced findings, its producers evidently ran, so one that
// vanished is more likely fixed than unchecked -- the case to protect is
// misconfig.verbose-error being skipped while the header check runs and finds
// things. When a source is empty and one of its checks was skipped, there is
// genuinely nothing to conclude.
//
// A document written before the skipped array existed has no skip list, so
// every absence reads as a fix exactly as it used to. That is the old
// behaviour, kept deliberately: inventing uncertainty about runs we have no
// information on would be its own kind of dishonesty.
func suppressedBy(to *finding.Document) func(finding.Finding) (string, bool) {
	if len(to.Skipped) == 0 && len(to.Failed) == 0 {
		return func(finding.Finding) (string, bool) { return "", false }
	}

	present := map[finding.Source]bool{}
	for _, f := range to.Findings {
		present[f.Source] = true
	}

	byRule := map[string]string{}
	bySource := map[finding.Source]string{}
	record := func(checkID, layer, reason string) {
		byRule[checkID] = reason

		src, ok := finding.SourceForLayer(layer)
		if !ok || present[src] {
			return
		}
		bySource[src] = reason
	}

	for _, sk := range to.Skipped {
		record(sk.CheckID, sk.Layer, sk.Reason)
	}

	// A check that ran and broke established no more than one that never ran.
	// semgrep exiting non-zero makes every sast finding disappear, and reading
	// that as a fix is the same error by a different route.
	for _, fl := range to.Failed {
		record(fl.CheckID, fl.Layer, "the check failed: "+fl.Error)
	}

	return func(f finding.Finding) (string, bool) {
		if reason, ok := byRule[f.RuleID]; ok {
			return reason, true
		}
		if reason, ok := bySource[f.Source]; ok {
			return reason, true
		}
		return "", false
	}
}

func severityIfChanged(prev, cur finding.Finding) finding.Severity {
	if prev.Severity != cur.Severity {
		return prev.Severity
	}
	return ""
}

func confidenceIfChanged(prev, cur finding.Finding) finding.Confidence {
	if prev.Confidence != cur.Confidence {
		return prev.Confidence
	}
	return ""
}

func sortEntries(entries []Entry) {
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Finding.Rank != entries[j].Finding.Rank {
			return entries[i].Finding.Rank > entries[j].Finding.Rank
		}
		return entries[i].Finding.FindingID < entries[j].Finding.FindingID
	})
}

// Progress reports whether the later run is an improvement.
//
// It is deliberately conservative: anything new or regressed means the answer
// is no, regardless of how much was fixed, because a scan that fixed nine
// things and introduced one critical has not made the application safer.
func (r *Result) Progress() string {
	switch {
	case r.Counts.Regressed > 0:
		return fmt.Sprintf("regressed: %d previously-fixed finding(s) are open again", r.Counts.Regressed)
	case r.Counts.New > 0 && r.Counts.Fixed > 0:
		return fmt.Sprintf("mixed: %d fixed, but %d new", r.Counts.Fixed, r.Counts.New)
	case r.Counts.New > 0:
		return fmt.Sprintf("worse: %d new finding(s)", r.Counts.New)
	case r.Counts.Unchecked > 0:
		// This outranks every remaining verdict, including "clean". Nothing
		// got worse, but the run cannot support a claim that anything got
		// better either, and saying "better" here is the exact failure this
		// bucket was added to stop.
		return fmt.Sprintf("inconclusive: %d finding(s) were not re-checked because their checks did not run (%d fixed, %d still open)",
			r.Counts.Unchecked, r.Counts.Fixed, r.Counts.StillOpen)
	case r.Counts.Fixed > 0 && r.Counts.StillOpen == 0:
		return fmt.Sprintf("clean: all %d previous finding(s) fixed", r.Counts.Fixed)
	case r.Counts.Fixed > 0:
		return fmt.Sprintf("better: %d fixed, %d still open", r.Counts.Fixed, r.Counts.StillOpen)
	case r.Counts.StillOpen > 0:
		return fmt.Sprintf("unchanged: %d still open", r.Counts.StillOpen)
	default:
		return "no findings in either run"
	}
}

// Improved reports whether the later run can be called no worse than the
// earlier one. It is what `vibekiller diff --fail-on-new` gates on.
//
// An unchecked finding makes the answer no, and that is a deliberate
// behaviour change rather than an incidental one. The common shape of this
// problem is a full scan locally and a narrower one in CI -- a missing
// scanner binary, no --target, a framework whose routes cannot be
// extracted -- and in that shape the gate used to pass precisely because
// coverage had disappeared. A build that goes green because less was
// checked is the same silent-coverage failure the rest of this tool works
// to prevent, moved to the one place a team actually relies on.
func (r *Result) Improved() bool {
	return r.Counts.New == 0 && r.Counts.Regressed == 0 && r.Counts.Unchecked == 0
}
