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
}

// Result is the whole comparison.
type Result struct {
	FromRun string `json:"from_run"`
	ToRun   string `json:"to_run"`

	New       []Entry `json:"new"`
	StillOpen []Entry `json:"still_open"`
	Fixed     []Entry `json:"fixed"`
	Regressed []Entry `json:"regressed"`

	Counts Counts `json:"counts"`
}

// Counts summarizes the comparison.
type Counts struct {
	New       int `json:"new"`
	StillOpen int `json:"still_open"`
	Fixed     int `json:"fixed"`
	Regressed int `json:"regressed"`
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

		fixed := f
		fixed.Status = finding.StatusFixed
		res.Fixed = append(res.Fixed, Entry{Change: ChangeFixed, Finding: fixed})
	}

	for _, bucket := range [][]Entry{res.New, res.StillOpen, res.Fixed, res.Regressed} {
		sortEntries(bucket)
	}

	res.Counts = Counts{
		New:       len(res.New),
		StillOpen: len(res.StillOpen),
		Fixed:     len(res.Fixed),
		Regressed: len(res.Regressed),
	}
	return res
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

// Improved reports whether anything got worse.
func (r *Result) Improved() bool {
	return r.Counts.New == 0 && r.Counts.Regressed == 0
}
