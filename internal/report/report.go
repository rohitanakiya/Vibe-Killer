// Package report renders a run for a human to read.
//
// The report is written for someone who has to decide what to do before
// lunch, so it leads with what was proven, separates that from what is
// suspected, and says plainly what the scan could not check. A scan that
// skipped its access-control checks because no tokens were configured must not
// read as an all-clear.
package report

import (
	"fmt"
	"html"
	"sort"
	"strings"
	"time"

	"github.com/rohitanakiya/Vibe-Killer/internal/diff"
	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
	"github.com/rohitanakiya/Vibe-Killer/internal/run"
)

// Input is everything the renderer needs.
type Input struct {
	Meta     run.Meta
	Findings []finding.Finding

	// Skipped lists checks that did not run, with reasons. This is reported
	// as prominently as the findings.
	Skipped []string

	// Failed lists checks that errored.
	Failed []string

	// Surface counts, for context on how much was mapped.
	RouteCount int
}

// Markdown renders the report as Markdown.
func Markdown(in Input) string {
	var b strings.Builder

	confirmed, suspected := partition(in.Findings)

	fmt.Fprintf(&b, "# Vibe Killer report: run %s\n\n", in.Meta.RunID)

	// Scope first. A reader has to know what was examined before they can
	// interpret what was found.
	b.WriteString("## Scope\n\n")
	fmt.Fprintf(&b, "- **Repository:** `%s`\n", in.Meta.RepoPath)
	if in.Meta.RepoRev != "" {
		fmt.Fprintf(&b, "- **Revision:** `%s`\n", in.Meta.RepoRev)
	}
	fmt.Fprintf(&b, "- **Mode:** %s\n", in.Meta.Mode)
	if in.Meta.Target != "" {
		fmt.Fprintf(&b, "- **Instance exercised:** %s\n", in.Meta.Target)
		fmt.Fprintf(&b, "- **Ownership acknowledged:** %v\n", in.Meta.TargetOwnershipAcknowledged)
	} else {
		b.WriteString("- **Instance exercised:** none (static analysis only)\n")
	}
	if len(in.Meta.AuthorizedTargets) > 0 {
		fmt.Fprintf(&b, "- **Declared targets:** %s\n", strings.Join(in.Meta.AuthorizedTargets, ", "))
	}
	fmt.Fprintf(&b, "- **Posture:** %s\n", posture(in.Meta))
	fmt.Fprintf(&b, "- **Requests sent:** %d\n", in.Meta.RequestCount)
	if in.RouteCount > 0 {
		fmt.Fprintf(&b, "- **Routes mapped:** %d\n", in.RouteCount)
	}
	if len(in.Meta.ScannersUsed) > 0 {
		fmt.Fprintf(&b, "- **Scanners:** %s\n", formatScanners(in.Meta.ScannersUsed))
	}
	if len(in.Meta.ScannersSkipped) > 0 {
		fmt.Fprintf(&b, "- **Scanners unavailable:** %s\n", formatScanners(in.Meta.ScannersSkipped))
	}
	b.WriteString("\n")

	// Summary table.
	b.WriteString("## Summary\n\n")
	counts := finding.Summarize(in.Findings)
	if counts.Total == 0 {
		b.WriteString("No findings were produced by the checks that ran.\n\n")
	} else {
		b.WriteString("| Severity | Count |\n|---|---|\n")
		for _, sev := range []finding.Severity{
			finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium,
			finding.SeverityLow, finding.SeverityInfo,
		} {
			if n := counts.BySeverity[string(sev)]; n > 0 {
				fmt.Fprintf(&b, "| %s | %d |\n", sev, n)
			}
		}
		fmt.Fprintf(&b, "\n**%d finding(s)**, of which **%d confirmed** by a non-destructive check against the running instance.\n\n",
			counts.Total, counts.Confirmed)
	}

	// What the scan could not do comes before the findings, not after, because
	// it changes how the findings should be read.
	if len(in.Skipped) > 0 || len(in.Failed) > 0 {
		b.WriteString("## What this scan did not check\n\n")
		if len(in.Skipped) > 0 {
			b.WriteString("These checks did not run, so this report says nothing about what they cover:\n\n")
			for _, s := range in.Skipped {
				fmt.Fprintf(&b, "- %s\n", s)
			}
			b.WriteString("\n")
		}
		if len(in.Failed) > 0 {
			b.WriteString("These checks failed to complete:\n\n")
			for _, s := range in.Failed {
				fmt.Fprintf(&b, "- %s\n", s)
			}
			b.WriteString("\n")
		}
	}

	if len(confirmed) > 0 {
		b.WriteString("## Confirmed findings\n\n")
		b.WriteString("Each of these was reproduced against the running instance using seeded data.\n\n")
		for i, f := range confirmed {
			writeFindingMarkdown(&b, i+1, f)
		}
	}

	if len(suspected) > 0 {
		b.WriteString("## Findings requiring review\n\n")
		b.WriteString("These come from static analysis, dependency data or secret scanning. They have not been reproduced against a running instance.\n\n")
		for i, f := range suspected {
			writeFindingMarkdown(&b, len(confirmed)+i+1, f)
		}
	}

	b.WriteString("---\n\n")
	b.WriteString("Vibe Killer reports and proves specific issues. It does not certify that an application is secure: ")
	b.WriteString("a clean run means the checks that ran found nothing, not that nothing is there.\n")

	return b.String()
}

func writeFindingMarkdown(b *strings.Builder, n int, f finding.Finding) {
	fmt.Fprintf(b, "### %d. %s\n\n", n, f.Title)
	fmt.Fprintf(b, "`%s` · **%s** · %s confidence · rank %.2f\n\n",
		f.FindingID, strings.ToUpper(string(f.Severity)), f.Confidence, f.Rank)

	fmt.Fprintf(b, "- **Rule:** `%s`\n", f.RuleID)
	fmt.Fprintf(b, "- **Category:** %s", f.Category)
	if f.CWE != "" {
		fmt.Fprintf(b, " (%s)", f.CWE)
	}
	b.WriteString("\n")
	fmt.Fprintf(b, "- **Where:** %s\n", locationLine(f.Location))
	fmt.Fprintf(b, "- **Found by:** %s\n", sourceLine(f))

	b.WriteString("\n**Evidence**\n\n")
	fmt.Fprintf(b, "%s\n\n", f.Evidence.Summary)

	if f.Evidence.Observed != "" || f.Evidence.Expected != "" {
		if f.Evidence.Observed != "" {
			fmt.Fprintf(b, "- Observed: %s\n", f.Evidence.Observed)
		}
		if f.Evidence.Expected != "" {
			fmt.Fprintf(b, "- Expected: %s\n", f.Evidence.Expected)
		}
		b.WriteString("\n")
	}

	if r := f.Evidence.Request; r != nil {
		b.WriteString("```http\n")
		fmt.Fprintf(b, "%s %s\n", r.Method, r.Path)
		if r.Auth != "" {
			fmt.Fprintf(b, "# authenticated as: %s\n", r.Auth)
		}
		for _, k := range sortedKeys(r.Headers) {
			fmt.Fprintf(b, "%s: %s\n", k, r.Headers[k])
		}
		if r.Body != "" {
			fmt.Fprintf(b, "\n%s\n", r.Body)
		}
		b.WriteString("```\n\n")
	}

	if f.Evidence.Snippet != "" {
		b.WriteString("```\n")
		b.WriteString(strings.TrimRight(f.Evidence.Snippet, "\n"))
		b.WriteString("\n```\n\n")
	}

	if len(f.Evidence.TaintPath) > 0 {
		b.WriteString("**Data flow**\n\n")
		for i, step := range f.Evidence.TaintPath {
			fmt.Fprintf(b, "%d. `%s:%d` — %s\n", i+1, step.File, step.Line, step.Note)
		}
		b.WriteString("\n")
	}

	if f.BlastRadius != nil {
		b.WriteString("**Blast radius**\n\n")
		fmt.Fprintf(b, "- Reachable from: %s\n", f.BlastRadius.ReachableFrom)
		for _, r := range f.BlastRadius.Reached {
			fmt.Fprintf(b, "- Reaches: %s\n", r)
		}
		fmt.Fprintf(b, "- Scope: %s\n\n", f.BlastRadius.Scope)
	}

	if f.Reproduction != nil {
		b.WriteString("**Reproduce**\n\n")
		if f.Reproduction.Command != "" {
			fmt.Fprintf(b, "```bash\n%s\n```\n\n", f.Reproduction.Command)
		}
		for i, step := range f.Reproduction.Steps {
			fmt.Fprintf(b, "%d. %s\n", i+1, step)
		}
		if f.Reproduction.ArtifactPath != "" {
			fmt.Fprintf(b, "\nArtifact: `%s`\n", f.Reproduction.ArtifactPath)
		}
		b.WriteString("\n")
	}

	b.WriteString("**Fix**\n\n")
	fmt.Fprintf(b, "%s\n\n", f.Remediation.Guidance)
	if f.Remediation.RootCauseHint != "" {
		fmt.Fprintf(b, "*Root cause:* %s\n\n", f.Remediation.RootCauseHint)
	}
	if !f.Remediation.FixableByGiver {
		fmt.Fprintf(b, "> **A person has to do this one.** %s\n\n", f.Remediation.HumanRequiredReason)
	}
	if len(f.Remediation.References) > 0 {
		b.WriteString("References: ")
		for i, r := range f.Remediation.References {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(b, "<%s>", r)
		}
		b.WriteString("\n\n")
	}
}

func partition(fs []finding.Finding) (confirmed, suspected []finding.Finding) {
	for _, f := range fs {
		if f.Confidence == finding.ConfidenceConfirmed {
			confirmed = append(confirmed, f)
			continue
		}
		suspected = append(suspected, f)
	}
	return confirmed, suspected
}

func posture(m run.Meta) string {
	if m.NonDestructive {
		return "non-destructive (read-only checks and seeded data only)"
	}
	if m.DisposableEnv {
		return "state-changing checks enabled against an environment marked disposable"
	}
	return "state-changing checks requested but not permitted"
}

func locationLine(l finding.Location) string {
	var parts []string
	if l.Endpoint != "" {
		parts = append(parts, "`"+l.Endpoint+"`")
	}
	if l.File != "" {
		s := "`" + l.File
		if l.Line > 0 {
			s += fmt.Sprintf(":%d", l.Line)
		}
		s += "`"
		parts = append(parts, s)
	}
	if l.Symbol != "" {
		parts = append(parts, "in `"+l.Symbol+"`")
	}
	if l.Package != "" {
		p := "`" + l.Package
		if l.Version != "" {
			p += "@" + l.Version
		}
		p += "`"
		if l.Ecosystem != "" {
			p += " (" + l.Ecosystem + ")"
		}
		parts = append(parts, p)
	}
	if len(parts) == 0 {
		return string(l.Type)
	}
	return strings.Join(parts, " ")
}

func sourceLine(f finding.Finding) string {
	if len(f.MergedFrom) > 1 {
		names := make([]string, 0, len(f.MergedFrom))
		for _, s := range f.MergedFrom {
			names = append(names, string(s))
		}
		return strings.Join(names, " + ") + " (merged)"
	}
	return string(f.Source)
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func formatScanners(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		if v := m[k]; v != "" {
			parts = append(parts, fmt.Sprintf("%s (%s)", k, v))
			continue
		}
		parts = append(parts, k)
	}
	return strings.Join(parts, ", ")
}

// DiffMarkdown renders a run-to-run comparison.
func DiffMarkdown(r *diff.Result) string {
	var b strings.Builder

	fmt.Fprintf(&b, "# Vibe Killer diff: %s to %s\n\n", r.FromRun, r.ToRun)
	fmt.Fprintf(&b, "**%s**\n\n", r.Progress())

	b.WriteString("| Change | Count |\n|---|---|\n")
	fmt.Fprintf(&b, "| new | %d |\n", r.Counts.New)
	fmt.Fprintf(&b, "| regressed | %d |\n", r.Counts.Regressed)
	fmt.Fprintf(&b, "| still open | %d |\n", r.Counts.StillOpen)
	fmt.Fprintf(&b, "| fixed | %d |\n", r.Counts.Fixed)
	fmt.Fprintf(&b, "| unchecked | %d |\n\n", r.Counts.Unchecked)

	section := func(title, note string, entries []diff.Entry) {
		if len(entries) == 0 {
			return
		}
		fmt.Fprintf(&b, "## %s (%d)\n\n", title, len(entries))
		if note != "" {
			fmt.Fprintf(&b, "%s\n\n", note)
		}
		for _, e := range entries {
			f := e.Finding
			fmt.Fprintf(&b, "- `%s` **%s** %s — %s\n", f.FindingID, f.Severity, f.RuleID, f.Title)
			fmt.Fprintf(&b, "  - %s\n", locationLine(f.Location))
			if e.PreviousSeverity != "" {
				fmt.Fprintf(&b, "  - severity changed from %s to %s\n", e.PreviousSeverity, f.Severity)
			}
			if e.PreviousConfidence != "" {
				fmt.Fprintf(&b, "  - confidence changed from %s to %s\n", e.PreviousConfidence, f.Confidence)
			}
			if e.SkipReason != "" {
				fmt.Fprintf(&b, "  - not re-checked: %s\n", e.SkipReason)
			}
		}
		b.WriteString("\n")
	}

	section("Regressed", "These were fixed and are reported again.", r.Regressed)
	section("New", "", r.New)
	section("Still open", "", r.StillOpen)
	section("Fixed", "No longer reported by the checks that ran. For a dynamic finding this means it is no longer reproducible.", r.Fixed)
	section("Not re-checked", "These were open in the earlier run and the check that would have found them did not run in the later one. "+
		"Their absence is not evidence that they are fixed, so they are counted neither way.", r.Unchecked)

	return b.String()
}

// HTML renders the report as a self-contained page.
//
// It is deliberately a single file with inline styles and no external assets:
// a report that fetched a stylesheet from a CDN would be a tool that phones
// out, which is exactly what Vibe Killer promises not to do.
func HTML(in Input) string {
	var b strings.Builder
	confirmed, suspected := partition(in.Findings)
	counts := finding.Summarize(in.Findings)

	b.WriteString(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vibe Killer report ` + html.EscapeString(in.Meta.RunID) + `</title>
<style>
  :root {
    --bg: #fbfbfa; --fg: #1a1a18; --muted: #6b6b66; --line: #e3e3df;
    --card: #ffffff; --accent: #2f5d50;
    --critical: #8b1a1a; --high: #b4521f; --medium: #8a6d1f; --low: #4a6b7c; --info: #6b6b66;
  }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) {
      --bg: #16171a; --fg: #e8e8e4; --muted: #9a9a94; --line: #2c2e33;
      --card: #1d1f23; --accent: #7fb3a0;
      --critical: #e06c6c; --high: #e09a5f; --medium: #d6c06a; --low: #8fb8cc; --info: #9a9a94;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--fg);
    font: 16px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  }
  .wrap { max-width: 980px; margin: 0 auto; padding: 48px 16px 96px; }
  h1 { font-size: 1.75rem; margin: 0 0 4px; letter-spacing: -0.01em; }
  h2 { font-size: 1.2rem; margin: 48px 0 16px; padding-bottom: 8px; border-bottom: 1px solid var(--line); }
  h3 { font-size: 1.05rem; margin: 0 0 12px; }
  .sub { color: var(--muted); margin: 0 0 32px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; }
  .tile { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 14px 16px; }
  .tile .n { font-size: 1.6rem; font-weight: 600; line-height: 1.2; }
  .tile .k { color: var(--muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.04em; }
  dl.scope { display: grid; grid-template-columns: max-content 1fr; gap: 6px 20px; margin: 0; }
  dl.scope dt { color: var(--muted); }
  dl.scope dd { margin: 0; overflow-wrap: anywhere; }
  .card { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 20px; margin: 0 0 16px; }
  .meta { color: var(--muted); font-size: 0.85rem; margin: 0 0 14px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .badge {
    display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 0.72rem;
    font-weight: 700; letter-spacing: 0.04em; text-transform: uppercase; color: #fff;
  }
  .critical { background: var(--critical); } .high { background: var(--high); }
  .medium { background: var(--medium); } .low { background: var(--low); } .info { background: var(--info); }
  pre {
    background: var(--bg); border: 1px solid var(--line); border-radius: 8px;
    padding: 12px 14px; overflow-x: auto; font-size: 0.85rem; margin: 12px 0;
  }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.9em; }
  .note { border-left: 3px solid var(--accent); padding: 10px 14px; margin: 14px 0; background: var(--bg); border-radius: 0 8px 8px 0; }
  .gap { border-left: 3px solid var(--high); }
  ol.flow { margin: 10px 0; padding-left: 22px; }
  footer { margin-top: 64px; padding-top: 16px; border-top: 1px solid var(--line); color: var(--muted); font-size: 0.85rem; }
  .k-label { color: var(--muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.04em; margin: 16px 0 4px; }
</style>
</head>
<body><div class="wrap">
`)

	fmt.Fprintf(&b, "<h1>Vibe Killer report</h1>\n<p class=\"sub\">Run <code>%s</code> &middot; %s</p>\n",
		html.EscapeString(in.Meta.RunID), html.EscapeString(in.Meta.StartedAt))

	// Summary tiles.
	b.WriteString(`<div class="grid">`)
	fmt.Fprintf(&b, `<div class="tile"><div class="n">%d</div><div class="k">findings</div></div>`, counts.Total)
	fmt.Fprintf(&b, `<div class="tile"><div class="n">%d</div><div class="k">confirmed</div></div>`, counts.Confirmed)
	fmt.Fprintf(&b, `<div class="tile"><div class="n">%d</div><div class="k">critical + high</div></div>`,
		counts.BySeverity["critical"]+counts.BySeverity["high"])
	fmt.Fprintf(&b, `<div class="tile"><div class="n">%d</div><div class="k">checks skipped</div></div>`, len(in.Skipped))
	b.WriteString("</div>\n")

	// Scope.
	b.WriteString("<h2>Scope</h2>\n<dl class=\"scope\">\n")
	row := func(k, v string) {
		if v == "" {
			return
		}
		fmt.Fprintf(&b, "<dt>%s</dt><dd>%s</dd>\n", html.EscapeString(k), html.EscapeString(v))
	}
	row("Repository", in.Meta.RepoPath)
	row("Revision", in.Meta.RepoRev)
	row("Mode", in.Meta.Mode)
	if in.Meta.Target != "" {
		row("Instance exercised", in.Meta.Target)
		row("Ownership acknowledged", fmt.Sprintf("%v", in.Meta.TargetOwnershipAcknowledged))
	} else {
		row("Instance exercised", "none (static analysis only)")
	}
	row("Declared targets", strings.Join(in.Meta.AuthorizedTargets, ", "))
	row("Posture", posture(in.Meta))
	row("Requests sent", fmt.Sprintf("%d", in.Meta.RequestCount))
	if in.RouteCount > 0 {
		row("Routes mapped", fmt.Sprintf("%d", in.RouteCount))
	}
	row("Scanners", formatScanners(in.Meta.ScannersUsed))
	row("Scanners unavailable", formatScanners(in.Meta.ScannersSkipped))
	b.WriteString("</dl>\n")

	// Coverage gaps, before the findings.
	if len(in.Skipped) > 0 || len(in.Failed) > 0 {
		b.WriteString("<h2>What this scan did not check</h2>\n")
		if len(in.Skipped) > 0 {
			b.WriteString(`<div class="note gap"><p>These checks did not run, so this report says nothing about what they cover.</p><ul>`)
			for _, s := range in.Skipped {
				fmt.Fprintf(&b, "<li>%s</li>", html.EscapeString(s))
			}
			b.WriteString("</ul></div>\n")
		}
		if len(in.Failed) > 0 {
			b.WriteString(`<div class="note gap"><p>These checks failed to complete.</p><ul>`)
			for _, s := range in.Failed {
				fmt.Fprintf(&b, "<li>%s</li>", html.EscapeString(s))
			}
			b.WriteString("</ul></div>\n")
		}
	}

	if len(confirmed) > 0 {
		b.WriteString("<h2>Confirmed findings</h2>\n")
		b.WriteString("<p class=\"sub\">Each of these was reproduced against the running instance using seeded data.</p>\n")
		for _, f := range confirmed {
			writeFindingHTML(&b, f)
		}
	}

	if len(suspected) > 0 {
		b.WriteString("<h2>Findings requiring review</h2>\n")
		b.WriteString("<p class=\"sub\">From static analysis, dependency data or secret scanning. Not reproduced against a running instance.</p>\n")
		for _, f := range suspected {
			writeFindingHTML(&b, f)
		}
	}

	if counts.Total == 0 {
		b.WriteString(`<div class="note"><p>No findings were produced by the checks that ran.</p></div>` + "\n")
	}

	b.WriteString(`<footer>Vibe Killer reports and proves specific issues. It does not certify that an application is secure: a clean run means the checks that ran found nothing, not that nothing is there.</footer>` + "\n")
	b.WriteString("</div></body></html>\n")

	return b.String()
}

func writeFindingHTML(b *strings.Builder, f finding.Finding) {
	b.WriteString(`<div class="card">`)
	fmt.Fprintf(b, `<h3><span class="badge %s">%s</span> %s</h3>`,
		string(f.Severity), html.EscapeString(string(f.Severity)), html.EscapeString(f.Title))

	fmt.Fprintf(b, `<p class="meta">%s &middot; %s &middot; %s confidence &middot; rank %.2f &middot; found by %s</p>`,
		html.EscapeString(f.FindingID), html.EscapeString(f.RuleID),
		html.EscapeString(string(f.Confidence)), f.Rank, html.EscapeString(sourceLine(f)))

	fmt.Fprintf(b, "<p><strong>Where:</strong> %s", stripBackticks(locationLine(f.Location)))
	if f.CWE != "" {
		fmt.Fprintf(b, " &middot; %s", html.EscapeString(f.CWE))
	}
	b.WriteString("</p>")

	fmt.Fprintf(b, "<p>%s</p>", html.EscapeString(f.Evidence.Summary))

	if f.Evidence.Observed != "" || f.Evidence.Expected != "" {
		b.WriteString("<ul>")
		if f.Evidence.Observed != "" {
			fmt.Fprintf(b, "<li><strong>Observed:</strong> %s</li>", html.EscapeString(f.Evidence.Observed))
		}
		if f.Evidence.Expected != "" {
			fmt.Fprintf(b, "<li><strong>Expected:</strong> %s</li>", html.EscapeString(f.Evidence.Expected))
		}
		b.WriteString("</ul>")
	}

	if r := f.Evidence.Request; r != nil {
		b.WriteString(`<div class="k-label">Request sent</div><pre>`)
		fmt.Fprintf(b, "%s %s\n", html.EscapeString(r.Method), html.EscapeString(r.Path))
		if r.Auth != "" {
			fmt.Fprintf(b, "# authenticated as: %s\n", html.EscapeString(r.Auth))
		}
		for _, k := range sortedKeys(r.Headers) {
			fmt.Fprintf(b, "%s: %s\n", html.EscapeString(k), html.EscapeString(r.Headers[k]))
		}
		if r.Body != "" {
			fmt.Fprintf(b, "\n%s\n", html.EscapeString(r.Body))
		}
		b.WriteString("</pre>")
	}

	if f.Evidence.Snippet != "" {
		fmt.Fprintf(b, `<div class="k-label">Source</div><pre>%s</pre>`,
			html.EscapeString(strings.TrimRight(f.Evidence.Snippet, "\n")))
	}

	if len(f.Evidence.TaintPath) > 0 {
		b.WriteString(`<div class="k-label">Data flow</div><ol class="flow">`)
		for _, s := range f.Evidence.TaintPath {
			fmt.Fprintf(b, "<li><code>%s:%d</code> &mdash; %s</li>",
				html.EscapeString(s.File), s.Line, html.EscapeString(s.Note))
		}
		b.WriteString("</ol>")
	}

	if f.BlastRadius != nil {
		b.WriteString(`<div class="k-label">Blast radius</div><ul>`)
		fmt.Fprintf(b, "<li>Reachable from %s</li>", html.EscapeString(f.BlastRadius.ReachableFrom))
		for _, r := range f.BlastRadius.Reached {
			fmt.Fprintf(b, "<li>Reaches %s</li>", html.EscapeString(r))
		}
		fmt.Fprintf(b, "<li>Scope: %s</li></ul>", html.EscapeString(f.BlastRadius.Scope))
	}

	if f.Reproduction != nil {
		b.WriteString(`<div class="k-label">Reproduce</div>`)
		if f.Reproduction.Command != "" {
			fmt.Fprintf(b, "<pre>%s</pre>", html.EscapeString(f.Reproduction.Command))
		}
		if len(f.Reproduction.Steps) > 0 {
			b.WriteString("<ol>")
			for _, s := range f.Reproduction.Steps {
				fmt.Fprintf(b, "<li>%s</li>", html.EscapeString(s))
			}
			b.WriteString("</ol>")
		}
	}

	b.WriteString(`<div class="k-label">Fix</div>`)
	fmt.Fprintf(b, "<p>%s</p>", html.EscapeString(f.Remediation.Guidance))
	if f.Remediation.RootCauseHint != "" {
		fmt.Fprintf(b, "<p><em>Root cause: %s</em></p>", html.EscapeString(f.Remediation.RootCauseHint))
	}
	if !f.Remediation.FixableByGiver {
		fmt.Fprintf(b, `<div class="note gap"><strong>A person has to do this one.</strong> %s</div>`,
			html.EscapeString(f.Remediation.HumanRequiredReason))
	}
	b.WriteString("</div>\n")
}

// stripBackticks renders the markdown-flavoured location line as HTML code
// spans.
func stripBackticks(s string) string {
	parts := strings.Split(s, "`")
	var b strings.Builder
	for i, p := range parts {
		if i%2 == 1 {
			fmt.Fprintf(&b, "<code>%s</code>", html.EscapeString(p))
			continue
		}
		b.WriteString(html.EscapeString(p))
	}
	return b.String()
}

// Timestamp formats a time for report headers.
func Timestamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }
