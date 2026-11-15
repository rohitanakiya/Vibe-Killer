// Package scanners wraps the external security tools Vibe Killer
// orchestrates and normalizes their output into the findings contract.
//
// Each wrapper is responsible for three things: invoking its tool with
// arguments that make the output machine-readable, parsing that output
// tolerantly enough that a new field in a tool release does not break the
// scan, and mapping the result onto a finding without inventing confidence
// the underlying tool did not express.
//
// Nothing here raises a finding to confirmed. Static analysis says a pattern
// is present, not that it is reachable in a running instance, so the highest
// confidence a wrapper assigns is likely.
package scanners

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"

	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
)

// relPath converts an absolute path reported by a scanner into a
// repo-relative, forward-slashed path, which is what the contract specifies.
func relPath(repoRoot, p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}

	// Both sides have to be absolutized before they can be compared: on
	// Windows, filepath.Rel refuses a pair where only one carries a drive
	// letter, which would silently leave absolute scanner paths in the report.
	absRoot, rootErr := filepath.Abs(repoRoot)
	if rootErr != nil {
		return filepath.ToSlash(filepath.Clean(p))
	}

	// A scanner reports relative paths against the directory it was run in,
	// which is the repo root, not this process's working directory. Resolving
	// them against the wrong base is how "node_modules/../server.js" survives
	// into a report: Rel then produces a path starting with "..", the
	// conversion gives up, and the uncleaned original is emitted — which also
	// stops it de-duplicating against the same finding reported by its real
	// path.
	// filepath.IsAbs is platform-specific: on Windows a POSIX-style path like
	// "/repo/src/app.js" is not absolute, because it carries no drive letter.
	// Scanner output is full of such paths, so a leading separator counts as
	// absolute here regardless of platform. Getting this wrong joins the root
	// to itself and yields "repo/src/app.js".
	absolute := filepath.IsAbs(p) || strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\`)

	var abs string
	if absolute {
		resolved, err := filepath.Abs(p)
		if err != nil {
			return filepath.ToSlash(filepath.Clean(p))
		}
		abs = resolved
	} else {
		abs = filepath.Join(absRoot, p)
	}
	abs = filepath.Clean(abs)

	if rel, err := filepath.Rel(absRoot, abs); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(filepath.Clean(p))
}

// fingerprint produces a short, stable, non-reversible identifier for a value.
//
// It exists so that a finding can prove it is about a specific secret without
// the run directory containing that secret. findings.json gets attached to
// tickets; a leaked credential must not travel with it.
func fingerprint(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0x1f})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// maskSecret renders just enough of a credential for a human to recognize
// which one it is, without disclosing a usable value.
func maskSecret(s string) string {
	s = strings.TrimSpace(s)
	switch {
	case s == "":
		return ""
	case len(s) <= 8:
		return strings.Repeat("*", len(s))
	default:
		return s[:2] + strings.Repeat("*", 8) + s[len(s)-2:]
	}
}

// truncate bounds a snippet so a single enormous minified line cannot bloat
// findings.json.
func truncate(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// firstCWE extracts a bare CWE identifier from the free-form strings tools
// emit, e.g. "CWE-89: Improper Neutralization of Special Elements".
func firstCWE(values []string) string {
	for _, v := range values {
		if i := strings.Index(v, "CWE-"); i >= 0 {
			rest := v[i+4:]
			end := 0
			for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
				end++
			}
			if end > 0 {
				return "CWE-" + rest[:end]
			}
		}
	}
	return ""
}

// ScanContext carries what every wrapper needs about the target.
type ScanContext struct {
	// RepoRoot is the absolute path of the project being analyzed.
	RepoRoot string

	// RepoRev is the git revision, recorded on each finding for traceability.
	RepoRev string

	// Exclude are glob patterns to skip.
	Exclude []string
}

// setLocationRev stamps the analyzed revision onto a location.
func (sc ScanContext) setLocationRev(loc *finding.Location) {
	loc.RepoRev = sc.RepoRev
}
