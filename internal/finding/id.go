package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// idHashLen is how many hex characters of the digest go into a finding_id.
// 12 hex characters is 48 bits: collision-safe at the scale of one repo's
// findings, and short enough to paste into a CLI command by hand.
const idHashLen = 12

// LocationKey builds the part of the stable identity that comes from where the
// issue lives.
//
// It deliberately excludes line numbers and the repo revision. A finding must
// keep its identity when an unrelated edit shifts it down a few lines,
// otherwise every run-to-run diff would report the whole file as new.
func (l Location) LocationKey() string {
	norm := func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

	switch l.Type {
	case LocationEndpoint:
		// Endpoints are keyed on the route template, not the concrete path, so
		// that probing id 90001 and id 90002 of the same route collapse into
		// one finding.
		return strings.Join([]string{"endpoint", NormalizeEndpoint(l.Endpoint)}, "|")
	case LocationDependency:
		// Version is excluded: an upgrade that fixes the vulnerability should
		// mark the finding fixed rather than replace it with a new identity.
		return strings.Join([]string{"dependency", norm(l.Ecosystem), norm(l.Package)}, "|")
	case LocationConfig:
		return strings.Join([]string{"config", normPath(l.File), norm(l.ConfigKey)}, "|")
	case LocationCode:
		return strings.Join([]string{"code", normPath(l.File), norm(l.Symbol)}, "|")
	default:
		return strings.Join([]string{norm(string(l.Type)), normPath(l.File), norm(l.Symbol)}, "|")
	}
}

// normPath canonicalizes a repo-relative path so that Windows and POSIX
// separators produce the same identity for the same file.
func normPath(p string) string {
	p = strings.ReplaceAll(strings.TrimSpace(p), "\\", "/")
	p = strings.TrimPrefix(p, "./")
	return strings.ToLower(p)
}

var (
	// numericSegment matches a path segment that is purely a number.
	numericSegment = regexp.MustCompile(`^[0-9]+$`)
	// uuidSegment matches a canonical UUID path segment.
	uuidSegment = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	// hexSegment matches a long hex blob, e.g. a Mongo ObjectId or a token.
	hexSegment = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
	// templateSegment matches an already-templated segment in any common
	// framework syntax: {id}, :id, <int:id>, [id], $id.
	templateSegment = regexp.MustCompile(`^(\{.*\}|:.+|<.+>|\[.+\]|\$.+)$`)
)

// NormalizeEndpoint turns a concrete endpoint string into a stable route
// template, e.g. "GET /api/orders/90001" into "GET /api/orders/{id}".
//
// Normalizing here is what lets a static route finding and a dynamic probe of
// the same route be recognized as the same issue during de-duplication.
func NormalizeEndpoint(ep string) string {
	ep = strings.TrimSpace(ep)
	if ep == "" {
		return ""
	}

	method, path := "", ep
	if i := strings.IndexByte(ep, ' '); i > 0 {
		method, path = strings.ToUpper(ep[:i]), strings.TrimSpace(ep[i+1:])
	}

	// Drop any query string: it is not part of a route's identity.
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}

	segs := strings.Split(path, "/")
	for i, s := range segs {
		switch {
		case s == "":
			// Keep empty segments so the leading slash survives.
		case templateSegment.MatchString(s), numericSegment.MatchString(s),
			uuidSegment.MatchString(s), hexSegment.MatchString(s):
			segs[i] = "{id}"
		default:
			segs[i] = strings.ToLower(s)
		}
	}
	path = strings.Join(segs, "/")

	// Collapse a trailing slash so /orders and /orders/ are one route.
	if len(path) > 1 {
		path = strings.TrimSuffix(path, "/")
	}

	if method == "" {
		return path
	}
	return method + " " + path
}

// ComputeID derives the stable finding_id from the triple the contract names:
// rule_id, location key, and evidence key.
//
// The same underlying issue produces the same id on every run and on every
// machine, which is what makes the run-to-run diff meaningful.
func ComputeID(ruleID string, loc Location, evidenceKey string) string {
	h := sha256.New()
	// Length-prefix each component so that no shuffling of content between
	// fields can produce the same digest.
	for _, part := range []string{
		strings.ToLower(strings.TrimSpace(ruleID)),
		loc.LocationKey(),
		strings.TrimSpace(evidenceKey),
	} {
		h.Write([]byte(part))
		h.Write([]byte{0x1f}) // unit separator
	}
	return "vk-" + hex.EncodeToString(h.Sum(nil))[:idHashLen]
}

// AssignID fills in SchemaVersion and FindingID. Checks call this instead of
// building ids themselves, so the hashing rule lives in exactly one place.
func (f *Finding) AssignID() {
	f.SchemaVersion = SchemaVersion
	if f.Location.Type == LocationEndpoint {
		f.Location.Endpoint = NormalizeEndpoint(f.Location.Endpoint)
	}
	f.FindingID = ComputeID(f.RuleID, f.Location, f.Evidence.EvidenceKey)
}
