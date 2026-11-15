// Package scope enforces the single hard boundary in Vibe Killer: network
// checks only ever talk to a host the operator declared in
// authorized_targets.
//
// The guard is deliberately the only thing in the codebase that can authorize
// a network destination, and it is consulted twice for every connection:
//
//  1. before a check is scheduled, against the requested target URL;
//  2. again at dial time, against the IP the name actually resolved to.
//
// The second check exists because a name is not a destination. A hostname that
// answered with a loopback address when the run started can answer with
// something else a second later, and a redirect can point anywhere. Pinning
// the addresses observed at setup and re-checking every dial closes both.
package scope

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// Guard holds the declared scope for a run.
//
// A Guard is safe for concurrent use: the orchestrator shares one across all
// workers.
type Guard struct {
	// origins are the declared targets, normalized to scheme://host:port.
	origins map[string]struct{}

	// hostPorts indexes declared host:port pairs for dial-time checks.
	hostPorts map[string]struct{}

	// acknowledged records whether the operator passed --i-own-this-target.
	acknowledged bool

	mu sync.RWMutex
	// pinned maps a declared hostname to the addresses it resolved to the
	// first time we looked it up. Later dials must match.
	pinned map[string][]string

	// resolver is swappable so tests do not depend on DNS.
	resolver func(host string) ([]string, error)
}

// Option configures a Guard.
type Option func(*Guard)

// WithResolver replaces the name resolver, for tests.
func WithResolver(fn func(host string) ([]string, error)) Option {
	return func(g *Guard) { g.resolver = fn }
}

// WithAcknowledgement records that the operator confirmed target ownership via
// --i-own-this-target.
func WithAcknowledgement(ack bool) Option {
	return func(g *Guard) { g.acknowledged = ack }
}

// DefaultTargets is the scope a config gets when it declares none: the
// operator's own machine, and nothing else.
func DefaultTargets() []string {
	return []string{"http://localhost", "http://127.0.0.1"}
}

// New builds a Guard from declared target strings.
//
// Each target must be an absolute http or https URL. A target with a path is
// accepted but the path is ignored: scope is an origin, not a prefix, because
// a path prefix is trivially escaped by a redirect.
func New(targets []string, opts ...Option) (*Guard, error) {
	g := &Guard{
		origins:   map[string]struct{}{},
		hostPorts: map[string]struct{}{},
		pinned:    map[string][]string{},
		resolver:  defaultResolver,
	}
	for _, o := range opts {
		o(g)
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no authorized targets declared")
	}

	for _, raw := range targets {
		origin, hostPort, err := normalizeOrigin(raw)
		if err != nil {
			return nil, fmt.Errorf("authorized_targets entry %q: %w", raw, err)
		}
		g.origins[origin] = struct{}{}
		g.hostPorts[hostPort] = struct{}{}
	}
	return g, nil
}

func defaultResolver(host string) ([]string, error) {
	addrs, err := net.LookupHost(host)
	if err != nil {
		return nil, err
	}
	return addrs, nil
}

// normalizeOrigin reduces a target string to a canonical scheme://host:port
// and the bare host:port.
func normalizeOrigin(raw string) (origin, hostPort string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", fmt.Errorf("empty target")
	}
	// Tolerate a bare host:port, which operators write by habit.
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", "", fmt.Errorf("not a URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", "", fmt.Errorf("scheme %q is not supported (http or https only)", u.Scheme)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", "", fmt.Errorf("no host")
	}

	port := u.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	hostPort = net.JoinHostPort(host, port)
	return scheme + "://" + hostPort, hostPort, nil
}

// Targets lists the declared origins, sorted, for the run log.
func (g *Guard) Targets() []string {
	out := make([]string, 0, len(g.origins))
	for o := range g.origins {
		out = append(out, o)
	}
	sort.Strings(out)
	return out
}

// Acknowledged reports whether the operator confirmed target ownership.
func (g *Guard) Acknowledged() bool { return g.acknowledged }

// ErrNotAcknowledged is returned when a network check is attempted without
// --i-own-this-target.
type ErrNotAcknowledged struct{ Target string }

func (e *ErrNotAcknowledged) Error() string {
	return fmt.Sprintf("refusing to send requests to %s without --i-own-this-target: "+
		"pass that flag to confirm you own or are authorized to test this instance", e.Target)
}

// ErrOutOfScope is returned when a destination was never declared.
type ErrOutOfScope struct {
	Want     string
	Declared []string
}

func (e *ErrOutOfScope) Error() string {
	return fmt.Sprintf("refusing to touch %s: it is not in authorized_targets (declared: %s)",
		e.Want, strings.Join(e.Declared, ", "))
}

// AuthorizeTarget checks a target URL against the declared scope, and that the
// operator acknowledged ownership. Call this before scheduling any network
// check.
func (g *Guard) AuthorizeTarget(raw string) error {
	origin, _, err := normalizeOrigin(raw)
	if err != nil {
		return fmt.Errorf("target %q: %w", raw, err)
	}
	if _, ok := g.origins[origin]; !ok {
		return &ErrOutOfScope{Want: origin, Declared: g.Targets()}
	}
	if !g.acknowledged {
		return &ErrNotAcknowledged{Target: origin}
	}
	return nil
}

// InScope reports whether an origin was declared, without considering the
// acknowledgement. Used to decide whether a redirect may be followed.
func (g *Guard) InScope(raw string) bool {
	origin, _, err := normalizeOrigin(raw)
	if err != nil {
		return false
	}
	_, ok := g.origins[origin]
	return ok
}

// AuthorizeDial is the dial-time half of the boundary. It is called by the
// HTTP transport with the host:port being connected to and the address it
// resolved to.
//
// Two conditions must hold: the host:port must have been declared, and the
// resolved address must match what that name resolved to when the run set up
// its scope. The second condition is what stops a name from being re-pointed
// at a different machine partway through a run.
func (g *Guard) AuthorizeDial(hostPort, resolvedAddr string) error {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return fmt.Errorf("malformed dial address %q: %w", hostPort, err)
	}
	host = strings.ToLower(host)

	if _, ok := g.hostPorts[strings.ToLower(hostPort)]; !ok {
		return &ErrOutOfScope{Want: hostPort, Declared: g.Targets()}
	}

	resolvedHost, _, err := net.SplitHostPort(resolvedAddr)
	if err != nil {
		resolvedHost = resolvedAddr
	}
	ip := net.ParseIP(resolvedHost)
	if ip == nil {
		return fmt.Errorf("refusing to dial %s: %q is not an IP address", hostPort, resolvedHost)
	}

	// A declared literal IP needs no pinning: the name is the address.
	if net.ParseIP(host) != nil {
		if !ip.Equal(net.ParseIP(host)) {
			return fmt.Errorf("refusing to dial %s: it resolved to %s, which is a different address", hostPort, ip)
		}
		return nil
	}

	allowed, err := g.pinnedFor(host)
	if err != nil {
		return fmt.Errorf("refusing to dial %s: cannot resolve it to pin its address: %w", hostPort, err)
	}
	for _, a := range allowed {
		if pinned := net.ParseIP(a); pinned != nil && pinned.Equal(ip) {
			return nil
		}
	}
	return fmt.Errorf("refusing to dial %s: it now resolves to %s, which is not among the addresses "+
		"it resolved to when this run started (%s). The name may have been re-pointed mid-run",
		hostPort, ip, strings.Join(allowed, ", "))
}

// pinnedFor returns the addresses a declared hostname is pinned to, resolving
// and caching on first use.
func (g *Guard) pinnedFor(host string) ([]string, error) {
	g.mu.RLock()
	addrs, ok := g.pinned[host]
	g.mu.RUnlock()
	if ok {
		return addrs, nil
	}

	resolved, err := g.resolver(host)
	if err != nil {
		return nil, err
	}
	if len(resolved) == 0 {
		return nil, fmt.Errorf("%s resolved to no addresses", host)
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	// Another worker may have pinned it while we resolved.
	if existing, ok := g.pinned[host]; ok {
		return existing, nil
	}
	g.pinned[host] = resolved
	return resolved, nil
}

// IsLocal reports whether an address is on the operator's own machine or
// private network. Used only to describe scope in the run log and to warn when
// a declared target is public; it never widens scope by itself.
func IsLocal(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
}

// PublicTargets lists declared origins that are not loopback or private, so
// the CLI can call them out before a run. Declaring a public host is allowed
// if the operator owns it, but it should never be silent.
func (g *Guard) PublicTargets() []string {
	var out []string
	for o := range g.origins {
		u, err := url.Parse(o)
		if err != nil {
			continue
		}
		if !IsLocal(u.Hostname()) {
			out = append(out, o)
		}
	}
	sort.Strings(out)
	return out
}
