// Package httpx is the only way Vibe Killer makes an outbound request.
//
// Routing every endpoint check through one client is what makes the dynamic
// safety properties true rather than aspirational. The client:
//
//   - refuses, at dial time, to connect to anything outside the declared
//     scope, so no bug in a check can reach an undeclared host;
//   - refuses to follow a redirect that leaves the declared scope;
//   - applies a per-host token-bucket rate limit and a per-host concurrency
//     cap, so a scan cannot overwhelm the operator's own instance;
//   - backs off on 429 and 5xx rather than hammering a struggling target;
//   - records every request it sends to the run log, with credentials
//     redacted.
//
// A check cannot opt out of any of this, because a check never constructs a
// transport of its own.
package httpx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
	"github.com/rohitanakiya/Vibe-Killer/internal/scope"
)

// MaxBodyBytes bounds how much of a response body is read.
//
// Checks compare response bodies and look for canary markers; none of them
// needs a large payload, and an unbounded read would let a misbehaving target
// exhaust memory.
const MaxBodyBytes = 2 << 20 // 2 MiB

// DefaultMaxRetries is how many times a request is retried on 429 or 5xx.
const DefaultMaxRetries = 2

// Options configures a Client.
type Options struct {
	// Guard is the declared scope. Required: a client without one would be a
	// client that can reach anything.
	Guard *scope.Guard

	// MaxRPS is the per-host request rate.
	MaxRPS float64

	// Concurrency is the per-host cap on in-flight requests.
	Concurrency int

	// Timeout bounds each individual request.
	Timeout time.Duration

	// MaxRetries bounds retries on 429 and 5xx responses.
	MaxRetries int

	// UserAgent identifies the scanner in the target's own logs, so an
	// operator reading those logs can tell which traffic was theirs.
	UserAgent string

	// Recorder receives every request for the audit log. Optional.
	Recorder Recorder
}

// Recorder is the run-log sink. The run package satisfies this.
type Recorder interface {
	LogRequest(ruleID string, req finding.Request, status int, note string)
}

// Client is a scope-enforcing, rate-limited HTTP client.
type Client struct {
	opts Options
	http *http.Client

	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	sems     map[string]chan struct{}

	reqMu sync.Mutex
	count int
}

// ErrOutOfScope wraps a scope refusal so callers can tell it apart from a
// network failure.
var ErrOutOfScope = errors.New("destination is outside the declared scope")

// New builds a Client.
func New(opts Options) (*Client, error) {
	if opts.Guard == nil {
		return nil, fmt.Errorf("httpx: a scope guard is required")
	}
	if opts.MaxRPS <= 0 {
		opts.MaxRPS = 10
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 4
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 15 * time.Second
	}
	if opts.MaxRetries < 0 {
		opts.MaxRetries = 0
	} else if opts.MaxRetries == 0 {
		opts.MaxRetries = DefaultMaxRetries
	}
	if opts.UserAgent == "" {
		opts.UserAgent = "vibekiller"
	}

	c := &Client{
		opts:     opts,
		limiters: map[string]*rate.Limiter{},
		sems:     map[string]chan struct{}{},
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}

	transport := &http.Transport{
		// This is the enforcement point that a check cannot bypass: the
		// address is checked after resolution, immediately before the socket
		// is opened.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("httpx: malformed dial address %q: %w", addr, err)
			}

			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("httpx: resolving %s: %w", host, err)
			}

			var lastErr error
			for _, ip := range ips {
				resolved := net.JoinHostPort(ip.IP.String(), port)
				if err := opts.Guard.AuthorizeDial(addr, resolved); err != nil {
					lastErr = fmt.Errorf("%w: %v", ErrOutOfScope, err)
					continue
				}
				conn, err := dialer.DialContext(ctx, network, resolved)
				if err != nil {
					lastErr = err
					continue
				}
				return conn, nil
			}
			if lastErr == nil {
				lastErr = fmt.Errorf("httpx: %s resolved to no usable address", host)
			}
			return nil, lastErr
		},
		MaxIdleConns:        20,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  false,
		ForceAttemptHTTP2:   true,
	}

	c.http = &http.Client{
		Transport: transport,
		Timeout:   opts.Timeout,
		// A redirect is a destination the target chose, not one the operator
		// declared, so it gets checked against scope like any other.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("httpx: stopped after 5 redirects")
			}
			if !opts.Guard.InScope(req.URL.Scheme + "://" + req.URL.Host) {
				return fmt.Errorf("%w: refusing to follow a redirect to %s",
					ErrOutOfScope, req.URL.Redacted())
			}
			return nil
		},
	}

	return c, nil
}

// Request describes one request a check wants to send.
type Request struct {
	// RuleID is the check making the request, for the audit log.
	RuleID string

	Method string

	// URL is the absolute target URL. It must be inside the declared scope.
	URL string

	Headers map[string]string
	Body    string

	// AuthLabel is the seeded-user label recorded in evidence, e.g. "userA".
	// The token itself goes in Headers and is redacted before logging.
	AuthLabel string

	// Note is a short description of intent for the audit log.
	Note string
}

// Response is what a check gets back.
type Response struct {
	Status     int
	Headers    http.Header
	Body       string
	Elapsed    time.Duration
	Truncated  bool
	FinalURL   string
	Redirected bool
}

// BodyContains reports whether the response body contains a marker. Checks use
// this to confirm a seeded canary actually crossed a boundary, rather than
// inferring it from the status code alone.
func (r *Response) BodyContains(marker string) bool {
	if marker == "" {
		return false
	}
	return strings.Contains(r.Body, marker)
}

// Do sends a request, enforcing scope, rate limit and concurrency, and
// records it in the run log.
func (c *Client) Do(ctx context.Context, req Request) (*Response, error) {
	if err := c.opts.Guard.AuthorizeTarget(req.URL); err != nil {
		// Record the refusal: a check that tried to go out of scope is
		// something the operator should be able to see in the log.
		c.record(req, 0, "refused: "+err.Error())
		return nil, fmt.Errorf("%w: %v", ErrOutOfScope, err)
	}

	u, err := url.Parse(req.URL)
	if err != nil {
		return nil, fmt.Errorf("httpx: parsing %q: %w", req.URL, err)
	}
	host := strings.ToLower(u.Host)

	// Per-host concurrency cap.
	sem := c.semaphore(host)
	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	method := req.Method
	if method == "" {
		method = http.MethodGet
	}

	var resp *Response
	var lastErr error

	for attempt := 0; attempt <= c.opts.MaxRetries; attempt++ {
		// Token-bucket rate limit, per host.
		if err := c.limiter(host).Wait(ctx); err != nil {
			return nil, err
		}

		resp, lastErr = c.attempt(ctx, method, req)
		if lastErr != nil {
			if errors.Is(lastErr, ErrOutOfScope) || errors.Is(lastErr, context.Canceled) {
				c.record(req, 0, "failed: "+lastErr.Error())
				return nil, lastErr
			}
			// A transport error is worth one retry: a dev server that was
			// still starting up is the common case.
			if attempt < c.opts.MaxRetries {
				if err := sleep(ctx, backoff(attempt, 0)); err != nil {
					return nil, err
				}
				continue
			}
			c.record(req, 0, "failed: "+lastErr.Error())
			return nil, lastErr
		}

		// Back off when the target says it is overloaded, rather than
		// treating the response as a result.
		if resp.Status == http.StatusTooManyRequests || resp.Status >= 500 {
			if attempt < c.opts.MaxRetries {
				wait := backoff(attempt, retryAfter(resp.Headers))
				c.record(req, resp.Status, fmt.Sprintf("backing off %s before retry %d", wait, attempt+1))
				if err := sleep(ctx, wait); err != nil {
					return nil, err
				}
				continue
			}
		}
		break
	}

	if lastErr != nil {
		return nil, lastErr
	}

	note := req.Note
	if resp.Redirected {
		note = strings.TrimSpace(note + " (followed redirect to " + resp.FinalURL + ")")
	}
	c.record(req, resp.Status, note)
	return resp, nil
}

func (c *Client) attempt(ctx context.Context, method string, req Request) (*Response, error) {
	var body io.Reader
	if req.Body != "" {
		body = strings.NewReader(req.Body)
	}

	hreq, err := http.NewRequestWithContext(ctx, method, req.URL, body)
	if err != nil {
		return nil, fmt.Errorf("httpx: building request: %w", err)
	}

	hreq.Header.Set("User-Agent", c.opts.UserAgent)
	hreq.Header.Set("Accept", "*/*")
	for k, v := range req.Headers {
		hreq.Header.Set(k, v)
	}

	start := time.Now()
	hresp, err := c.http.Do(hreq)
	if err != nil {
		// A scope refusal from CheckRedirect or DialContext arrives wrapped in
		// a *url.Error; unwrap so callers can match on it.
		if errors.Is(err, ErrOutOfScope) {
			return nil, fmt.Errorf("%w: %v", ErrOutOfScope, err)
		}
		return nil, err
	}
	defer hresp.Body.Close()

	limited := io.LimitReader(hresp.Body, MaxBodyBytes+1)
	data, readErr := io.ReadAll(limited)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, fmt.Errorf("httpx: reading response body: %w", readErr)
	}

	truncated := false
	if len(data) > MaxBodyBytes {
		data = data[:MaxBodyBytes]
		truncated = true
	}

	finalURL := hresp.Request.URL.String()
	return &Response{
		Status:     hresp.StatusCode,
		Headers:    hresp.Header,
		Body:       string(data),
		Elapsed:    time.Since(start),
		Truncated:  truncated,
		FinalURL:   finalURL,
		Redirected: finalURL != req.URL,
	}, nil
}

// record writes the request to the audit log and counts it.
func (c *Client) record(req Request, status int, note string) {
	c.reqMu.Lock()
	c.count++
	c.reqMu.Unlock()

	if c.opts.Recorder == nil {
		return
	}

	u, err := url.Parse(req.URL)
	path := req.URL
	if err == nil {
		path = u.RequestURI()
	}

	c.opts.Recorder.LogRequest(req.RuleID, finding.Request{
		Method: req.Method,
		Path:   path,
		// Headers are redacted by the recorder, but the auth label is what
		// actually belongs in evidence: it names the seeded identity rather
		// than carrying its token.
		Headers: finding.RedactHeaders(req.Headers),
		Auth:    req.AuthLabel,
		Body:    truncateBody(req.Body),
	}, status, note)
}

func truncateBody(s string) string {
	const max = 512
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// Count reports how many requests this client has sent.
func (c *Client) Count() int {
	c.reqMu.Lock()
	defer c.reqMu.Unlock()
	return c.count
}

func (c *Client) limiter(host string) *rate.Limiter {
	c.mu.Lock()
	defer c.mu.Unlock()
	l, ok := c.limiters[host]
	if !ok {
		// A burst of one keeps the scan to a steady trickle rather than
		// letting it arrive in bunches, which matters when the target is the
		// operator's own laptop.
		l = rate.NewLimiter(rate.Limit(c.opts.MaxRPS), 1)
		c.limiters[host] = l
	}
	return l
}

func (c *Client) semaphore(host string) chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.sems[host]
	if !ok {
		s = make(chan struct{}, c.opts.Concurrency)
		c.sems[host] = s
	}
	return s
}

// Close releases idle connections. A run must not leave sockets open.
func (c *Client) Close() error {
	if t, ok := c.http.Transport.(*http.Transport); ok {
		t.CloseIdleConnections()
	}
	return nil
}

// backoff returns the wait before the next attempt, honouring a Retry-After
// hint when the target gave one.
func backoff(attempt int, retryAfter time.Duration) time.Duration {
	if retryAfter > 0 {
		if retryAfter > 30*time.Second {
			return 30 * time.Second
		}
		return retryAfter
	}
	d := time.Duration(1<<attempt) * 500 * time.Millisecond
	if d > 8*time.Second {
		return 8 * time.Second
	}
	return d
}

// retryAfter reads the Retry-After header in either of its two forms.
func retryAfter(h http.Header) time.Duration {
	v := strings.TrimSpace(h.Get("Retry-After"))
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
