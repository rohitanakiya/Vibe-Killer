package httpx

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rohitanakiya/Vibe-Killer/internal/finding"
	"github.com/rohitanakiya/Vibe-Killer/internal/scope"
)

// This package is the single enforcement point for everything Vibe Killer
// promises about network behaviour, so these tests are about the promises
// rather than about plumbing: that an undeclared host cannot be reached, that
// a redirect cannot carry a request out of scope, that the target's own rate
// limit is respected, and that a credential never reaches the audit log.

// recorder captures what the client logged.
type recorder struct {
	mu      chan struct{}
	entries []entry
}

type entry struct {
	ruleID string
	req    finding.Request
	status int
	note   string
}

func newRecorder() *recorder {
	return &recorder{mu: make(chan struct{}, 1)}
}

func (r *recorder) LogRequest(ruleID string, req finding.Request, status int, note string) {
	r.mu <- struct{}{}
	r.entries = append(r.entries, entry{ruleID, req, status, note})
	<-r.mu
}

func (r *recorder) all() []entry {
	r.mu <- struct{}{}
	defer func() { <-r.mu }()
	return append([]entry(nil), r.entries...)
}

func clientFor(t *testing.T, targets []string, opts ...func(*Options)) (*Client, *recorder) {
	t.Helper()

	guard, err := scope.New(targets, scope.WithAcknowledgement(true))
	if err != nil {
		t.Fatal(err)
	}

	rec := newRecorder()
	o := Options{
		Guard: guard, MaxRPS: 1000, Concurrency: 4,
		Timeout: 5 * time.Second, Recorder: rec,
	}
	for _, fn := range opts {
		fn(&o)
	}

	c, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, rec
}

func TestNewRequiresAGuard(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("a client was built with no scope guard; it would be able to reach anything")
	}
}

func TestRequestsToDeclaredHostsSucceed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c, rec := clientFor(t, []string{srv.URL})

	resp, err := c.Do(context.Background(), Request{
		RuleID: "test.rule", Method: http.MethodGet, URL: srv.URL + "/api/x",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 || !strings.Contains(resp.Body, "ok") {
		t.Errorf("response = %d %q", resp.Status, resp.Body)
	}
	if c.Count() != 1 {
		t.Errorf("count = %d", c.Count())
	}

	logged := rec.all()
	if len(logged) != 1 {
		t.Fatalf("logged %d requests, want 1", len(logged))
	}
	if logged[0].req.Path != "/api/x" {
		t.Errorf("logged path = %q", logged[0].req.Path)
	}
}

// The core promise. An undeclared host must be unreachable even when a check
// asks for it directly, and the refusal must be recorded so the operator can
// see that something tried.
func TestUndeclaredHostsAreRefusedAndTheAttemptIsLogged(t *testing.T) {
	declared := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`ok`))
	}))
	defer declared.Close()

	var reached int32
	undeclared := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&reached, 1)
		_, _ = w.Write([]byte(`ok`))
	}))
	defer undeclared.Close()

	c, rec := clientFor(t, []string{declared.URL})

	_, err := c.Do(context.Background(), Request{
		RuleID: "test.rule", Method: http.MethodGet, URL: undeclared.URL + "/secrets",
	})
	if err == nil {
		t.Fatal("the client allowed a request to an undeclared host")
	}
	if !errors.Is(err, ErrOutOfScope) {
		t.Errorf("error = %v, want ErrOutOfScope", err)
	}
	if atomic.LoadInt32(&reached) != 0 {
		t.Error("the undeclared host was actually contacted")
	}

	logged := rec.all()
	if len(logged) != 1 || !strings.Contains(logged[0].note, "refused") {
		t.Errorf("the refusal was not recorded: %+v", logged)
	}
}

// A redirect is a destination the target chose, not one the operator declared,
// so it gets checked like any other.
func TestRedirectsOutOfScopeAreRefused(t *testing.T) {
	var followed int32
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&followed, 1)
		_, _ = w.Write([]byte(`you should not be here`))
	}))
	defer elsewhere.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/landed", http.StatusFound)
	}))
	defer redirector.Close()

	c, _ := clientFor(t, []string{redirector.URL})

	_, err := c.Do(context.Background(), Request{
		RuleID: "test.rule", Method: http.MethodGet, URL: redirector.URL + "/go",
	})
	if err == nil {
		t.Fatal("the client followed a redirect out of the declared scope")
	}
	if atomic.LoadInt32(&followed) != 0 {
		t.Error("the out-of-scope redirect target was contacted")
	}
}

// A redirect inside the declared scope is ordinary and must work.
func TestRedirectsWithinScopeAreFollowed(t *testing.T) {
	var mux http.ServeMux
	srv := httptest.NewServer(&mux)
	defer srv.Close()

	mux.HandleFunc("/go", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/landed", http.StatusFound)
	})
	mux.HandleFunc("/landed", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`arrived`))
	})

	c, _ := clientFor(t, []string{srv.URL})

	resp, err := c.Do(context.Background(), Request{
		RuleID: "test.rule", Method: http.MethodGet, URL: srv.URL + "/go",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp.Body, "arrived") {
		t.Errorf("body = %q", resp.Body)
	}
	if !resp.Redirected {
		t.Error("the response does not record that it was redirected")
	}
}

func TestRedirectLoopsAreBounded(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/again", http.StatusFound)
	}))
	defer srv.Close()

	c, _ := clientFor(t, []string{srv.URL})

	if _, err := c.Do(context.Background(), Request{
		RuleID: "test.rule", Method: http.MethodGet, URL: srv.URL + "/start",
	}); err == nil {
		t.Fatal("an endless redirect loop was followed without limit")
	}
}

// A run directory gets attached to tickets, so a credential must never reach
// the audit log. The seeded-user label is what belongs there.
func TestCredentialsAreRedactedInTheAuditLog(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`ok`))
	}))
	defer srv.Close()

	c, rec := clientFor(t, []string{srv.URL})

	const secret = "Bearer eyJhbGciOiJIUzI1NiJ9.super-secret-value"
	_, err := c.Do(context.Background(), Request{
		RuleID: "test.rule", Method: http.MethodGet, URL: srv.URL + "/api/x",
		Headers: map[string]string{
			"Authorization": secret,
			"Cookie":        "session=also-secret",
			"Accept":        "application/json",
		},
		AuthLabel: "userA",
	})
	if err != nil {
		t.Fatal(err)
	}

	logged := rec.all()
	if len(logged) != 1 {
		t.Fatalf("logged %d", len(logged))
	}

	for _, header := range []string{"Authorization", "Cookie"} {
		if got := logged[0].req.Headers[header]; got != finding.RedactedMarker {
			t.Errorf("%s was logged as %q, want it redacted", header, got)
		}
	}
	if logged[0].req.Headers["Accept"] != "application/json" {
		t.Error("a harmless header was altered")
	}
	if logged[0].req.Auth != "userA" {
		t.Errorf("the auth label was logged as %q", logged[0].req.Auth)
	}

	// Belt and braces: the secret must not appear anywhere in what was logged.
	if strings.Contains(fmt.Sprintf("%+v", logged), "super-secret-value") {
		t.Error("the credential value reached the audit log")
	}
}

// The target is usually a development server on the operator's own machine, so
// the rate limit is a courtesy that has to actually work.
func TestPerHostRateLimitIsApplied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`ok`))
	}))
	defer srv.Close()

	// 20 requests per second: six requests must take at least a quarter of a
	// second, where an unlimited client would finish in milliseconds.
	c, _ := clientFor(t, []string{srv.URL}, func(o *Options) { o.MaxRPS = 20 })

	start := time.Now()
	for i := 0; i < 6; i++ {
		if _, err := c.Do(context.Background(), Request{
			RuleID: "test.rule", Method: http.MethodGet, URL: srv.URL + "/x",
		}); err != nil {
			t.Fatal(err)
		}
	}
	elapsed := time.Since(start)

	if elapsed < 200*time.Millisecond {
		t.Errorf("six requests at 20 rps took %s; the rate limit is not being applied", elapsed)
	}
}

// A struggling target should be backed off from, not hammered.
func TestBackoffOn429AndThenSuccess(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempts, 1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`ok`))
	}))
	defer srv.Close()

	c, rec := clientFor(t, []string{srv.URL}, func(o *Options) { o.MaxRetries = 2 })

	resp, err := c.Do(context.Background(), Request{
		RuleID: "test.rule", Method: http.MethodGet, URL: srv.URL + "/x",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Errorf("status = %d, want the retry to have succeeded", resp.Status)
	}
	if atomic.LoadInt32(&attempts) < 2 {
		t.Error("the client did not retry after a 429")
	}

	// The backoff should be visible in the log, so a slow scan is explicable.
	var sawBackoff bool
	for _, e := range rec.all() {
		if strings.Contains(e.note, "backing off") {
			sawBackoff = true
		}
	}
	if !sawBackoff {
		t.Error("the backoff was not recorded in the audit log")
	}
}

func TestRetryAfterParsing(t *testing.T) {
	h := http.Header{}

	h.Set("Retry-After", "3")
	if got := retryAfter(h); got != 3*time.Second {
		t.Errorf("numeric Retry-After = %s", got)
	}

	h.Set("Retry-After", http.TimeFormat)
	_ = retryAfter(h) // a malformed date must not panic

	h.Del("Retry-After")
	if got := retryAfter(h); got != 0 {
		t.Errorf("absent Retry-After = %s", got)
	}
}

func TestBackoffIsBounded(t *testing.T) {
	// A Retry-After the target chose must not let it park the scan.
	if got := backoff(0, time.Hour); got > 30*time.Second {
		t.Errorf("backoff honoured an hour-long Retry-After: %s", got)
	}
	// And the exponential growth must have a ceiling.
	if got := backoff(20, 0); got > 8*time.Second {
		t.Errorf("backoff grew unbounded: %s", got)
	}
}

// A misbehaving target must not be able to exhaust the scanner's memory.
func TestResponseBodiesAreTruncated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := strings.Repeat("A", 64<<10)
		for i := 0; i < 64; i++ { // 4 MiB, over the 2 MiB cap
			_, _ = w.Write([]byte(chunk))
		}
	}))
	defer srv.Close()

	c, _ := clientFor(t, []string{srv.URL})

	resp, err := c.Do(context.Background(), Request{
		RuleID: "test.rule", Method: http.MethodGet, URL: srv.URL + "/big",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Body) > MaxBodyBytes {
		t.Errorf("body is %d bytes, over the %d cap", len(resp.Body), MaxBodyBytes)
	}
	if !resp.Truncated {
		t.Error("the response does not record that it was truncated")
	}
}

func TestContextCancellationStopsTheRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	c, _ := clientFor(t, []string{srv.URL})

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	if _, err := c.Do(ctx, Request{
		RuleID: "test.rule", Method: http.MethodGet, URL: srv.URL + "/hang",
	}); err == nil {
		t.Fatal("a cancelled request returned successfully")
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Errorf("cancellation took %s to take effect", elapsed)
	}
}

func TestBodyContains(t *testing.T) {
	r := &Response{Body: `{"note":"VK-CANARY-USERB"}`}

	if !r.BodyContains("VK-CANARY-USERB") {
		t.Error("BodyContains missed a present marker")
	}
	if r.BodyContains("VK-CANARY-USERA") {
		t.Error("BodyContains matched an absent marker")
	}
	// An empty marker must never match, or every response would look like a
	// disclosure.
	if r.BodyContains("") {
		t.Error("an empty marker matched")
	}
}

func TestUserAgentIdentifiesTheScanner(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("User-Agent")
		_, _ = w.Write([]byte(`ok`))
	}))
	defer srv.Close()

	c, _ := clientFor(t, []string{srv.URL}, func(o *Options) { o.UserAgent = "vibekiller/test" })

	if _, err := c.Do(context.Background(), Request{
		RuleID: "test.rule", Method: http.MethodGet, URL: srv.URL + "/x",
	}); err != nil {
		t.Fatal(err)
	}

	// The operator has to be able to tell which traffic in their own logs was
	// the scan.
	if !strings.Contains(seen, "vibekiller") {
		t.Errorf("User-Agent = %q, want it to identify the scanner", seen)
	}
}

func TestRequestBodyIsSentAndTruncatedInTheLog(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 64)
		n, _ := r.Body.Read(buf)
		got = string(buf[:n])
		_, _ = w.Write([]byte(`ok`))
	}))
	defer srv.Close()

	c, rec := clientFor(t, []string{srv.URL})

	long := strings.Repeat("x", 2000)
	if _, err := c.Do(context.Background(), Request{
		RuleID: "test.rule", Method: http.MethodPost, URL: srv.URL + "/x", Body: long,
	}); err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(got, "xxxx") {
		t.Errorf("the body was not sent: %q", got)
	}
	logged := rec.all()
	if len(logged[0].req.Body) > 600 {
		t.Errorf("the logged body is %d bytes; it should be truncated", len(logged[0].req.Body))
	}
}
