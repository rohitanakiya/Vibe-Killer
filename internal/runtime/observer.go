// Package runtime is the observe-only runtime front: the deepest view Vibe
// Killer has of an application, and the one that needs the most care.
//
// It answers questions no external check can: which queries actually ran while
// a request was served, and which authorization checks actually fired. A
// static rule can say a handler looks wrong and an endpoint check can say the
// boundary failed, but only the running process can say that the query reached
// the database with no owner predicate in it.
//
// # Vibe Killer does not inject anything into your process
//
// That is the whole design constraint here, and it is why this package is
// shaped the way it is. Reaching into a running process to instrument it would
// mean altering the application under test, which is exactly what the tool
// promises not to do, and it would leave the operator unsure what had been
// changed.
//
// So the direction is inverted. Vibe Killer opens a sink on loopback and
// prints a small snippet you add to your own application, in your own
// language, yourself. Your app posts observations to the sink while the scan
// runs. The code is yours, you can read all of it, and you remove it when you
// are done — there is nothing for Vibe Killer to clean up, because it never
// put anything there.
//
// The sink binds to loopback, accepts observations only while a run is in
// progress, and is shut down when the run ends.
package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SchemaVersion versions the observation format an agent posts.
const SchemaVersion = "1.0"

// Observation is what an agent reports about one handled request.
//
// Every field is something the application knew and an outside observer could
// not: which middleware ran, which queries were issued, and what the handler
// decided.
type Observation struct {
	SchemaVersion string `json:"schema_version"`

	// CorrelationID ties this observation to the request Vibe Killer sent.
	// The agent reads it from the X-Vibekiller-Probe header.
	CorrelationID string `json:"correlation_id"`

	Method string `json:"method"`

	// Path is the concrete path the application served.
	Path string `json:"path"`

	// Route is the template the framework matched, if the agent can read it.
	Route string `json:"route"`

	Status int `json:"status"`

	// Handler is the function that served the request.
	Handler string `json:"handler,omitempty"`

	// AuthChecks names the authorization middleware, decorators or guards
	// that actually ran. An empty list for a route the source declares as
	// protected is the finding.
	AuthChecks []string `json:"auth_checks,omitempty"`

	// Principal is the identity the application resolved, if any. This is
	// what the app thinks the caller is, which is not always what the token
	// said.
	Principal string `json:"principal,omitempty"`

	// Queries are the database statements issued while serving the request.
	Queries []Query `json:"queries,omitempty"`

	DurationMS int64 `json:"duration_ms,omitempty"`

	// ReceivedAt is set by the sink, not the agent.
	ReceivedAt time.Time `json:"received_at"`
}

// Query is one statement the application issued.
//
// The agent is expected to send the statement text with its parameters
// *separated*, never interpolated: the shape of the statement is what matters
// here, and a bound parameter may hold real data from the operator's own
// database. The sink refuses an observation whose parameters look like values
// rather than placeholders.
type Query struct {
	// SQL is the statement text as the driver received it, with placeholders
	// left in place.
	SQL string `json:"sql"`

	// ParamCount is how many parameters were bound. The values are
	// deliberately not transmitted.
	ParamCount int `json:"param_count"`

	// Table is the primary table, if the agent can determine it.
	Table string `json:"table,omitempty"`

	DurationMS int64 `json:"duration_ms,omitempty"`
}

// Observer is the per-stack runtime front.
//
// It exists as an interface because the way a runtime observation is obtained
// is entirely stack-specific — an in-process agent for Node or Python, a
// driver wrapper, a proxy — while what the checks need from it is the same.
// Nothing in the core knows which kind is attached.
type Observer interface {
	// Name identifies the observer, e.g. "agent-sink".
	Name() string

	// Start begins observing and returns the address or instructions the
	// operator needs.
	Start(ctx context.Context) error

	// Observations returns everything recorded so far.
	Observations() []Observation

	// ForCorrelation returns the observation matching a probe, if one
	// arrived.
	ForCorrelation(id string) (Observation, bool)

	// Attached reports whether anything is actually reporting. A runtime run
	// where the agent was never installed must say so rather than reporting
	// that nothing was wrong.
	Attached() bool

	// Stop detaches. It must leave nothing behind.
	Stop() error
}

// HeaderCorrelation is the header Vibe Killer sets on its probes, and the one
// an agent echoes back in its observation.
const HeaderCorrelation = "X-Vibekiller-Probe"

// Sink is an Observer that receives observations over loopback HTTP from an
// agent the operator installed in their own application.
type Sink struct {
	port int

	srv  *http.Server
	addr string

	mu            sync.RWMutex
	observations  []Observation
	byCorrelation map[string]Observation
	rejected      int
	lastReject    string
}

// NewSink builds a sink. A port of zero picks an ephemeral one.
func NewSink(port int) *Sink {
	return &Sink{port: port, byCorrelation: map[string]Observation{}}
}

// Name identifies the observer.
func (s *Sink) Name() string { return "agent-sink" }

// MaxObservationBytes bounds one posted observation.
const MaxObservationBytes = 256 << 10

// MaxObservations bounds how many are retained, so a long run cannot grow
// without limit.
const MaxObservations = 5000

// Start binds the sink on loopback and serves until Stop.
func (s *Sink) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", s.port))
	if err != nil {
		return fmt.Errorf("starting the runtime sink: %w", err)
	}
	s.addr = ln.Addr().String()

	mux := http.NewServeMux()
	mux.HandleFunc("/observe", s.handleObserve)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true,"schema_version":"` + SchemaVersion + `"}`))
	})

	s.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = s.srv.Serve(ln) }()

	return nil
}

// handleObserve accepts one observation.
func (s *Sink) handleObserve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, MaxObservationBytes+1))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if len(body) > MaxObservationBytes {
		s.reject("an observation exceeded the size limit")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}

	var obs Observation
	if err := json.Unmarshal(body, &obs); err != nil {
		s.reject("an observation was not valid JSON: " + err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if err := validate(&obs); err != nil {
		s.reject(err.Error())
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"error":` + jsonString(err.Error()) + `}`))
		return
	}

	obs.ReceivedAt = time.Now()

	s.mu.Lock()
	if len(s.observations) < MaxObservations {
		s.observations = append(s.observations, obs)
	}
	if obs.CorrelationID != "" {
		s.byCorrelation[obs.CorrelationID] = obs
	}
	s.mu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

// validate rejects an observation that carries more than it should.
//
// The important rule is the last one. An agent that interpolated parameter
// values into the statement text would be sending the operator's own data to
// the sink, where it would land in a run directory. The shape of the
// statement is all these checks need, so an observation that looks like it
// carries values is refused and the refusal is reported.
func validate(obs *Observation) error {
	if obs.SchemaVersion != "" && obs.SchemaVersion != SchemaVersion {
		return fmt.Errorf("observation schema_version %q is not %q", obs.SchemaVersion, SchemaVersion)
	}
	if obs.Method == "" && obs.Path == "" {
		return fmt.Errorf("observation names neither a method nor a path")
	}

	for i := range obs.Queries {
		q := &obs.Queries[i]
		if len(q.SQL) > 4000 {
			q.SQL = q.SQL[:4000] + " ...[truncated]"
		}
		if looksInterpolated(q.SQL) {
			return fmt.Errorf("refusing an observation whose statement looks like it has values " +
				"interpolated into it. Send the statement with its placeholders intact and the " +
				"parameters separate, so that no real data reaches the run directory")
		}
	}
	return nil
}

// interpolationMarkers are the shapes a statement takes once values have been
// substituted into it.
var interpolationMarkers = []string{"'", "\""}

// looksInterpolated reports whether a statement appears to carry literal
// values rather than placeholders.
//
// A quoted string in a statement an ORM built is almost always a substituted
// value; a parameterized statement carries ?, $1, :name or %s instead. This
// errs towards refusing, because the cost of a wrong refusal is a missing
// observation and the cost of a wrong acceptance is the operator's data on
// disk.
func looksInterpolated(sql string) bool {
	for _, m := range interpolationMarkers {
		if strings.Contains(sql, m) {
			return true
		}
	}
	return false
}

func jsonString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}

func (s *Sink) reject(reason string) {
	s.mu.Lock()
	s.rejected++
	s.lastReject = reason
	s.mu.Unlock()
}

// Rejected reports how many observations were refused, and why the last one
// was. A silent rejection would look like an application that issued no
// queries.
func (s *Sink) Rejected() (int, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rejected, s.lastReject
}

// Addr returns the sink's address.
func (s *Sink) Addr() string { return s.addr }

// URL returns the endpoint an agent posts to.
func (s *Sink) URL() string {
	if s.addr == "" {
		return ""
	}
	return "http://" + s.addr + "/observe"
}

// Observations returns everything recorded.
func (s *Sink) Observations() []Observation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Observation(nil), s.observations...)
}

// ForCorrelation returns the observation for one probe.
func (s *Sink) ForCorrelation(id string) (Observation, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	obs, ok := s.byCorrelation[id]
	return obs, ok
}

// Attached reports whether the agent ever posted anything.
func (s *Sink) Attached() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.observations) > 0
}

// Stop shuts the sink down.
func (s *Sink) Stop() error {
	if s.srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return s.srv.Shutdown(ctx)
}

// WaitForAgent blocks briefly for the first observation, so a run can tell the
// operator the agent is working before it starts probing.
func (s *Sink) WaitForAgent(ctx context.Context, d time.Duration) bool {
	deadline := time.NewTimer(d)
	defer deadline.Stop()
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()

	for {
		if s.Attached() {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-deadline.C:
			return s.Attached()
		case <-tick.C:
		}
	}
}

// --- query shape analysis --------------------------------------------------

// ownerColumnNames are the columns that tie a row to a principal. A
// single-record read that constrains none of them is a read that trusts the
// id it was given.
var ownerColumnNames = []string{
	"user_id", "userid", "owner_id", "ownerid", "account_id", "accountid",
	"tenant_id", "tenantid", "org_id", "orgid", "organization_id",
	"customer_id", "customerid", "created_by", "createdby", "author_id",
	"member_id", "team_id", "workspace_id",
}

// HasOwnerPredicate reports whether a statement constrains on an ownership
// column.
//
// The column has to appear in a comparison, not merely among the selected
// columns: "SELECT user_id FROM orders WHERE id = ?" returns the owner's id
// but constrains nothing, and reading it as scoped would hide exactly the
// weakness this is looking for.
//
// Both sides of the comparison count. A join writes the ownership constraint
// with the column on the right — "ON u.id = o.user_id" — and that is just as
// much a constraint as "WHERE user_id = ?".
func (q Query) HasOwnerPredicate() bool {
	lower := strings.ToLower(q.SQL)

	for _, col := range ownerColumnNames {
		offset := 0
		for {
			idx := strings.Index(lower[offset:], col)
			if idx < 0 {
				break
			}
			at := offset + idx
			offset = at + len(col)

			if !isWordBoundaried(lower, at, len(col)) {
				continue
			}
			if !inWhereClause(lower, at) {
				continue
			}
			if comparedAt(lower, at, len(col)) {
				return true
			}
		}
	}
	return false
}

// isWordBoundaried reports whether an occurrence is the whole identifier
// rather than part of a longer one, so that "subuser_id_old" does not count as
// "user_id". A dot before it is allowed, since that is a table qualifier.
func isWordBoundaried(s string, at, length int) bool {
	if at > 0 {
		prev := s[at-1]
		if isIdentChar(prev) {
			return false
		}
	}
	end := at + length
	if end < len(s) && isIdentChar(s[end]) {
		return false
	}
	return true
}

func isIdentChar(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

// comparisonOperators are what turns a column reference into a constraint.
var comparisonOperators = []string{"=", "!=", "<>", "in", "is", ">", "<"}

// comparedAt reports whether the occurrence sits on either side of a
// comparison.
func comparedAt(s string, at, length int) bool {
	after := strings.TrimLeft(s[at+length:], " \t\n\r")
	for _, op := range comparisonOperators {
		if strings.HasPrefix(after, op) {
			return true
		}
	}

	// Look to the left, skipping a table qualifier such as "o." so that
	// "= o.user_id" is recognized as a comparison against the column.
	before := s[:at]
	before = strings.TrimRight(before, " \t\n\r")
	if strings.HasSuffix(before, ".") {
		before = strings.TrimRight(before[:len(before)-1], " \t\n\r")
		// Drop the alias itself.
		i := len(before)
		for i > 0 && isIdentChar(before[i-1]) {
			i--
		}
		before = strings.TrimRight(before[:i], " \t\n\r")
	}
	for _, op := range comparisonOperators {
		if strings.HasSuffix(before, op) {
			return true
		}
	}
	return false
}

// inWhereClause reports whether an offset falls after a WHERE, ON or HAVING
// keyword, which is where a constraint lives.
func inWhereClause(lowerSQL string, offset int) bool {
	prefix := lowerSQL[:offset]
	for _, kw := range []string{" where ", " on ", " having ", " and ", " or "} {
		if strings.Contains(prefix, kw) {
			return true
		}
	}
	return false
}

// IsSingleRecordRead reports whether a statement reads one row by identifier,
// which is the shape an ownership check is supposed to guard.
func (q Query) IsSingleRecordRead() bool {
	lower := strings.ToLower(strings.TrimSpace(q.SQL))
	if !strings.HasPrefix(lower, "select") {
		return false
	}
	if !strings.Contains(lower, " where ") {
		return false
	}
	// A constraint on an id column, which is how a record is addressed.
	for _, form := range []string{"id =", "id=", "id in", "_id =", "_id=", ".id ="} {
		if strings.Contains(lower, form) {
			return true
		}
	}
	return false
}

// TableOf returns the primary table a statement reads, best effort.
func (q Query) TableOf() string {
	if q.Table != "" {
		return q.Table
	}
	lower := strings.ToLower(q.SQL)
	idx := strings.Index(lower, " from ")
	if idx < 0 {
		return ""
	}
	rest := strings.TrimSpace(q.SQL[idx+6:])
	for i, r := range rest {
		if r == ' ' || r == '\n' || r == '\t' || r == ',' || r == '(' || r == ')' {
			return strings.Trim(rest[:i], "`\"[]")
		}
	}
	return strings.Trim(rest, "`\"[]")
}
