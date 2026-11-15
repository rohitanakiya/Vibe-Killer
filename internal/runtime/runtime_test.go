package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func startSink(t *testing.T) *Sink {
	t.Helper()
	s := NewSink(0)
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Stop() })
	return s
}

func post(t *testing.T, s *Sink, obs Observation) int {
	t.Helper()
	body, err := json.Marshal(obs)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(s.URL(), "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// The sink must bind to loopback only. A sink on all interfaces would be a
// service Vibe Killer had opened on the operator's machine, which is the
// opposite of what the tool promises.
func TestSinkBindsToLoopbackOnly(t *testing.T) {
	s := startSink(t)

	if !strings.HasPrefix(s.Addr(), "127.0.0.1:") {
		t.Errorf("the sink bound to %q, want loopback", s.Addr())
	}
	if !strings.HasPrefix(s.URL(), "http://127.0.0.1:") {
		t.Errorf("sink URL = %q", s.URL())
	}
}

func TestSinkRecordsAndCorrelatesObservations(t *testing.T) {
	s := startSink(t)

	if s.Attached() {
		t.Error("the sink reports attached before anything posted")
	}

	code := post(t, s, Observation{
		SchemaVersion: SchemaVersion,
		CorrelationID: "probe-1",
		Method:        "GET",
		Path:          "/api/orders/90001",
		Route:         "/api/orders/<int:order_id>",
		Status:        200,
		Handler:       "get_order",
		AuthChecks:    []string{"require_auth"},
		Queries: []Query{
			{SQL: "SELECT id, item FROM orders WHERE id = ?", ParamCount: 1},
		},
	})
	if code != http.StatusNoContent {
		t.Fatalf("post returned %d", code)
	}

	if !s.Attached() {
		t.Error("the sink does not report attached after an observation arrived")
	}

	obs, ok := s.ForCorrelation("probe-1")
	if !ok {
		t.Fatal("the observation was not correlated")
	}
	if obs.Handler != "get_order" || len(obs.Queries) != 1 {
		t.Errorf("observation = %+v", obs)
	}
	if obs.ReceivedAt.IsZero() {
		t.Error("the sink did not stamp received_at")
	}

	if _, ok := s.ForCorrelation("probe-unknown"); ok {
		t.Error("the sink correlated an id it never received")
	}
	if len(s.Observations()) != 1 {
		t.Errorf("observations = %d", len(s.Observations()))
	}
}

// This is the safety property that matters most in this package. An agent that
// interpolated values into the statement text would be sending the operator's
// own data to the sink, where it would land in a run directory. The sink
// refuses it rather than storing it.
func TestSinkRefusesStatementsThatCarryValues(t *testing.T) {
	s := startSink(t)

	refused := []string{
		"SELECT * FROM orders WHERE id = '90001'",
		`SELECT * FROM users WHERE email = "grace@example.invalid"`,
		"SELECT * FROM orders WHERE note = 'VK-CANARY-USERB'",
	}
	for _, sql := range refused {
		code := post(t, s, Observation{
			SchemaVersion: SchemaVersion, Method: "GET", Path: "/x",
			Queries: []Query{{SQL: sql, ParamCount: 0}},
		})
		if code != http.StatusUnprocessableEntity {
			t.Errorf("the sink accepted a statement carrying values (%d): %s", code, sql)
		}
	}

	if len(s.Observations()) != 0 {
		t.Errorf("%d refused observation(s) were stored anyway", len(s.Observations()))
	}

	// The refusal has to be visible, or it looks like an app that ran no
	// queries.
	n, reason := s.Rejected()
	if n != len(refused) {
		t.Errorf("rejected count = %d, want %d", n, len(refused))
	}
	if !strings.Contains(reason, "placeholders") {
		t.Errorf("the recorded reason should explain the requirement: %q", reason)
	}

	// Parameterized statements in every common placeholder style must pass.
	accepted := []string{
		"SELECT * FROM orders WHERE id = ?",
		"SELECT * FROM orders WHERE id = $1 AND user_id = $2",
		"SELECT * FROM orders WHERE id = :id",
		"SELECT * FROM orders WHERE id = %s",
	}
	for _, sql := range accepted {
		code := post(t, s, Observation{
			SchemaVersion: SchemaVersion, Method: "GET", Path: "/x",
			Queries: []Query{{SQL: sql, ParamCount: 1}},
		})
		if code != http.StatusNoContent {
			t.Errorf("the sink refused a parameterized statement (%d): %s", code, sql)
		}
	}
}

func TestSinkRejectsMalformedAndMismatchedObservations(t *testing.T) {
	s := startSink(t)

	resp, err := http.Post(s.URL(), "application/json", strings.NewReader("{not json"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("malformed JSON returned %d", resp.StatusCode)
	}

	if code := post(t, s, Observation{SchemaVersion: "99.0", Method: "GET", Path: "/x"}); code != http.StatusUnprocessableEntity {
		t.Errorf("a mismatched schema version returned %d", code)
	}

	if code := post(t, s, Observation{SchemaVersion: SchemaVersion}); code != http.StatusUnprocessableEntity {
		t.Errorf("an observation naming neither method nor path returned %d", code)
	}

	// Only POST is accepted.
	getResp, err := http.Get(s.URL())
	if err != nil {
		t.Fatal(err)
	}
	_ = getResp.Body.Close()
	if getResp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET on the sink returned %d", getResp.StatusCode)
	}
}

func TestSinkHealthEndpoint(t *testing.T) {
	s := startSink(t)

	resp, err := http.Get("http://" + s.Addr() + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("health returned %d", resp.StatusCode)
	}
}

func TestSinkStopsCleanly(t *testing.T) {
	s := NewSink(0)
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	url := s.URL()

	if err := s.Stop(); err != nil {
		t.Errorf("Stop returned %v", err)
	}
	if _, err := http.Post(url, "application/json", strings.NewReader("{}")); err == nil {
		t.Error("the sink still answers after Stop; a run must leave nothing listening")
	}
	// Stopping twice must not panic.
	_ = s.Stop()
}

func TestWaitForAgentTimesOut(t *testing.T) {
	s := startSink(t)

	start := time.Now()
	if s.WaitForAgent(context.Background(), 300*time.Millisecond) {
		t.Error("WaitForAgent reported an agent that never posted")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("WaitForAgent waited %s, far longer than asked", elapsed)
	}

	post(t, s, Observation{SchemaVersion: SchemaVersion, Method: "GET", Path: "/x"})
	if !s.WaitForAgent(context.Background(), time.Second) {
		t.Error("WaitForAgent did not see an observation that had already arrived")
	}
}

// --- query shape analysis --------------------------------------------------

// This is the analysis the whole runtime access-control finding rests on, so
// each case is one the checks will actually meet.
func TestHasOwnerPredicate(t *testing.T) {
	withOwner := []string{
		"SELECT * FROM orders WHERE id = ? AND user_id = ?",
		"SELECT * FROM orders WHERE user_id = $1 AND id = $2",
		"select * from orders where id=? and owner_id=?",
		"SELECT * FROM o JOIN u ON u.id = o.user_id WHERE o.id = ?",
		"SELECT * FROM orders WHERE id = ? AND tenant_id IN (?)",
		"SELECT * FROM docs WHERE id = ? AND created_by = ?",
	}
	for _, sql := range withOwner {
		if !(Query{SQL: sql}).HasOwnerPredicate() {
			t.Errorf("HasOwnerPredicate = false for a scoped query: %s", sql)
		}
	}

	withoutOwner := []string{
		"SELECT * FROM orders WHERE id = ?",
		"SELECT id, item, user_id FROM orders WHERE id = ?", // selected, not constrained
		"select * from orders where id = $1",
		"SELECT * FROM orders WHERE id = ? LIMIT 1",
	}
	for _, sql := range withoutOwner {
		if (Query{SQL: sql}).HasOwnerPredicate() {
			t.Errorf("HasOwnerPredicate = true for an unscoped query: %s", sql)
		}
	}
}

// Selecting a column is not constraining on it. This is the distinction that
// decides whether a finding is raised, so it gets its own test.
func TestSelectingAnOwnerColumnIsNotConstrainingOnIt(t *testing.T) {
	q := Query{SQL: "SELECT id, item, user_id, total FROM orders WHERE id = ?"}
	if q.HasOwnerPredicate() {
		t.Error("a query that merely selects user_id was treated as scoping on it")
	}
	if !q.IsSingleRecordRead() {
		t.Error("the query was not recognized as a single-record read")
	}
}

func TestIsSingleRecordRead(t *testing.T) {
	yes := []string{
		"SELECT * FROM orders WHERE id = ?",
		"select id from orders where _id = ?",
		"SELECT * FROM orders WHERE o.id = ? AND x = ?",
	}
	for _, sql := range yes {
		if !(Query{SQL: sql}).IsSingleRecordRead() {
			t.Errorf("IsSingleRecordRead = false for: %s", sql)
		}
	}

	no := []string{
		"SELECT * FROM orders",                     // no where
		"UPDATE orders SET total = ? WHERE id = ?", // not a read
		"INSERT INTO orders VALUES (?, ?, ?)",
		"SELECT * FROM orders WHERE total > ?", // not by id
	}
	for _, sql := range no {
		if (Query{SQL: sql}).IsSingleRecordRead() {
			t.Errorf("IsSingleRecordRead = true for: %s", sql)
		}
	}
}

func TestTableOf(t *testing.T) {
	tests := []struct{ sql, want string }{
		{"SELECT * FROM orders WHERE id = ?", "orders"},
		{"SELECT * FROM `orders` WHERE id = ?", "orders"},
		{"select a, b from user_profiles where id = ?", "user_profiles"},
		{"SELECT * FROM orders, items WHERE id = ?", "orders"},
		{"SELECT 1", ""},
	}
	for _, tc := range tests {
		if got := (Query{SQL: tc.sql}).TableOf(); got != tc.want {
			t.Errorf("TableOf(%q) = %q, want %q", tc.sql, got, tc.want)
		}
	}

	// An explicit table from the agent wins over parsing.
	if got := (Query{SQL: "SELECT 1", Table: "orders"}).TableOf(); got != "orders" {
		t.Errorf("TableOf ignored the agent's explicit table: %q", got)
	}
}

// --- agents ----------------------------------------------------------------

func TestAgentsAreBundledForTheSupportedStacks(t *testing.T) {
	stacks := AvailableAgents()
	if len(stacks) < 2 {
		t.Fatalf("only %d agent(s) are bundled: %v", len(stacks), stacks)
	}

	for _, adapter := range stacks {
		agent, err := AgentFor(adapter)
		if err != nil {
			t.Errorf("AgentFor(%q): %v", adapter, err)
			continue
		}
		if len(agent.Source) == 0 {
			t.Errorf("the %s agent is empty", adapter)
		}
		if agent.FileName == "" || agent.Language == "" {
			t.Errorf("the %s agent is missing metadata: %+v", adapter, agent)
		}

		src := string(agent.Source)
		// The agent must be inert without the environment variable, so leaving
		// it installed on an unscanned machine does nothing.
		if !strings.Contains(src, "VIBEKILLER_SINK") {
			t.Errorf("the %s agent does not gate on VIBEKILLER_SINK", adapter)
		}
		// And it must refuse a non-loopback sink, so a stray variable cannot
		// turn it into an exfiltration path.
		if !strings.Contains(src, "127.0.0.1") {
			t.Errorf("the %s agent does not restrict the sink to loopback", adapter)
		}
	}
}

func TestAgentForUnknownStackExplainsItself(t *testing.T) {
	_, err := AgentFor("haskell")
	if err == nil {
		t.Fatal("expected an error for a stack with no bundled agent")
	}
	// The message should tell the operator what to do, not just refuse.
	if !strings.Contains(err.Error(), "sink accepts observations from any language") {
		t.Errorf("the error should point at the alternative: %v", err)
	}
}

// The agent is the operator's file. Overwriting one they may have edited would
// be the tool changing their application, which is the thing this design is
// built to avoid.
func TestAgentWriteRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()

	agent, err := AgentFor("node")
	if err != nil {
		t.Fatal(err)
	}

	path, err := agent.Write(dir)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != agent.FileName {
		t.Errorf("wrote to %q", path)
	}

	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(written) != string(agent.Source) {
		t.Error("the agent was altered on the way to disk")
	}

	// Pretend the operator edited it.
	if err := os.WriteFile(path, []byte("// my edits\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.Write(dir); err == nil {
		t.Error("Write overwrote an existing agent file")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != "// my edits\n" {
		t.Error("the operator's edits were overwritten")
	}
}

func TestAgentInstructionsNameTheSinkAndTheFile(t *testing.T) {
	agent, err := AgentFor("python")
	if err != nil {
		t.Fatal(err)
	}

	out := agent.Instructions("http://127.0.0.1:18080/observe", "/tmp/app/vibekiller_agent.py")
	for _, want := range []string{
		"http://127.0.0.1:18080/observe",
		"vibekiller_agent",
		"attach(app)",
		"never parameter values",
		"nothing to clean up",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the instructions do not mention %q:\n%s", want, out)
		}
	}
}

func TestSinkSatisfiesTheObserverInterface(t *testing.T) {
	var _ Observer = NewSink(0)
}
