package scope

import (
	"errors"
	"strings"
	"testing"
)

func fixedResolver(m map[string][]string) Option {
	return WithResolver(func(host string) ([]string, error) {
		addrs, ok := m[host]
		if !ok {
			return nil, errors.New("no such host")
		}
		return addrs, nil
	})
}

func TestNewNormalizesTargets(t *testing.T) {
	g, err := New([]string{
		"http://localhost:3000",
		"HTTP://LOCALHOST:8080/some/path",
		"127.0.0.1:9000",
		"https://staging.example.com",
	}, WithAcknowledgement(true))
	if err != nil {
		t.Fatal(err)
	}

	want := []string{
		"http://127.0.0.1:9000",
		"http://localhost:3000",
		"http://localhost:8080",
		"https://staging.example.com:443",
	}
	got := g.Targets()
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("target %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestNewRejectsUnusableTargets(t *testing.T) {
	tests := []struct{ name, target string }{
		{"empty list entry", ""},
		{"unsupported scheme", "ftp://localhost"},
		{"file scheme", "file:///etc/passwd"},
		{"no host", "http://"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New([]string{tc.target}); err == nil {
				t.Errorf("accepted unusable target %q", tc.target)
			}
		})
	}

	if _, err := New(nil); err == nil {
		t.Error("accepted an empty target list")
	}
}

func TestAuthorizeTargetRefusesUndeclaredHosts(t *testing.T) {
	g, err := New([]string{"http://localhost:3000"}, WithAcknowledgement(true))
	if err != nil {
		t.Fatal(err)
	}

	if err := g.AuthorizeTarget("http://localhost:3000/api/orders"); err != nil {
		t.Errorf("declared target was refused: %v", err)
	}

	undeclared := []string{
		"http://localhost:3001",          // same host, different port
		"https://localhost:3000",         // same host:port, different scheme
		"http://127.0.0.1:3000",          // loopback, but not the declared name
		"http://example.com",             // someone else entirely
		"http://169.254.169.254/latest/", // link-local metadata address
	}
	for _, target := range undeclared {
		err := g.AuthorizeTarget(target)
		if err == nil {
			t.Errorf("authorized undeclared target %s", target)
			continue
		}
		var oos *ErrOutOfScope
		if !errors.As(err, &oos) {
			t.Errorf("target %s refused with %T, want ErrOutOfScope", target, err)
		}
	}
}

func TestAuthorizeTargetRequiresAcknowledgement(t *testing.T) {
	g, err := New([]string{"http://localhost:3000"})
	if err != nil {
		t.Fatal(err)
	}

	err = g.AuthorizeTarget("http://localhost:3000")
	var notAck *ErrNotAcknowledged
	if !errors.As(err, &notAck) {
		t.Fatalf("got %v, want ErrNotAcknowledged", err)
	}
	if !strings.Contains(err.Error(), "--i-own-this-target") {
		t.Errorf("the error should name the flag that unblocks it: %v", err)
	}

	// InScope answers the narrower question and ignores the acknowledgement,
	// because redirect checks need it before a run is under way.
	if !g.InScope("http://localhost:3000/x") {
		t.Error("InScope should be true for a declared origin regardless of acknowledgement")
	}
}

func TestAuthorizeDialRefusesUndeclaredHostPort(t *testing.T) {
	g, err := New([]string{"http://localhost:3000"}, WithAcknowledgement(true),
		fixedResolver(map[string][]string{"localhost": {"127.0.0.1"}}))
	if err != nil {
		t.Fatal(err)
	}

	if err := g.AuthorizeDial("localhost:3000", "127.0.0.1:3000"); err != nil {
		t.Errorf("declared host:port was refused: %v", err)
	}
	if err := g.AuthorizeDial("localhost:9999", "127.0.0.1:9999"); err == nil {
		t.Error("authorized a dial to an undeclared port")
	}
}

// The reason the dial-time check exists: a declared name that starts out
// pointing at the operator's own machine must not be able to send traffic
// somewhere else later in the run.
func TestAuthorizeDialPinsResolvedAddresses(t *testing.T) {
	resolved := map[string][]string{"app.test": {"127.0.0.1"}}
	g, err := New([]string{"http://app.test:3000"}, WithAcknowledgement(true), fixedResolver(resolved))
	if err != nil {
		t.Fatal(err)
	}

	if err := g.AuthorizeDial("app.test:3000", "127.0.0.1:3000"); err != nil {
		t.Fatalf("first dial to the pinned address was refused: %v", err)
	}

	// The name now answers with a different address.
	resolved["app.test"] = []string{"203.0.113.10"}
	err = g.AuthorizeDial("app.test:3000", "203.0.113.10:3000")
	if err == nil {
		t.Fatal("a dial to a re-pointed name was authorized")
	}
	if !strings.Contains(err.Error(), "re-pointed") {
		t.Errorf("error should explain the pinning failure, got: %v", err)
	}
}

func TestAuthorizeDialChecksLiteralIPsDirectly(t *testing.T) {
	g, err := New([]string{"http://127.0.0.1:3000"}, WithAcknowledgement(true))
	if err != nil {
		t.Fatal(err)
	}

	if err := g.AuthorizeDial("127.0.0.1:3000", "127.0.0.1:3000"); err != nil {
		t.Errorf("literal declared IP was refused: %v", err)
	}
	if err := g.AuthorizeDial("127.0.0.1:3000", "10.1.2.3:3000"); err == nil {
		t.Error("a declared literal IP accepted a dial to a different address")
	}
	if err := g.AuthorizeDial("127.0.0.1:3000", "not-an-ip"); err == nil {
		t.Error("accepted a dial to something that is not an address")
	}
}

func TestIsLocal(t *testing.T) {
	local := []string{"localhost", "app.localhost", "127.0.0.1", "::1", "10.0.0.5", "192.168.1.10", "172.16.0.1", "169.254.1.1"}
	for _, h := range local {
		if !IsLocal(h) {
			t.Errorf("IsLocal(%q) = false, want true", h)
		}
	}

	public := []string{"example.com", "203.0.113.10", "8.8.8.8", "staging.example.com"}
	for _, h := range public {
		if IsLocal(h) {
			t.Errorf("IsLocal(%q) = true, want false", h)
		}
	}
}

func TestPublicTargetsAreSurfaced(t *testing.T) {
	g, err := New([]string{
		"http://localhost:3000",
		"http://192.168.1.50:8080",
		"https://staging.example.com",
	}, WithAcknowledgement(true))
	if err != nil {
		t.Fatal(err)
	}

	pub := g.PublicTargets()
	if len(pub) != 1 || pub[0] != "https://staging.example.com:443" {
		t.Errorf("PublicTargets() = %v, want just the public staging host", pub)
	}
}

func TestDefaultTargetsAreLocalOnly(t *testing.T) {
	g, err := New(DefaultTargets(), WithAcknowledgement(true))
	if err != nil {
		t.Fatal(err)
	}
	if pub := g.PublicTargets(); len(pub) != 0 {
		t.Errorf("the default scope reaches off-machine targets: %v", pub)
	}
}
