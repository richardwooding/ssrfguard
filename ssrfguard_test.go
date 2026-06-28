package ssrfguard

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestValidateURL(t *testing.T) {
	g := New()
	cases := []struct {
		name    string
		url     string
		wantErr error
	}{
		{"public literal IP", "https://8.8.8.8/path", nil},
		{"empty", "", ErrEmptyURL},
		{"bad scheme ftp", "ftp://8.8.8.8", ErrUnsupportedScheme},
		{"bad scheme file", "file:///etc/passwd", ErrUnsupportedScheme},
		{"no host", "https://", ErrMissingHost},
		{"loopback v4", "http://127.0.0.1", ErrBlockedAddress},
		{"loopback v4 in 127/8", "http://127.0.0.5:8080", ErrBlockedAddress},
		{"loopback v6", "http://[::1]/x", ErrBlockedAddress},
		{"private 10/8", "http://10.0.0.1", ErrBlockedAddress},
		{"private 172.16/12", "http://172.16.0.1", ErrBlockedAddress},
		{"private 192.168/16", "http://192.168.1.1", ErrBlockedAddress},
		{"cloud metadata 169.254.169.254", "http://169.254.169.254/latest/meta-data/", ErrBlockedAddress},
		{"unspecified", "http://0.0.0.0", ErrBlockedAddress},
		{"localhost name", "http://localhost:3000", ErrBlockedAddress},
		{"sub.localhost name", "http://db.localhost", ErrBlockedAddress},
		{"ipv4-mapped loopback", "http://[::ffff:127.0.0.1]", ErrBlockedAddress},
		{"scheme case-insensitive", "HTTPS://8.8.8.8", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := g.ValidateURL(tc.url)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("ValidateURL(%q) = %v, want nil", tc.url, err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ValidateURL(%q) = %v, want %v", tc.url, err, tc.wantErr)
			}
		})
	}
}

func TestValidateURLAllowPrivate(t *testing.T) {
	g := New(WithAllowPrivate(true))
	for _, u := range []string{"http://127.0.0.1", "http://10.0.0.1", "http://169.254.169.254", "https://example.com"} {
		if err := g.ValidateURL(u); err != nil {
			t.Errorf("AllowPrivate ValidateURL(%q) = %v, want nil", u, err)
		}
	}
	// Scheme is still enforced even when private addresses are allowed.
	if err := g.ValidateURL("ftp://127.0.0.1"); !errors.Is(err, ErrUnsupportedScheme) {
		t.Errorf("ftp scheme err = %v, want ErrUnsupportedScheme", err)
	}
}

func TestValidateURLUnresolvableIsAllowed(t *testing.T) {
	// A name in the reserved .invalid TLD never resolves; it should be allowed
	// at validation time and left for the dial-time guard.
	if err := New().ValidateURL("https://nonexistent.invalid/feed"); err != nil {
		t.Fatalf("ValidateURL(unresolvable) = %v, want nil", err)
	}
}

func TestWithResolverIsUsed(t *testing.T) {
	// A custom resolver that fails fast without touching the network. The lookup
	// erroring means the host is treated as unresolvable, hence allowed.
	var dialed atomic.Bool
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			dialed.Store(true)
			return nil, errors.New("no network in test")
		},
	}
	if err := New(WithResolver(r)).ValidateURL("https://example.com/feed"); err != nil {
		t.Fatalf("ValidateURL with fail-fast resolver = %v, want nil", err)
	}
	if !dialed.Load() {
		t.Fatal("the custom resolver was not used")
	}
}

func TestWithResolverNilIgnored(t *testing.T) {
	g := New(WithResolver(nil))
	if g.resolver != net.DefaultResolver {
		t.Fatal("WithResolver(nil) should leave the default resolver in place")
	}
}

func TestValidateURLContextHonorsDeadline(t *testing.T) {
	// A resolver that blocks until its lookup context is canceled, proving that
	// the context passed to ValidateURLContext propagates into DNS resolution.
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- New(WithResolver(r)).ValidateURLContext(ctx, "https://example.com/feed") }()

	select {
	case err := <-done:
		// A timed-out lookup is treated as unresolvable, hence allowed.
		if err != nil {
			t.Fatalf("ValidateURLContext = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ValidateURLContext did not honor the context deadline")
	}
}

func TestWithSchemes(t *testing.T) {
	g := New(WithSchemes("https"))
	if err := g.ValidateURL("http://8.8.8.8"); !errors.Is(err, ErrUnsupportedScheme) {
		t.Errorf("http should be rejected when only https allowed, got %v", err)
	}
	if err := g.ValidateURL("https://8.8.8.8"); err != nil {
		t.Errorf("https should be allowed, got %v", err)
	}
}

func TestIsBlockedIP(t *testing.T) {
	g := New()
	blocked := []string{
		"127.0.0.1", "::1", "10.1.2.3", "172.16.0.1", "172.31.255.255",
		"192.168.0.1", "169.254.169.254", "0.0.0.0", "fe80::1", "fc00::1", "fd12::34",
	}
	for _, s := range blocked {
		if !g.IsBlockedIP(net.ParseIP(s)) {
			t.Errorf("IsBlockedIP(%s) = false, want true", s)
		}
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "172.32.0.1", "172.15.0.1", "2606:4700:4700::1111"}
	for _, s := range allowed {
		if g.IsBlockedIP(net.ParseIP(s)) {
			t.Errorf("IsBlockedIP(%s) = true, want false", s)
		}
	}
}

func TestIsBlockedIPAllowPrivate(t *testing.T) {
	g := New(WithAllowPrivate(true))
	if g.IsBlockedIP(net.ParseIP("127.0.0.1")) {
		t.Error("with AllowPrivate, 127.0.0.1 should not be blocked")
	}
}

func TestControl(t *testing.T) {
	g := New()
	if err := g.Control("tcp", "8.8.8.8:443", nil); err != nil {
		t.Errorf("Control(public) = %v, want nil", err)
	}
	for _, addr := range []string{"127.0.0.1:80", "169.254.169.254:80", "10.0.0.1:443", "[::1]:80"} {
		if err := g.Control("tcp", addr, nil); !errors.Is(err, ErrBlockedAddress) {
			t.Errorf("Control(%q) = %v, want ErrBlockedAddress", addr, err)
		}
	}
	// AllowPrivate permits internal dials.
	if err := New(WithAllowPrivate(true)).Control("tcp", "127.0.0.1:80", nil); err != nil {
		t.Errorf("Control(loopback) with AllowPrivate = %v, want nil", err)
	}
}

// TestClientBlocksLoopbackAtDial is the end-to-end check: httptest listens on a
// loopback address, so a guarded client must refuse to connect to it.
func TestClientBlocksLoopbackAtDial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := New().Client().Get(srv.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatalf("expected guarded client to block loopback %s", srv.URL)
	}
	if !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("err = %v, want ErrBlockedAddress", err)
	}

	// With AllowPrivate, the same request succeeds.
	resp, err = New(WithAllowPrivate(true)).Client().Get(srv.URL)
	if err != nil {
		t.Fatalf("AllowPrivate client.Get(%s) = %v, want success", srv.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestTransportClonesBase(t *testing.T) {
	base := &http.Transport{MaxIdleConns: 77, MaxConnsPerHost: 9}
	got := New().Transport(base)
	if got == base {
		t.Fatal("Transport should clone, not mutate, the base transport")
	}
	if got.MaxIdleConns != 77 || got.MaxConnsPerHost != 9 {
		t.Fatalf("clone lost base settings: MaxIdleConns=%d MaxConnsPerHost=%d", got.MaxIdleConns, got.MaxConnsPerHost)
	}
	if got.DialContext == nil {
		t.Fatal("Transport should set a guarded DialContext")
	}
	if base.DialContext != nil {
		t.Fatal("base transport must not be mutated")
	}
}
