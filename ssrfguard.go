// Package ssrfguard helps prevent Server-Side Request Forgery (SSRF) in Go
// HTTP clients. It validates outbound URLs (scheme and host) and blocks requests
// to internal address ranges — loopback, private (RFC 1918 / RFC 4193),
// link-local (which includes the cloud metadata endpoint 169.254.169.254), and
// the unspecified address.
//
// Crucially, the protection can run at dial time via [Guard.Control], a
// [net.Dialer] Control hook that inspects the actual IP the connection is about
// to reach. This defeats DNS-rebinding attacks, where a hostname resolves to a
// harmless address during validation but to an internal one at connect time —
// something a parse-time-only check cannot catch.
//
// Typical use, as a guarded HTTP client:
//
//	client := ssrfguard.New().Client()
//	resp, err := client.Get(userSuppliedURL) // blocked if it dials an internal IP
//
// Or validate up front (for example, when accepting a URL into a config):
//
//	if err := ssrfguard.New().ValidateURL(userSuppliedURL); err != nil {
//		// reject
//	}
//
// For trusted environments, [WithAllowPrivate] disables internal-range blocking,
// and [WithSchemes] customizes the permitted URL schemes.
package ssrfguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// Errors returned by a Guard. Use [errors.Is] to test for them; ValidateURL and
// Control wrap them with additional context.
var (
	// ErrEmptyURL is returned by ValidateURL for an empty input.
	ErrEmptyURL = errors.New("ssrfguard: empty URL")
	// ErrInvalidURL is returned when a URL cannot be parsed.
	ErrInvalidURL = errors.New("ssrfguard: invalid URL")
	// ErrUnsupportedScheme is returned for a URL scheme not in the allowed set.
	ErrUnsupportedScheme = errors.New("ssrfguard: unsupported URL scheme")
	// ErrMissingHost is returned for a URL with no host.
	ErrMissingHost = errors.New("ssrfguard: URL has no host")
	// ErrBlockedAddress is returned when a destination resolves to, or is, a
	// blocked address (loopback, private, link-local, or unspecified).
	ErrBlockedAddress = errors.New("ssrfguard: destination address is blocked")
)

// Guard enforces an SSRF policy: which URL schemes are allowed and which
// destination IP addresses are blocked. Build one with [New]; the zero value is
// not usable. A Guard is immutable after construction and safe for concurrent
// use by multiple goroutines.
type Guard struct {
	schemes      map[string]struct{}
	allowPrivate bool
	resolver     *net.Resolver
}

// Option configures a [Guard] passed to [New].
type Option func(*Guard)

// WithSchemes sets the allowed URL schemes (compared case-insensitively). The
// default is "http" and "https". Passing no schemes leaves the default in place.
func WithSchemes(schemes ...string) Option {
	return func(g *Guard) {
		if len(schemes) == 0 {
			return
		}
		set := make(map[string]struct{}, len(schemes))
		for _, s := range schemes {
			set[strings.ToLower(s)] = struct{}{}
		}
		g.schemes = set
	}
}

// WithAllowPrivate controls whether destinations on internal ranges (loopback,
// private, link-local, unspecified) are permitted. The default is false, which
// blocks them. Set it to true only for trusted environments — for example,
// talking to services on a private network or localhost during development.
func WithAllowPrivate(allow bool) Option {
	return func(g *Guard) { g.allowPrivate = allow }
}

// WithResolver sets the [net.Resolver] used to resolve named hosts during URL
// validation. The default is [net.DefaultResolver]. A nil resolver is ignored,
// leaving the default in place.
//
// Supplying a custom resolver lets callers point DNS at a specific server, apply
// a [net.Resolver.Dial] hook (for example to enforce a timeout or to make tests
// hermetic by failing fast instead of touching the network), or otherwise
// control resolution. It composes with [Guard.ValidateURLContext], which carries
// a deadline into the lookup.
func WithResolver(r *net.Resolver) Option {
	return func(g *Guard) {
		if r != nil {
			g.resolver = r
		}
	}
}

// New returns a Guard with the given options. By default it allows the http and
// https schemes, blocks internal address ranges, and resolves named hosts with
// [net.DefaultResolver].
func New(opts ...Option) *Guard {
	g := &Guard{
		schemes:  map[string]struct{}{"http": {}, "https": {}},
		resolver: net.DefaultResolver,
	}
	for _, opt := range opts {
		opt(g)
	}
	return g
}

// IsBlockedIP reports whether ip is blocked by the policy. When AllowPrivate is
// set, nothing is blocked. Otherwise loopback, private (RFC 1918 / RFC 4193),
// link-local unicast and multicast (including the 169.254.169.254 cloud metadata
// endpoint), and the unspecified address are blocked. IPv4-mapped IPv6 addresses
// are classified by their embedded IPv4 address.
func (g *Guard) IsBlockedIP(ip net.IP) bool {
	if g.allowPrivate {
		return false
	}
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified()
}

// ValidateURL parses rawURL and checks it against the policy: it must be a
// parseable URL with an allowed scheme and a non-empty host. Unless AllowPrivate
// is set, a literal-IP host is checked directly, and a named host is resolved and
// rejected if any resolved address is blocked.
//
// A named host that cannot currently be resolved is allowed, so transient DNS
// failures don't reject otherwise-valid URLs; the dial-time [Guard.Control] hook
// still blocks it if it later resolves to an internal address.
//
// ValidateURL resolves named hosts with a background context, so the lookup is
// bounded only by the resolver's own settings. Use [Guard.ValidateURLContext] to
// impose a deadline or to make the lookup cancellable.
func (g *Guard) ValidateURL(rawURL string) error {
	return g.ValidateURLContext(context.Background(), rawURL)
}

// ValidateURLContext is [Guard.ValidateURL] with a caller-supplied context that
// governs DNS resolution of named hosts. Pass a context with a deadline to bound
// the lookup, which a parse-time-only check otherwise leaves at the mercy of the
// resolver — a slow or unreachable DNS server can stall an unbounded lookup.
//
// If ctx is canceled or its deadline elapses during resolution, it returns
// ctx.Err(). A genuine DNS resolution failure (an unresolvable name) is not an
// error: the host is allowed, leaving the dial-time [Guard.Control] hook to block
// it if it later resolves to an internal address.
func (g *Guard) ValidateURLContext(ctx context.Context, rawURL string) error {
	if rawURL == "" {
		return ErrEmptyURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidURL, err)
	}
	if _, ok := g.schemes[strings.ToLower(u.Scheme)]; !ok {
		return fmt.Errorf("%w: %q", ErrUnsupportedScheme, u.Scheme)
	}
	if u.Host == "" {
		return ErrMissingHost
	}
	if g.allowPrivate {
		return nil
	}
	return g.validateHost(ctx, u.Hostname())
}

// validateHost rejects hostnames that are, or resolve to, blocked addresses.
func (g *Guard) validateHost(ctx context.Context, hostname string) error {
	if hostname == "" {
		return ErrMissingHost
	}
	if isLocalhostName(hostname) {
		return fmt.Errorf("%w: %s", ErrBlockedAddress, hostname)
	}
	if ip := net.ParseIP(hostname); ip != nil {
		if g.IsBlockedIP(ip) {
			return fmt.Errorf("%w: %s", ErrBlockedAddress, ip)
		}
		return nil
	}
	resolver := g.resolver
	if resolver == nil {
		// Defensive: a Guard built directly (bypassing New) has no resolver.
		resolver = net.DefaultResolver
	}
	addrs, err := resolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		if ctx.Err() != nil {
			// The caller canceled or the deadline elapsed; surface it rather
			// than masquerading a context error as a successful validation.
			return ctx.Err()
		}
		// Genuinely unresolvable for now; let the dial-time guard catch it later.
		return nil
	}
	for _, addr := range addrs {
		if g.IsBlockedIP(addr.IP) {
			return fmt.Errorf("%w: %s resolves to %s", ErrBlockedAddress, hostname, addr.IP)
		}
	}
	return nil
}

// Control is a [net.Dialer] Control hook that rejects connections whose
// destination address is blocked by the policy. Because it runs after DNS
// resolution and just before connecting, it inspects the address actually being
// dialed and so blocks DNS-rebinding attacks. Plug it into a dialer:
//
//	dialer := &net.Dialer{Control: guard.Control}
func (g *Guard) Control(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("%w: cannot parse dial address %q", ErrBlockedAddress, address)
	}
	if g.IsBlockedIP(ip) {
		return fmt.Errorf("%w: %s", ErrBlockedAddress, ip)
	}
	return nil
}

// Dialer returns a *net.Dialer whose Control hook enforces the guard, with the
// same default Timeout and KeepAlive as [http.DefaultTransport]'s dialer.
func (g *Guard) Dialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   g.Control,
	}
}

// Transport returns a clone of base whose DialContext enforces the guard at dial
// time. If base is nil, a clone of [http.DefaultTransport] is used.
func (g *Guard) Transport(base *http.Transport) *http.Transport {
	if base == nil {
		base, _ = http.DefaultTransport.(*http.Transport)
	}
	t := base.Clone()
	t.DialContext = g.Dialer().DialContext
	return t
}

// Client returns an *http.Client whose transport enforces the guard at dial time.
func (g *Guard) Client() *http.Client {
	return &http.Client{Transport: g.Transport(nil)}
}

// isLocalhostName reports whether hostname is the localhost name or a subdomain
// of the reserved .localhost TLD (RFC 6761).
func isLocalhostName(hostname string) bool {
	hostname = strings.ToLower(hostname)
	return hostname == "localhost" || strings.HasSuffix(hostname, ".localhost")
}
