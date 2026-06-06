package ssrfguard

import (
	"net"
	"net/url"
	"testing"
)

// FuzzValidateURL checks that ValidateURL never panics on arbitrary input and
// that it never accepts a URL whose host is a literal IP the policy blocks.
func FuzzValidateURL(f *testing.F) {
	seeds := []string{
		"",
		"https://8.8.8.8",
		"http://127.0.0.1",
		"http://[::1]",
		"http://169.254.169.254/latest/meta-data/",
		"http://localhost",
		"ftp://example.com",
		"file:///etc/passwd",
		"http://0.0.0.0",
		// Classic SSRF obfuscations (the dial-time guard is the real backstop).
		"http://2130706433",       // decimal 127.0.0.1
		"http://0177.0.0.1",       // octal
		"http://0x7f.0.0.1",       // hex
		"http://127.0.0.1.nip.io", // DNS-based loopback
		"http://[::ffff:127.0.0.1]",
		"http://user:pass@127.0.0.1@evil.com/",
		"http://example.com\x00.internal/",
		"https://例え.テスト",
		"http://%6c%6f%63%61%6c%68%6f%73%74", // encoded "localhost"
	}
	for _, s := range seeds {
		f.Add(s)
	}

	g := New()
	f.Fuzz(func(t *testing.T, raw string) {
		err := g.ValidateURL(raw) // must not panic

		if err == nil {
			if u, perr := url.Parse(raw); perr == nil {
				if ip := net.ParseIP(u.Hostname()); ip != nil && g.IsBlockedIP(ip) {
					t.Fatalf("ValidateURL accepted %q whose literal IP %s is blocked", raw, ip)
				}
			}
		}

		// Control must not panic on arbitrary input either.
		_ = g.Control("tcp", raw, nil)
	})
}
