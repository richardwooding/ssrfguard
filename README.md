# ssrfguard

[![Go Reference](https://pkg.go.dev/badge/github.com/richardwooding/ssrfguard.svg)](https://pkg.go.dev/github.com/richardwooding/ssrfguard)
[![Go](https://github.com/richardwooding/ssrfguard/actions/workflows/go.yml/badge.svg)](https://github.com/richardwooding/ssrfguard/actions/workflows/go.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Website:** [richardwooding.github.io/ssrfguard](https://richardwooding.github.io/ssrfguard/)

A small, dependency-free Go library that helps prevent **Server-Side Request
Forgery (SSRF)**. It validates outbound URLs and blocks requests to internal
address ranges — and it can enforce the block **at dial time**, which is what
makes it robust against DNS rebinding.

```go
client := ssrfguard.New().Client()
resp, err := client.Get(userSuppliedURL) // refused if it dials an internal IP
```

## Why dial-time matters

Most SSRF checks validate the URL up front: resolve the host, see a public IP,
allow it. But an attacker who controls DNS can return a **public IP at
validation time and an internal IP a moment later at connect time** (DNS
rebinding) — bypassing the check entirely.

`ssrfguard` plugs into [`net.Dialer.Control`](https://pkg.go.dev/net#Dialer),
which runs *after* DNS resolution and *just before* the socket connects, so it
inspects the address the connection will actually reach. The guarded
`http.Client` is safe even when the hostname's resolution changes between
validation and connection.

It blocks (unless you opt out):

- **Loopback** — `127.0.0.0/8`, `::1`
- **Private** — RFC 1918 (`10/8`, `172.16/12`, `192.168/16`) and RFC 4193 ULA (`fc00::/7`)
- **Link-local** — `169.254.0.0/16` (including the cloud metadata endpoint
  `169.254.169.254`) and `fe80::/10`
- **Unspecified** — `0.0.0.0`, `::`

IPv4-mapped IPv6 (e.g. `::ffff:127.0.0.1`) is classified by its embedded IPv4
address, and only `http`/`https` schemes are allowed by default.

## Install

```sh
go get github.com/richardwooding/ssrfguard
```

Requires Go 1.26+. No third-party dependencies.

## Usage

### Guarded HTTP client (recommended)

```go
client := ssrfguard.New().Client()
resp, err := client.Get(untrustedURL)
if errors.Is(err, ssrfguard.ErrBlockedAddress) {
    // refused to connect to an internal address
}
```

Compose over your own tuned transport — its settings are preserved, only the
dialer is wrapped:

```go
base := &http.Transport{MaxConnsPerHost: 10 /* TLS, proxy, pooling, … */}
client := &http.Client{Transport: ssrfguard.New().Transport(base)}
```

Or attach the guard to a dialer you already build:

```go
dialer := &net.Dialer{Control: ssrfguard.New().Control}
```

### Up-front validation

When you accept a URL into config or a database (and the request happens later),
validate it eagerly too:

```go
g := ssrfguard.New()
if err := g.ValidateURL(userSuppliedURL); err != nil {
    return fmt.Errorf("rejected: %w", err)
}
```

`ValidateURL` checks the scheme and host, and — for a literal IP or a resolvable
name — that it isn't an internal address. A name that can't currently be resolved
is allowed through; the dial-time guard remains the backstop.

`ValidateURL` resolves names with a background context, so the lookup is bounded
only by the resolver. To impose a deadline — important when validating
attacker-supplied URLs, since a slow DNS server would otherwise stall the call —
use `ValidateURLContext`:

```go
ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
defer cancel()
if err := g.ValidateURLContext(ctx, userSuppliedURL); err != nil {
    return fmt.Errorf("rejected: %w", err)
}
```

### Options

```go
// Only allow https.
ssrfguard.New(ssrfguard.WithSchemes("https"))

// Permit internal ranges (trusted/dev environments).
ssrfguard.New(ssrfguard.WithAllowPrivate(true))

// Resolve names with a custom resolver — point DNS at a specific server, bound
// lookups with a Dial hook, or make tests hermetic. Defaults to net.DefaultResolver.
ssrfguard.New(ssrfguard.WithResolver(myResolver))
```

## Comparison

- [`doyensec/safeurl`](https://github.com/doyensec/safeurl) — a fuller-featured
  guarded client (allow/deny lists). `ssrfguard` is smaller and composes as a
  plain dialer/transport primitive with zero dependencies.
- Hand-rolled "resolve then check the IP" snippets are common but validate at
  parse time only, leaving the DNS-rebinding window open. `ssrfguard` closes it.

## Security note

SSRF defense is layered. `ssrfguard` covers URL scheme/host validation and
internal-range blocking at dial time, but it does not (yet) restrict redirects,
add allowlist-only modes, or inspect request bodies. Pair it with redirect
policies (`http.Client.CheckRedirect`) and least-privilege networking as needed.
Reports and contributions welcome.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE)
