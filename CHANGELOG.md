# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `Guard.ValidateURLContext` — `ValidateURL` with a caller-supplied context that
  governs DNS resolution, so a slow or unreachable resolver can't stall an
  unbounded lookup. `ValidateURL` now delegates to it with `context.Background()`.
- `WithResolver` — sets the `net.Resolver` used to resolve named hosts (defaults
  to `net.DefaultResolver`). Lets callers point DNS at a specific server, apply a
  `Dial` hook to bound or cancel lookups, or make tests hermetic by failing fast
  instead of touching the network.

## [0.1.0] - 2026-06-07

Initial release.

### Added
- `Guard` with `New(...Option)`, configurable via `WithSchemes` and
  `WithAllowPrivate`.
- `Guard.ValidateURL` — up-front scheme/host validation with literal-IP and
  DNS-resolution checks against blocked ranges.
- `Guard.IsBlockedIP` — classifies loopback, private (RFC 1918 / RFC 4193),
  link-local (including the `169.254.169.254` cloud metadata endpoint), and the
  unspecified address.
- `Guard.Control` — a `net.Dialer` Control hook that blocks at dial time,
  defeating DNS-rebinding.
- `Guard.Dialer`, `Guard.Transport`, and `Guard.Client` helpers for guarded
  outbound HTTP.

[0.1.0]: https://github.com/richardwooding/ssrfguard/releases/tag/v0.1.0
