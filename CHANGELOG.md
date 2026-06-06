# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
