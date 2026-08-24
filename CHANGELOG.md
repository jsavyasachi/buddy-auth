# Changelog

## [4.1.0] - 2026-08-24

### Fixed

- The async Ring handler now routes exceptions delivered via the `raise`
  callback, not just synchronously thrown exceptions, through the configured
  authorization backend, closing an authorization-bypass gap in async
  handlers.

### Added

- Centralized JWT/JWS/JWE verification-error isolation distinguishes backend
  verification failures from user `authfn` failures.
- Built-in OIDC provider integration on the JWKS backend, including issuer
  discovery and issuer, audience, nonce, and `azp` validation.
- RFC 6750-compliant, opt-in `WWW-Authenticate: Bearer` challenge responses
  with case-insensitive Bearer scheme parsing.
- A new API-key backend with header, cookie, and query placement plus
  caller-supplied lookup.
- Composable access-rule policies with named policies, explicit default-deny,
  and host, header, and query matchers.
- A generative/property-based test suite using test.check for malformed-input
  and algorithm-confusion coverage.
- Ring 1.12+/Reitit/Clojure-CLI usage examples in the user guide.

## [4.0.2] - 2026-08-17

### Fixed

- `jws-backend` no longer swallows exceptions thrown by the user's
  `authfn`. Only the `jwt/unsign` call is guarded, so a malformed or expired
  token still yields an unauthenticated request, but a bug in the identity
  transformation propagates instead of silently proceeding unauthenticated.

## [4.0.0] - 2026-07-21

### Changed

- Breaking for JWKS backend users: upgraded jose-clj to 0.5.0. Configure an expected JWT algorithm with `:options {:algs #{...}}`.
