# Changelog

## [Unreleased]

### Fixed

- `backends/basic` no longer treats a malformed HTTP Basic header as a
  credential. RFC 7617, section 2, defines the decoded payload as
  `user-id ":" password`; a payload with no colon - including anything that was
  not valid base64 - was handed to `authfn` as `{:username "..." :password nil}`,
  a footgun for any `authfn` that does not nil-check the password. It now parses
  to `nil` and the request is simply unauthenticated. An empty password
  (`user:`) is legal and still parses, as does a password containing colons.

### Security

- **Breaking.** `backends/oidc` now requires an expected audience. Previously a
  backend built without `:audience` (or `:options {:aud ...}`) performed no
  audience validation at all: the `azp` cross-check degenerated to a
  no-op, and no `:aud` claim check was configured downstream, so a token the
  issuer minted for a *different* relying party authenticated successfully.
  This is the confused-deputy case OIDC Core section 3.1.3.7 exists to prevent,
  and it is most severe on shared issuers such as Google, Auth0, and Azure AD.
  Construction without an audience now throws `IllegalArgumentException`.
  Pass the explicit `:audience :any` sentinel to opt out of the check.
- `backends/oidc` validates the configured audience against the token's `aud`
  claim inside the backend's own verifier, not only through the downstream
  `:aud` claim check, so a single-audience token can no longer bypass it.
- **Breaking.** `backends/oidc` now requires an `exp` claim on every token it
  accepts. A token carrying no `exp` at all previously authenticated and stayed
  valid forever, so a leaked one could never age out. OIDC Core section 2 makes
  `exp` REQUIRED on an ID token and RFC 9068 does the same for a JWT access
  token, so there is no opt-out. A caller's own `:options {:required [...]}`
  claims are kept alongside `exp` rather than replaced. `backends/jwks` is
  unchanged: plain JWT leaves `exp` optional.

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
