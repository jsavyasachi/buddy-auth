# Changelog

## [4.0.2] - 2026-08-17

### Fixed

- `jws-backend` no longer swallows exceptions thrown by the user's
  `authfn`. Only the `jwt/unsign` call is guarded, so a malformed or expired
  token still yields an unauthenticated request, but a bug in the identity
  transformation propagates instead of silently proceeding unauthenticated.

## [4.0.0] - 2026-07-21

### Changed

- Breaking for JWKS backend users: upgraded jose-clj to 0.5.0. Configure an expected JWT algorithm with `:options {:algs #{...}}`.
