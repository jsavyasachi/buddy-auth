# Changelog

## [4.0.0] - 2026-07-21

### Changed

- Breaking for JWKS backend users: upgraded jose-clj to 0.5.0. Configure an expected JWT algorithm with `:options {:algs #{...}}`.
