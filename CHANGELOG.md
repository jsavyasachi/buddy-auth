# Changelog

## [Unreleased]

### Changed

- Breaking for JWKS backend users: upgraded jose-clj to 0.5.0. Configure an expected JWT algorithm with `:options {:algs #{...}}`.
