# Changelog
All notable changes to **rc5-course** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

## [0.2.0] – 2025-05-03
### Added
- **CLI** moved to `src/bin/rc5-cbc.rs`; helper functions now accept `&[u8]` and trim zero-padding.
- Integration & property tests:
  - `tests/block.rs` – Rivest vector #2 (RC5-32/12/16)
  - `tests/roundtrip.rs` – proptest random block round-trips
  - `tests/cli.rs` – end-to-end file encrypt/decrypt via CLI
- GitHub Actions workflow: `fmt`, `clippy -D warnings`, and `cargo test`.
- CI status badge in README.

### Changed
- Library API: `encrypt`, `decrypt`, `expand_key` now take `&[u8]` instead of `Vec<u8>`.
- Re-exported `rc5` module via new `src/lib.rs`.
- README rewritten with build instructions and usage.

### Removed
- Old `examples/rc5cli.rs` duplicate build target (now a single binary).

---

[Unreleased]: https://github.com/JohnBasrai/rc5-cbc/compare/v0.2.0...HEAD
