# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-05-07

### Added

- Initial implementation of Entangled v1.0 protocol library.
- Wire-format types (`types`): Manifest, ContentDocument, TransactionDocument, 11 block kinds, inline elements, link targets, form fields, state policy, state updates.
- JCS canonicalization with errata EID 6292 and EID 7920 applied (`canon`).
- Ed25519 signing and verification, SHA-256 hashing, BIP-39 PIP derivation, OS-level random generation via `getrandom` (`crypto`).
- Closed-schema validation pipeline Stage 2-5, canary state and anti-downgrade (Stage 8), clock-skew tolerance (`validation`).
- High-level document builder and parser (`document`).
- Client-side state store with consent model, mode preservation, per-publisher isolation, storage cap (`state`).
- Tor v3 onion address parsing, checksum verification, fetch-origin binding (`tor`).
- 286+ tests covering wire format, validation, canonicalization, signing, PIP round-trip, state management, Tor v3 binding.

### Notes

- `forbid(unsafe_code)` enforced at the crate level. Direct dependencies that contain `unsafe` (sha2, sha3, ed25519-dalek with curve25519-dalek transitively) are RustCrypto/dalek-maintained.
- Test vectors verified against RFC 8032 §7.1, RFC 8785 §3.2.4, BIP-39 reference data, and Tor v3 onion service `duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion`.

[Unreleased]: https://github.com/samjanny/entangled-api/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/samjanny/entangled-api/releases/tag/v0.1.0
