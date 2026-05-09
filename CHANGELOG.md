# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-05-09

Initial public release. The crate has gone through an internal audit
cycle (AUDIT-2026-05) prior to this tag; the entries below describe
the shipping API surface, not deltas against a previous release.

### Added

- Wire-format types (`types`): `Manifest`, `ContentDocument`,
  `TransactionDocument`, 11 block kinds, inline elements, link targets
  (`same_site`, `entangled`, `citation`, `carrier`), form fields, state
  policy, state updates.
- JCS canonicalization with errata EID 6292 and EID 7920 applied
  (`canon`). Numeric domain restricted to `0..=i64::MAX` per §04;
  out-of-range values produce `CanonError::NumberOutOfRange`.
- Ed25519 signing and verification, SHA-256 hashing, BIP-39 PIP
  derivation, OS-level random generation via `getrandom` (`crypto`).
- Role-tagged signing keys: `PublisherSigningKey` signs manifests,
  `RuntimeSigningKey` signs content and transaction documents. The two
  types are not interconvertible at the public API; cross-role signing
  is rejected at compile time. `crypto::SigningKey` is crate-private.
  `verifying_key()` returns the role-correct pubkey type
  (`PublisherPubkey` / `RuntimePubkey`).
- Closed-schema validation pipeline Stages 2-5, signature verification
  (Stage 6), canary state and anti-downgrade (Stage 8), clock-skew
  tolerance, and origin binding (Stage 9) (`validation`).
- `manifest.updated` clock-skew enforcement (Stage 5,
  `E_SCHEMA_FIELD_SYNTAX` with
  `details.reason: "future_beyond_skew_tolerance"`) threaded through
  `parse_and_verify_manifest`, `parse_and_validate_manifest`,
  `validate_manifest`, and `build_manifest`, all of which take a
  `now: &EntangledTimestamp` parameter. The crate does not query the
  system clock itself; the caller passes a deterministic
  `EntangledTimestamp` in tests and an
  `OffsetDateTime::now_utc().into()` (or equivalent) in production.
- `canary.issued_at` clock-skew enforcement at Stage 8
  (`E_CANARY_INVALID`), exposed via `validate_canary_structure` and
  threaded through `verify_canary`. The two clock-skew sites are
  intentionally distinct: §10 routes them to different diagnostic codes
  and stages, and the implementation discriminates accordingly.
- High-level document builder and parser with type-state pipeline
  (`document`). `parse_and_verify_manifest` returns
  `ManifestSigVerified`; the caller traverses `verify_canary` (Stage 8)
  and `verify_origin` (Stage 9), or explicitly opts out via
  `skip_canary_check` / `skip_origin_check`. The wrappers are
  `#[must_use]`. Pre-chain field access is provided through the sealed
  `ManifestRead` trait (`publisher_pubkey`, `origin`, `state_policy`,
  `navigation`, `min_refresh_interval`, `updated`); the bare `Manifest`
  is reachable only via `into_parts()` after the full chain or after
  an explicit skip. There is no `manifest()` accessor.
- Standalone helpers `validate_canary_structure`,
  `compute_canary_state`, and `verify_origin_binding` for callers
  operating on manifests obtained from sources other than
  `parse_and_verify_manifest` (test harnesses, conformance corpus
  runners, mock servers).
- Client-side state store with consent model, mode preservation,
  per-publisher isolation, default 256 KiB storage cap (`state`).
  `state::build_submit_body` and `state::StateStore::get_request_state`
  take the current `&[StatePolicyEntry]` and exclude entries whose
  `(namespace, key)` is no longer declared, per §07.
- Tor v3 onion address parsing, checksum verification, fetch-origin
  binding (`tor`). `OnionAddress::verify_strict()` returns a
  `DecodedOnionAddress` whose `pubkey: OriginPubkey` is cryptographically
  verified per `rend-spec-v3.txt`. There is no unverified-pubkey
  accessor.
- Diagnostic schema: closed enum of v1.0 codes per §11, with structured
  `details` payloads (`field_path`, `reason`, etc.) where the spec
  prescribes them. `E_SCHEMA_DUPLICATE_ENTRY` covers within-array
  uniqueness violations (`state_policy` `(namespace, key)`,
  `submit_form` field `name`, `select.options` `value`, inline `marks`).
- Conformance harness driven by the upstream `samjanny/entangled`
  corpus (`tests/conformance`). The harness mocks the implementation
  clock to the corpus `clock_now` and runs every vector through the
  appropriate pipeline. The corpus is distributed separately; the
  harness skips with a notice when absent and honors
  `ENTANGLED_CORPUS_PATH` for an alternative location.
- ~290 unit/integration tests covering wire format, validation,
  canonicalization, signing, PIP round-trip, state management, Tor v3
  binding, and pipeline-stage / diagnostic-code precedence.

### Spec compatibility

- Code aligned to spec **v1.0-rc.10** (the most recent rc with
  diagnostic-affecting changes).
- Conformance corpus pinned in CI to **v1.0-rc.12**. rc.11 and rc.12
  are additive-only releases with no new diagnostic codes, no semantic
  changes, and no wire-format or signature-input changes; the
  rc.10-aligned implementation passes every rc.12 vector.

### Notes

- `forbid(unsafe_code)` enforced at the crate level. Direct dependencies
  that contain `unsafe` (sha2, sha3, ed25519-dalek with
  curve25519-dalek transitively) are RustCrypto/dalek-maintained.
- Test vectors verified against RFC 8032 §7.1, RFC 8785 §3.2.4, BIP-39
  reference data, and Tor v3 onion service
  `duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion`.
- MSRV: 1.88.

### Known limitations

- **Stage 3 not parser-enforced**: `validation::parse::parse_with_limits`
  constructs the full `serde_json::Value` before applying
  string/array/object/depth caps via `walk_limits`. Stage 2's 1 MiB
  byte cap bounds the worst-case pre-rejection allocation; replacing
  the post-parse walk with a streaming `Visitor` is tracked for a
  future release.
- **`E_SIG_MALFORMED` reported as Stage 5 schema error**: a `sig` field
  that is a string of the wrong length or non-base64url contents fails
  inside `serde_json::from_value` while deserializing the `Signature`
  newtype. The diagnostic is therefore reported as
  `E_SCHEMA_FIELD_LENGTH` / `E_SCHEMA_FIELD_SYNTAX` (Stage 5) rather
  than the `E_SIG_MALFORMED` (Stage 6) code reserved by §11. The
  pipeline still rejects the document with the correct severity and
  stage range; only the specific code differs.

[Unreleased]: https://github.com/samjanny/entangled-api/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/samjanny/entangled-api/releases/tag/v0.1.0
