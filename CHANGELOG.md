# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-05-07

### Fixed (pre-release audit, AUDIT-2026-05)

- **Transaction signing/verification key role**: `sign_transaction_payload` and `verify_transaction_payload` now sign with `K_runtime` and verify against `&RuntimePubkey`, matching §05's "transactions are signed by `K_runtime`". The previous version mistakenly took `&OriginPubkey`, which would have allowed transactions signed by the wrong key role to verify. **Breaking change** for anyone calling these helpers directly. (AUDIT-2026-05 finding #1.)
- **Submit-body request-state filtering**: `state::build_submit_body` and `state::StateStore::get_request_state` now require `&[StatePolicyEntry]` (the *current* policy) and exclude entries whose `(namespace, key)` is no longer declared, per §07: "state entries for `(namespace, key)` combinations no longer declared in the new policy ... MUST NOT be included in submit requests". The previous version transmitted such entries as long as they had not yet expired, leaking client-only data after a policy contraction. **Breaking change** to both function signatures. (AUDIT-2026-05 finding #2.)
- **`manifest.updated` clock-skew enforcement in the public pipeline**: `parse_and_verify_manifest`, `parse_and_validate_manifest`, `validate_manifest`, `validate_manifest_fields` (crate-internal), and `build_manifest` now take an additional `now: &EntangledTimestamp` parameter and apply the §06 / §10 300-second clock-skew check on `manifest.updated` as part of Stage 5. The previous version exposed the helper `validation::check_manifest_clock_skew` but did not invoke it from the public pipeline, leaving manifests dated arbitrarily in the future erroneously accepted by `parse_and_verify_manifest`. **Breaking change** to all the listed signatures; pass a deterministic `EntangledTimestamp` in tests, `OffsetDateTime::now_utc().into()` (or equivalent) in production. The crate deliberately does not query the system clock itself. (AUDIT-2026-05 follow-up finding #1.)
- **Empty content `blocks` array**: `validate_content_fields` now rejects content documents with an empty `blocks` array with `E_SCHEMA_REQUIRED_FIELD`, per §02 ("`blocks` MUST contain at least one block"). (AUDIT-2026-05 finding #5.)
- **Per-publisher storage cap default**: raised from 64 KiB to 256 KiB so the default satisfies §07's lower bound (`sum(max_size)` across the policy worst case = 128 KiB) with comfortable headroom for namespace/key overhead. Callers that need a smaller cap construct via `StateStore::with_cap`. (AUDIT-2026-05 finding #3.)
- **Empty optional strings rejected**: `canary.freshness_proof`, `image.caption`, and `note.title` now reject `""` with `E_SCHEMA_FIELD_SYNTAX`. The spec text for each forbids an empty string as a substitute for an omitted optional. (AUDIT-2026-05 finding #6.)
- **Citation URL character set tightened to RFC 3986**: `validate_citation_url` now permits only unreserved / gen-delims / sub-delims / `%` bytes. Previously the validator accepted any printable ASCII byte (`0x21..=0x7E`), which let through `<`, `>`, `"`, `\`, `^`, `` ` ``, `{`, `|`, `}` — none of which are valid URI characters per RFC 3986 §2.2/§2.3. (AUDIT-2026-05 finding #9.)
- **Canonicalizer numeric domain restricted to `0..=i64::MAX`**: `canon::canonicalize` now rejects negative integers and unsigned values exceeding `i64::MAX` with `CanonError::NumberOutOfRange`, matching §04 ("All numeric fields in Entangled are non-negative integers ... within the range expressible as a 64-bit signed integer"). The previous behavior accepted any `i64` or `u64`, which let through values outside the Entangled domain when the canonicalizer was used directly with arbitrary `serde_json::Value` input. (AUDIT-2026-05 finding #10.)

### Documentation

- `document::parser` module-level doc now explicitly enumerates pipeline coverage (Stages 2-6) and the caller's responsibilities for Stages 7-10 (trust state, canary state, transport binding, rendering). The asymmetry between Stage 5 (`manifest.updated` clock-skew, integrated) and Stage 8 (`canary.issued_at` clock-skew, exposed via `validate_canary_structure`) is documented as a deliberate split: Stage 8 depends on the canary state machine and anti-downgrade history, neither of which are closed-schema concerns.

### Known deviations (accepted for v0.1.x)

- **Stage 3 not parser-enforced**: `validation::parse::parse_with_limits` constructs the full `serde_json::Value` before applying string/array/object/depth caps via `walk_limits`. Stage 2's 1 MiB byte cap bounds the worst-case pre-rejection allocation; replacing the post-parse walk with a streaming `Visitor` is tracked for a future release. (AUDIT-2026-05 finding #7.)
- **`E_SIG_MALFORMED` reported as Stage 5 schema error**: a `sig` field that is a string of the wrong length or non-base64url contents fails inside `serde_json::from_value` while deserializing the `Signature` newtype. The diagnostic is therefore reported as `E_SCHEMA_FIELD_LENGTH` / `E_SCHEMA_FIELD_SYNTAX` (Stage 5) rather than the `E_SIG_MALFORMED` (Stage 6) code reserved by §11. The pipeline still rejects the document with the correct severity and stage range; only the specific code differs. (AUDIT-2026-05 finding #8.)

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

[Unreleased]: https://github.com/samjanny/entangled-api/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/samjanny/entangled-api/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/samjanny/entangled-api/releases/tag/v0.1.0
