# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added (spec v1.0-rc.14 alignment)

- **§06 `origin.not_after`**: optional `Option<EntangledTimestamp>` field
  on `Origin` (and therefore on `Manifest.origin` /
  `UnsignedManifest.origin`). Absent in the closed-schema steady state;
  encoded by omission per §04 no-`null` discipline. Stage 5 enforces the
  two §06 `MUST` constraints — `not_after` strictly later than
  `canary.issued_at`, and within a 5-year horizon
  (`ORIGIN_NOT_AFTER_MAX_HORIZON_SECS = 5 * 365 * 86_400`) — and reports
  violations as `E_ORIGIN_INVALID` with `details.reason` in the §11
  vocabulary (`not_after_not_after_issued_at`, `not_after_beyond_5y`).
  Public helper `validation::validate_origin_not_after`.
- **Stage 9 `origin.not_after` expiry check (§10)**:
  `validation::check_origin_not_after` rejects a manifest whose
  declared `not_after` is past `now` beyond the §10 clock-skew
  tolerance (300 s in the publisher's favour) with `E_ORIGIN_EXPIRED`.
  Callers run it after `tor::verify_origin_binding` has cleared
  carrier origin binding; the helper does not duplicate the Stage 5
  semantic checks.
- **Stage 9 migration chain-cycle guard (§10)**:
  `validation::check_migration_chain_cycle` takes the per-flow
  `visited_origins: HashSet<OnionAddress>` and the announcing
  manifest's `MigrationPointer`; it rejects revisited successor
  addresses as `E_MIGRATION_INVALID` with `details.reason =
  "chain_cycle"` and inserts the successor on acceptance so the caller
  can thread the set through the next hop. The complementary
  automatic chain-depth limit (one hop without re-prompting; high-
  threat mode) is a client-chrome concern and remains the caller's
  responsibility.
- **§11 diagnostic codes**: `E_ORIGIN_EXPIRED` and `E_ORIGIN_INVALID`
  added to `DiagnosticCode`, both cataloged at Stage 9 alongside the
  rest of the Binding family. `E_MIGRATION_INVALID` now additionally
  covers `details.reason = "chain_cycle"` (visited-origin cycle) and
  `details.reason = "successor_origin_not_after_present"` (a rc.14
  successor-shape violation: the successor pointer schema does not
  carry `not_after`; the successor manifest declares its own).
- **CI conformance corpus pinned to `v1.0-rc.14`** in
  `.github/workflows/ci.yml`. The local `docs-spec/` mirror is at
  rc.14; the rc.14 schema and helper additions are all additive
  (existing 32 corpus vectors validate identically byte-for-byte under
  rc.14 since they omit `origin.not_after` and carry no migration
  cycle), keeping the 32/32 green count.

### Added (spec v1.0-rc.13 alignment)

- **§04 Unicode NFC for user-visible strings**: schema validation now
  rejects non-NFC values in `canary.statement`, `meta.title`,
  `navigation[].label`, `state_policy[].purpose`, every inline `value`
  (Text and Link), `code_block.content`, `image.alt`, `image.caption`,
  `note.title`, `submit_form` field labels, `submit_form` select-option
  labels, and `submit_form.submit_label` with `E_SCHEMA_FIELD_SYNTAX`
  carrying `details.field_path` and `reason: "non_nfc_string"`. The
  crate does not silently re-normalize: re-normalization would alter
  the JCS canonical bytes and break the publisher's signature. New
  `crate::validation::strings::check_nfc` helper. New dependency on
  `unicode-normalization`.
- **§06 `migration_pointer`**: optional top-level manifest field
  (`Option<MigrationPointer>` on `Manifest` and `UnsignedManifest`)
  carrying `successor_origin` and `announced_at`. Stage 5 schema
  validation enforces the three §06 structural rules with
  `E_MIGRATION_INVALID` (self-pointing address, carrier mismatch,
  `announced_at` after `updated`). Public function
  `validation::validate_migration_pointer`.
- **`verify_migration_announcement`** (§10 Stage 9): publisher-identity
  continuity check across an announcing manifest and the successor it
  declares. Mismatch emits `E_MIGRATION_MISMATCH` with `details`
  carrying both pubkeys and the announced successor address. Lives at
  `validation::verify_migration_announcement`.
- **§11 diagnostic codes**: `E_MIGRATION_MISMATCH` and
  `E_MIGRATION_INVALID` added to `DiagnosticCode` at Stage 9.

### Changed (spec v1.0-rc.13 alignment)

- **§08 `E_CANARY_CONFLICT` is now a fault condition**, not a
  recoverable transient error. Documented on `check_canary_conflict`:
  the client MUST NOT pick a deterministic winner by lexicographic
  comparison or any other tiebreaker over manifest content (gameable
  by an attacker holding `K_publisher_priv`). The retained
  pre-conflict manifest stays in place for current rendering and
  anti-downgrade; resolution is a chrome / trust-state concern outside
  this crate's scope. Behavior of the helper itself is unchanged; only
  the framing on the docstring updated.
- **Conformance runner** now invokes `check_anti_downgrade` before
  `check_canary_conflict` when the corpus pre-loads a previously
  verified manifest as context. The two checks are mutually exclusive
  per §08 and are applied in stage order. The standalone
  `check_anti_downgrade` helper was already public; only the harness
  wiring is new.
- **CI conformance corpus pinned to `v1.0-rc.13`** in
  `.github/workflows/ci.yml`. The local `docs-spec/` mirror is at
  rc.13; both rc.13 vectors that exercise new behavior (181
  anti-downgrade, 190 NFD statement) pass alongside the existing 30,
  for a total of 32/32 corpus vectors green. rc.12 vectors 154
  (non-canonical R) and 155 (non-canonical A) were already passing
  under the §05 strict-profile fixes from the v0.1.0 cycle.

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
  The §05 v1.0-rc.4 strict profile (canonical encoding, non-small-order)
  is enforced uniformly: at signature verification via `verify_strict`,
  and at canary structure validation (`canary.runtime_pubkey`, Stage 8)
  and origin binding (`origin.origin_pubkey`, Stage 9) via the
  `validate_pubkey_strict` / `validate_runtime_pubkey_strict` /
  `validate_origin_pubkey_strict` / `validate_publisher_pubkey_strict`
  helpers exposed from the `crypto` module. A pubkey failing the strict
  profile during ordinary signature verification is reported as
  `E_SIG_VERIFICATION` with `details.reason: "public_key_rejected"`,
  per §05 — `E_SIG_INVALID_KEY` is reserved for "expected verification
  key not available". The same rejection on `canary.runtime_pubkey`
  surfaces as `E_CANARY_INVALID` at Stage 8 with
  `details.field_path: "canary.runtime_pubkey"`; on
  `origin.origin_pubkey` as `E_BIND_ORIGIN` at Stage 9 with
  `details.field_path: "origin.origin_pubkey"`.
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
