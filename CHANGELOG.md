# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

SEMVER MINOR in 0.x. Three upstream spec tags land in this release:
rc.20 was errata-only (corpus vector 139 field correction, no
implementation impact), rc.21 introduces a normative tightening on
`state_policy` satisfiability (N62, `E_SUBMIT_BUDGET`), and rc.22
aligns §05:174 to what `ed25519-dalek::verify_strict` has always
actually done about small-order signature `R` rejection (N63, closing
upstream issue #1, opened from this audit). The same release closes
the rc.19 catch-up that the prior 0.3.x line had only partially
landed (Lotti 11-13 / N45-N51); Lotti 14, 15, 16, 18, and 19 are now
landed here. The release also lands an internal audit pass that
plugged seven correctness/normative gaps unrelated to a single spec
revision. Conformance harness now matches the upstream rc.22 corpus
byte-equal at the `rc_target` boundary (60/60 vectors).

### Changed (spec v1.0-rc.22 alignment — Lotto 22)

- **§05:174 small-order `R` rejection alignment** (Lotto 22, N63).
  Pre-N63 §05:174 wrongly claimed `verify_strict` accepts small-order
  `R`; rc.22 inverts the rule (the strict profile MUST reject small-
  order `R`), matching what `ed25519_dalek 2.x verify_strict` always
  did. No code change was needed in this crate — `crypto::ed25519`
  uses `verify_strict`, so we were already conformant under rc.22
  semantics. The `VerifyingKey::verify` docstring is updated to drop
  the "known divergence" note (no longer divergent) and cite N63 as
  the source of the symmetric small-order rejection rule. Corpus
  vector `157-sig-small-order-r` lands as an additional sub-case of
  `E_SIG_VERIFICATION` and passes end-to-end against the existing
  pipeline.

### Changed (spec v1.0-rc.21 alignment — Lotto 21)

- **§07 / §09 submit budget satisfiability invariant** (Lotto 21, N62).
  `validate_state_policy` now rejects a manifest whose `state_policy`
  aggregate worst-case `request_state` encoded contribution exceeds
  the new `SUBMIT_STATE_BUDGET_BYTES = 53_248` budget. The check is
  Stage 5, deterministic from the manifest payload alone, and does
  not depend on the client's current retained state. New diagnostic
  `E_SUBMIT_BUDGET` (severity Error, stage 5, document_kind Manifest)
  with structured `details = { component: "state", declared_bytes,
  budget_bytes }`. Closes the deadlock vector in which a compromised
  `K_runtime` repeatedly issues `set` operations filling state to the
  policy's declared maxima.
- **`SUBMIT_STATE_BUDGET_BYTES`, `SUBMIT_OVERHEAD_RESERVE_BYTES`,
  `SUBMIT_FIELD_MIN_RESERVE_BYTES`** added to
  `entangled_core::validation::limits`. A compile-time `const _: () =
  assert!(...)` pins the §09 partition identity `overhead +
  field_min + state_budget == SUBMIT_BODY_MAX_BYTES` so a future
  re-tune cannot silently break the cap.

### Changed (spec v1.0-rc.19 catch-up — Lotti 14-19, N52-N60)

These changes had landed in upstream rc.19 alongside Lotti 11-13
but were not in the prior 0.3.x line. They are landed here as part
of the rc.21 bump.

- **`E_CANARY_RUNTIME_REUSE`** (Lotto 14 N55 + Lotto 19 N60). New
  Stage 8 diagnostic. New helper
  `entangled_core::validation::canary::check_runtime_pubkey_rotation`
  enforces the MUST-level immediate-preceding rotation check and the
  SHOULD-level extended publisher-history check. Structured `details
  = { runtime_pubkey, previous_issued_at, current_issued_at,
  window_position }` where `window_position = 1` is the immediate-
  preceding match and `>= 2` walks publisher history backwards.
- **`E_HISTORICAL_NO_PUBLICATION_PROOF`** (Lotto 14 N52). New
  off-pipeline diagnostic (severity Error, document_kind Content).
  Catalog entry only — the check itself is the caller's
  responsibility, since publication-existence proof relies on either
  a previously verified content index or a rendering record, both
  outside the crate's scope.
- **`canary.freshness_proof` NFC enforcement made explicit** (Lotto
  18 N59). Stage 5 now applies the §04 NFC requirement to
  `freshness_proof` symmetrically with `statement`. An rc.18
  implementation correctly applying §04:154 already produced the
  correct rejection; the explicit check pins the behavior against
  future refactors and corpus vector `191-unicode-nfd-freshness-proof`.
- **`E_MIGRATION_INVALID` structured details extended** (Lotto 15
  N57). All emission sites now carry `announcing_origin_address` and
  `successor_origin_address` in `details`. Two `reason` identifiers
  are renamed to the §11 vocabulary:
  `self_pointing_migration → self_pointer` and `announced_after_updated
  → announced_at_after_updated`. The `chain_cycle` reason already
  matched. The helper `check_migration_chain_cycle` gains an
  `announcing_origin_address` parameter so the diagnostic can name
  both ends of the rejected hop (callers must pass the announcing
  origin's address — typically the announcing manifest's
  `origin.address`).
- **`E_ORIGIN_INVALID.details.reason` typo fixed** (Lotto 15 N56).
  The strict-later-than constraint now reports `details.reason =
  "not_after_not_later_than_issued_at"`, matching the §11 vocabulary.
  The pre-N56 identifier (`not_after_not_after_issued_at`) carried
  an obvious stutter.

### Changed (conformance harness — rc.19/rc.21 alignment)

- **`previously_verified_history` context field** wired into the
  harness. Carries the publisher's ordered prior-manifest history
  (oldest first) for N60-style vectors (`185-canary-runtime-reuse-
  resurrection`). The harness reverses the array into the
  most-recent-first order expected by `check_runtime_pubkey_rotation`
  and, when the corpus omits the immediate-preceding
  `previously_verified` field, treats the head of the history as the
  immediate-preceding manifest so `window_position` accounting
  matches the §11 N60 schema.
- **Migration chain-cycle guard wired into multi-manifest vectors.**
  The harness now seeds `visited_origins` with the announcing
  origin, applies `check_migration_chain_cycle` on the announcing
  manifest's own `migration_pointer`, and reapplies it on the
  successor manifest's `migration_pointer` after a successful
  successor pipeline. Exercises vector
  `201-migration-chain-cycle` end-to-end.
- **No-key-available content vectors emit `E_SIG_INVALID_KEY`.**
  When a content vector omits both `expected_runtime_pubkey` and
  `previously_verified` and the pipeline surfaces
  `E_SIG_VERIFICATION` under the placeholder zero key, the harness
  re-maps the diagnostic to `E_SIG_INVALID_KEY` per §11:172/175.
  Models the "no relevant verified manifest available" case from
  vector `156-sig-invalid-key-no-manifest` without conflating it
  with verify-equation failures.

### Changed (spec revision pin)

- **`entangled_core::SPEC_REVISION = "1.0-rc.21"`** (bumped from
  rc.19, skipping rc.20 which was errata-only and conformance-
  identical to rc.19 at the catalog level).
- **CI conformance corpus pin** moved from the rc.18 commit-SHA pin
  to `ref: v1.0-rc.21` in `.github/workflows/ci.yml`. The
  "temporary commit-SHA pin" note is dropped now that an upstream
  tag exists.

## [0.3.1] - 2026-05-11

SEMVER PATCH. Findings from an internal crypto-security audit of the
0.3.0 line. No wire-format or behavioral change for conformant inputs;
all changes are additive helpers, internal hardening, or CI/policy
fixes. Existing signatures produced under 0.3.0 continue to verify
byte-equivalent under 0.3.1.

### Fixed (security hardening)

- **Verifier signature input now derived from the wire `Value`, not a
  typed-model round trip** (audit finding H-1). Previously,
  `parse_and_verify_{manifest,content,transaction}` computed the
  Stage 6 signature input by re-serializing the deserialized typed
  struct (`serde_json::to_value(&manifest)`), re-attaching the `kind`
  discriminator, stripping `sig`, and JCS-canonicalizing the result.
  The bytes the verifier actually checked against the Ed25519
  signature were therefore mediated by the faithfulness of every
  `Serialize`/`Deserialize` impl in the workspace — a structural
  invariant that holds today but would silently break the next time
  a struct grows a field with on-the-way-in normalization or an
  `Option` whose `skip_serializing_if` semantics drift. The verifier
  now takes the wire `Value` returned by Stage 3 parsing, strips
  `sig`, and canonicalizes that directly. No conformant signature is
  affected today (a new property test pins both paths to the same
  JCS bytes), but the invariant is now anchored to the bytes the
  parser observed rather than to a Serialize-impl audit obligation.

### Added

- `entangled_core::types::keys::RequestId::generate()` — production
  constructor that draws 16 bytes of OS entropy via `getrandom`
  (audit finding L-1). Documented panic on RNG unavailability,
  matching the existing internal `SigningKey::generate` pattern.
  `from_bytes` remains available for tests and embedders integrating
  a non-OS entropy source; its docstring now steers production
  callers to `generate()` so the §09 anti-replay no-reuse contract
  is not silently bypassed by a counter-derived id.
- `entangled_core::types::Manifest::canonical_payload_hash() -> [u8; 32]`
  and the matching default method on `ManifestRead` (audit finding
  L-4). Computes the SHA-256 of the JCS-canonical signed payload —
  the same digest required for
  `RetainedManifestRecord::manifest_payload_hash` in the §08
  anti-conflict check. Available on every type-state wrapper so
  callers can record the hash before `into_parts()`. A test pins
  the helper's output byte-equal to the digest derived from the
  wire path.
- `entangled_core::validation::parse_and_validate_{manifest,content,
  transaction}_with_value` — variants that return both the typed
  model and the parsed wire `Value`. Backing the H-1 verifier
  refactor; useful in their own right for callers that need the
  validated `Value` (e.g. higher-level diagnostic surfaces).
- `entangled_core::SPEC_REVISION = "1.0-rc.18"` constant. The
  conformance harness now asserts byte-equality between this
  constant and the corpus's `rc_target`; a corpus pinned ahead of
  or behind the code fails CI loudly instead of degrading silently
  (audit finding M-2).
- Top-level `SECURITY.md` documenting the private vulnerability
  reporting channel, response-timeline SLAs, and disclosure norms
  (audit finding L-2).

### Changed

- CI conformance corpus pin moved forward to align with rc.18
  content (audit finding M-2). Until upstream
  [`samjanny/entangled`](https://github.com/samjanny/entangled) cuts
  the `v1.0-rc.18` tag, the CI workflow pins to the upstream `main`
  HEAD commit `a807cd33` carrying the rc.18 corpus during the
  post-soak window. Switch back to a tag ref once cut.

## [0.3.0] - 2026-05-11

SEMVER MINOR in 0.x. Behavioral break driven by the spec v1.0-rc.18
Lotto 10 cryptographic-audit tranche: the §08 canary interval ceiling
narrows from 90 to 30 days. The rc.18 Lotto 7 clarifications
(N18/N21/N30/N31) shipped in 0.2.0; this tag adds only the Lotto 10
normative tightening.

### Changed (spec v1.0-rc.18 alignment — Lotto 10)

- **§08 Canary interval ceiling — 90 days → 30 days** (Lotto 10, N42).
  `CANARY_INTERVAL_MAX_SECS` drops from `90 * 86_400` (7,776,000 s) to
  `30 * 86_400` (2,592,000 s), aligning the protocol-level MUST with
  the operational upper bound previously recommended by the operator
  playbook. The 7-day MUST floor is unchanged. `validate_canary_structure`
  rejects intervals in `(30, 90]` days under the same `E_CANARY_INVALID`
  code; the diagnostic message updates from "90 days" to "30 days".
  Tests that previously asserted a 90-day boundary now assert a 30-day
  boundary; shared fixtures (`tests/common`, `tests/document/fixtures`,
  `tests/tor/integration_full`, `tests/validation/manifest_clock_skew`,
  `tests/document/type_state`) shrink their default canary intervals
  from 31 to 30 days. An rc.17 publisher emitting an interval in
  `(30, 90]` days is non-conformant under rc.18.

## [0.2.1] - 2026-05-11

### Fixed

- Broken rustdoc intra-doc link for `validate_migration_pointer` that
  would have failed `cargo doc` under `-D warnings` (CI doc job) and
  similarly broken docs.rs (459ac26). No API or behavioral change.

## [0.2.0] - 2026-05-11

SEMVER MINOR in 0.x. Tagged after the rc.13 → rc.18 Lotto 7
spec-alignment accumulation, a validator return-type change, and
security-audit follow-ups. The detailed spec-alignment entries below
were drafted under "Unreleased" as each rc landed and were not promoted
into this versioned section when the tag was cut; they are reproduced
here verbatim.

### Changed

- **Public API: `validate_state_updates_against_policy` return type**
  changed from `Result<(), Diagnostic>` to
  `Result<Vec<&StatePolicyEntry>, Diagnostic>` to eliminate the
  `set_with_policy` panic-on-invariant by threading the matched policy
  entries from the validator (1b6495d). This is the SEMVER MINOR break
  that motivated the 0.1 → 0.2 bump.
- **Security audit follow-ups** (3374b1d): `StoreKey` strongly typed at
  the state-store boundary; `migration_pointer` null guard at parse.

### Changed (spec v1.0-rc.18 alignment — Lotto 7, anticipating tag)

The rc.18 tag was in soak on rc.17 at the time of this release. The
Lotto 7 errata are textual clarifications and one diagnostic-precision
constraint, all behaviorally compatible with rc.16 / rc.17 emitters.

- **§11 `E_ORIGIN_EXPIRED.details.now` rounded down to minute precision**
  (N18). `check_origin_not_after` now emits `details.now` as
  `YYYY-MM-DDTHH:MM:00Z` so the diagnostic does not leak sub-minute
  clock skew if forwarded to third parties (crash reports, support
  channels). Minute-level resolution remains sufficient for clock-skew
  troubleshooting. `details.not_after` is publisher-declared and
  exposed as-is. New `minute_precision_utc` helper inside the module.
- **§10 Cross-session migration history — module docs tightened to
  rc.18 wording.** `validation/migration.rs` records the N30 rule
  (Replacement events fire at every Adoption against the pre-Adoption
  current origin, closing the `A → B → A → B` direction gap) and the
  N31 365-day SHOULD-NOT-exceed upper bound (plus the
  bounded-storage event-count alternative). Storage and confirmation
  surface remain caller concerns; the crate adds no new types.
- **§10 Chain depth and cycle prevention — post-rejection state
  clarified** (N21). `check_migration_chain_cycle` docstring notes
  that a cycle rejection invalidates only the new adoption: the most
  recently verified successor stays the current origin and cached
  manifests for visited origins remain usable under their refresh
  policy. No behavior change; documentation only.

### Changed (spec v1.0-rc.17 alignment)

- **CI conformance corpus pinned to `v1.0-rc.17`** in
  `.github/workflows/ci.yml`. rc.17 is wire-format and corpus-content
  identical to rc.16 (the bump is to the spec-repo tag covering the
  Lotto 6 operator playbook and README updates). No protocol or
  crate-API surface changes; the corpus remains 34 vectors and all
  pass byte-for-byte.

### Changed (spec v1.0-rc.16 alignment)

- **§11 `E_MIGRATION_MISMATCH.details.underlying_diagnostic` →
  `underlying_diagnostic_code`** (N22). The field is renamed for
  clarity: it carries only the §11 **code identifier string** (e.g.
  `"E_ORIGIN_EXPIRED"`), not the full structured diagnostic record.
  `wrap_successor_stage9_failure` now emits a JSON string under the new
  key; the rc.15 nested-record shape is gone. Tests assert the new key
  and the absence of the rc.15 key.
- **Conformance harness — Stage 9 origin-not-after and migration
  scenarios.** `tests/conformance/runner.rs` now invokes
  `check_origin_not_after` after carrier origin binding for every
  manifest vector, and adds a migration scenario branch driven by the
  rc.16 corpus context (`successor_origin_address`,
  `successor_manifest_path`). On a successor Stage 1-9 failure the
  harness calls `wrap_successor_stage9_failure` and compares the
  produced `details` against the corpus `diagnostic_details` (subset
  match). `Verdict::Reject` now carries the full `Diagnostic` so
  details can be compared.
- **CI conformance corpus pinned to `v1.0-rc.16`**
  (`.github/workflows/ci.yml`). Total vectors 34 (was 32) — new rc.16
  vectors `006-manifest-valid-not-after` and
  `200-migration-successor-origin-expired` exercise the rc.14
  `origin.not_after` schema acceptance and the rc.15
  `successor_stage9_failure` migration path respectively. All 34
  vectors are green.

### Added (spec v1.0-rc.16 alignment)

- **Cross-session migration history (§10 v1.0-rc.16, N20) — caller-side
  documentation.** New module-level note in
  `entangled-core/src/validation/migration.rs` describing the rc.16
  SHOULD-level mitigation: clients maintaining per-publisher migration
  history (adoption / replacement events) should consult it within a
  recall window (recommended 30 days; configurable, 7-day minimum)
  and raise friction on a successor that was previously replaced.
  Storage and the user-confirmation surface are caller concerns
  (trust-state machine + chrome); the crate provides no
  `MigrationHistory` type because v1.0 leaves the storage backend
  unspecified. Documented as a v1.0 limitation.

### Changed (spec v1.0-rc.15 alignment)

- **§11 `E_MIGRATION_MISMATCH` `details` schema** updated to the rc.15
  shape: `mismatch_field` (with values `publisher_pubkey`, `address`,
  `origin_pubkey`, and the rc.15 addition `successor_stage9_failure`)
  replaces the prior crate-local `reason` key; pubkey fields renamed
  from `announcing_pubkey` / `successor_pubkey` to
  `announcing_publisher_pubkey` / `successor_publisher_pubkey` to match
  the §11 vocabulary. `verify_migration_announcement` emits the new
  schema for the `publisher_pubkey` direct-mismatch path. Tests
  updated; no consumers of the legacy keys remain.
- **§10 rc.15 symmetric clock-skew formula** codified in the
  `check_origin_not_after` docstring. Behavior unchanged: the
  pre-existing implementation already evaluates `now > not_after +
  CLOCK_SKEW_TOLERANCE_SECS`, which is the rc.15 normative formula.
  The docstring now references the past-bound mirror of the future-bound
  tolerance applied to `manifest.updated` and `canary.issued_at`.

### Added (spec v1.0-rc.15 alignment)

- **`wrap_successor_stage9_failure`** (§11 v1.0-rc.15): public helper
  that wraps a successor manifest's Stage 1-9 failure into an
  `E_MIGRATION_MISMATCH` diagnostic without losing the underlying
  cause. The wrapper attaches `mismatch_field:
  "successor_stage9_failure"`, the announced successor address, the
  announcing publisher pubkey, and the original diagnostic verbatim as
  `underlying_diagnostic`. `successor_publisher_pubkey` is scoped per
  rc.15: present only when the caller supplies it (the successor
  cleared its own Stage 5), omitted otherwise (failures at Stage 1-4
  before a validated pubkey exists). Lives at
  `validation::wrap_successor_stage9_failure`.
- **CI conformance corpus pinned to `v1.0-rc.15`** in
  `.github/workflows/ci.yml`. rc.15 is wire-compatible with rc.14
  (no schema or canonicalization changes; the diagnostic-details
  extension is additive); the existing 32 corpus vectors validate
  identically byte-for-byte.

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
