# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.4] - 2026-05-29

SEMVER PATCH in 0.x. Spec alignment to v1.0-rc.26 (upstream Lotto 26),
closing `samjanny/entangled-api#4`. No code or behavior change; the
implementation already emitted `content_index` for content-index
diagnostics. `spec_version` stays `"1.0"`.

### Changed (spec v1.0-rc.26 alignment - Lotto 26)

- **`SPEC_REVISION` bumped `1.0-rc.25` -> `1.0-rc.26`** and the CI
  conformance-corpus pin (`.github/workflows/ci.yml`) moved to
  `ref: v1.0-rc.26`. rc.26 adds `content_index` as a fifth `document_kind`
  enum value (§11) and assigns it to the three `E_CONTENT_INDEX_*` codes,
  which previously the catalog labelled `manifest`. This crate already
  emitted `DocumentKindLabel::ContentIndex` (serialized `content_index`)
  for those diagnostics (the L-1 regression test pins it), so the spec
  now matches the implementation; no code change. The rc.26 corpus is
  byte-equal to rc.25 at the vector level (only `rc_target` moved).

## [0.5.3] - 2026-05-29

SEMVER PATCH in 0.x. Spec alignment to v1.0-rc.25 (upstream Lotto 25) and
implementation of the section 06:383 announcement-internal successor
address-to-key binding check, closing `samjanny/entangled-api#3`. No
public API signature change; `spec_version` stays `"1.0"`.

### Added

- **migration_pointer successor address-to-key binding check (06:383).**
  `validate_migration_pointer` now verifies, for Tor v3, that
  `successor_origin.address` decodes to a public key equal to
  `successor_origin.origin_pubkey` (the same binding rule as for the
  top-level `origin`, per section 05). This is announcement-internal: it
  checks the two declared fields and does not fetch the successor
  (distinct from the section 10 fetch-time `E_MIGRATION_MISMATCH`
  checks). A decode failure or key mismatch is reported as
  `E_MIGRATION_INVALID` with `details.reason = "successor_key_mismatch"`,
  the closed-enum reason value added in spec rc.25. Before this release
  the check was not enforced at the announcement level; an inconsistent
  successor binding was caught only later, at the section 10 fetch step
  (which is the caller's transport layer). Behavior change: an announcing
  manifest whose `successor_origin` address and pubkey are inconsistent
  is now rejected at Stage 5 validation.

### Changed (spec v1.0-rc.25 alignment - Lotto 25)

- **`SPEC_REVISION` bumped `1.0-rc.24` -> `1.0-rc.25`** and the CI
  conformance-corpus pin (`.github/workflows/ci.yml`) moved to
  `ref: v1.0-rc.25`. The rc.25 corpus adds one vector
  (`202-migration-successor-key-mismatch`) exercising the new check; no
  existing vector input bytes change.

## [0.5.2] - 2026-05-29

SEMVER PATCH in 0.x. Bug fix: the runtime request-state transmit-budget
check now measures the exact JSON-escaped wire byte length the spec
mandates, instead of a raw UTF-8 byte length. Closes
`samjanny/entangled-api#1`. No public API signature change, no spec text
change (the fix aligns the implementation to the existing 07:480 MUST;
`SPEC_REVISION` stays `1.0-rc.24`).

### Fixed

- **E_STATE_TRANSMIT_BUDGET measured raw UTF-8 byte length, not the
  JSON-escaped wire length (07:480 / 09:260).** `StateStore` rejected a
  request-mode `set` whose retained state would overflow the minimal
  submit body, but it projected the body size from raw `value.len()`
  with no escape expansion. A retained `value` containing `"`, `\`, or
  control characters in U+0000 through U+001F is larger on the wire
  (control characters expand to the 6-byte `\u00XX` form), so the check
  under-counted and could admit retained state whose real minimal submit
  body exceeds the 64 KiB cap, which is the deadlock the rule exists to
  prevent. `StateStore::projected_minimal_submit_bytes` now builds the
  actual minimal `SubmitBody` (`fields = {}`, retained request-mode
  entries, a fixed-length `request_id`) and serializes it, taking the
  byte length of the result, which is literally the "exact UTF-8 JSON
  byte sequence it would transmit" 07:480 specifies. This also drops the
  prior approximation that seeded the projection with the 4096-byte 09
  partition reserve in place of the real envelope, so the projection is
  now exact rather than over-reserved. Behavior change: at the wire
  boundary, some control-character-heavy values previously accepted are
  now correctly rejected, and some ASCII values previously rejected by
  the over-reservation are now correctly accepted. A control-character
  regression test is added (`tests/state/transmit_budget.rs`).

### Changed

- **`encoded_request_state_entry_bytes` doc-comment corrected; it
  previously over-claimed about runtime accounting.** The comment
  (added in 0.5.1) stated that the runtime E_STATE_TRANSMIT_BUDGET check
  "is where actual escaped wire bytes are accounted." That was false:
  the runtime check did not escape-expand. The helper is now documented
  as the Stage 5 raw-byte envelope bound only (the necessary condition),
  and is no longer called by the runtime path, which serializes the body
  directly (the sufficient condition). The Stage 5 E_SUBMIT_BUDGET
  aggregate is unchanged and remains correct.
- **Historical-content caller-obligation documentation.** The crate root
  and the `E_HISTORICAL_*` diagnostic-code group now state explicitly
  that historical-content authorization (10:510-553), including the
  10:522 publication-existence MUST that fires
  `E_HISTORICAL_NO_PUBLICATION_PROOF`, lives in the caller's trust-state
  and publisher-history layer and is out of scope for this crate. The
  codes are defined for 11 catalog completeness but are not emitted here;
  a caller building that layer must implement the check. This is a
  security-relevant caller obligation (an exfiltrated former
  `K_runtime_priv` can forge historically-verifying documents without
  the publication-existence check). Documentation only; no behavior
  change.

## [0.5.1] - 2026-05-29

SEMVER PATCH in 0.x. Spec alignment to v1.0-rc.24 (upstream Lotto 24):
seven specification ambiguities are pinned to the reading this crate
already takes, closing upstream `samjanny/entangled#2`, `#3`, `#4`,
`#5`, `#7`, `#8`, and `#9` (AMB-01 through AMB-08). No public API
change, no behavior change, no wire-format change; the crate already
implemented every pinned reading. `spec_version` remains `"1.0"`.

### Changed (spec v1.0-rc.24 alignment - Lotto 24: AMB-01..AMB-08)

- **`SPEC_REVISION` bumped `1.0-rc.23` -> `1.0-rc.24`** and the CI
  conformance-corpus pin (`.github/workflows/ci.yml`) moved to
  `ref: v1.0-rc.24` in lockstep. The conformance harness asserts the
  corpus `rc_target` equals `SPEC_REVISION`; the rc.24 corpus is
  byte-identical to rc.23 at the vector level (only `rc_target`
  moved), so the existing 60 vectors pass unchanged.
- **No emission-path, type, or severity change.** Each of the seven
  upstream ambiguities pins a reading this crate already takes, so no
  code change was required to remain conformant:
  - AMB-01/02 (`samjanny/entangled#2`, `#3`): for `/content_index.json`,
    transport violations map to `E_CONTENT_INDEX_FETCH_FAILED`,
    displacing the generic Stage 1 transport codes. Already documented
    as a caller obligation in `validation/content_index.rs` module docs
    (PR5 / audit finding M-4).
  - AMB-03 (`samjanny/entangled#4`): an empty content-index `entries`
    map is valid. `ContentIndex::is_empty()` already exposes this state
    as legitimate.
  - AMB-04 (`samjanny/entangled#5`): when the content-index fetch
    fails, the per-document checks are not evaluated.
    `verify_content_against_index` requires a `ContentIndex` argument
    that a failed fetch never produces, so these checks already cannot
    run without a verified index.
  - AMB-06 (`samjanny/entangled#7`): the 5-year `origin.not_after`
    ceiling is evaluated per manifest against that manifest's own
    `canary.issued_at`. `validate_origin_not_after` already checks the
    horizon against the current manifest's `canary.issued_at`.
  - AMB-07 (`samjanny/entangled#8`): the `request_state`/`fields`
    array-wrapper bytes count against `SUBMIT_OVERHEAD_RESERVE_BYTES`;
    only per-entry payload and inter-entry commas count against the
    per-array budget. `aggregate_request_state_bytes` already counts
    the 36-byte per-entry envelope plus field lengths plus inter-entry
    commas, with the array wrapper provided for in the 4096-byte
    overhead reserve.
  - AMB-08 (`samjanny/entangled#9`): the per-value `max_size` cap and
    the 4096 ceiling are raw UTF-8 byte lengths, not JSON-escaped wire
    lengths. The crate already checks `value.len()` (raw UTF-8 bytes)
    against the cap and plugs the raw `max_size` into the Stage 5
    budget aggregate with no escape expansion. The
    `encoded_request_state_entry_bytes` doc comment in
    `validation/state.rs` is sharpened to state explicitly that
    `value_bytes` is a raw UTF-8 byte length in both call sites and is
    not escape-expanded for the Stage 5 envelope bound.

### Fixed

- **README stale crate version.** The Status section read
  `Current crate version: 0.1.0`; it now reads `0.5.1`, matching the
  package version. This line had not been updated since the 0.1.0
  release and was unrelated to any single feature change.

## [0.5.0] - 2026-05-28

SEMVER MINOR in 0.x. Public API break driven by the v1.0-rc.23 spec
catalog alignment (Lotto 23, N64-N66): two diagnostic codes are
renamed and promoted from `warning` to `error`, and one stage tag is
corrected, closing upstream `samjanny/entangled#10` (AMB-09) and
`samjanny/entangled#6` (AMB-05) plus one sweep finding (N66). The
break affects downstream code that pattern-matches the renamed enum
variants or relies on `DiagnosticCode::stage()` returning `9` for
`EOriginInvalid`, and the serde wire form of the `code` field
changes for the two renamed codes. No wire-format change to any
signed document; `spec_version` remains `"1.0"`.

### Changed (spec v1.0-rc.23 alignment - Lotto 23: N64-N66)

Two diagnostic codes are renamed and promoted from `warning` to
`error`, and one stage tag is corrected, to align `entangled-core`
with the v1.0-rc.23 spec catalog. The N63 / Lotto 22 source-cite
discipline against external libraries is extended at rc.23 to the
catalog-vs-behavior dimension via a full row-by-row sweep of section
11 against the emission sections in section 02 through section 10
(see upstream `docs/RELEASES.md` for the per-row verdict table).

- **`W_CANARY_EXPIRED` renamed to `E_CANARY_EXPIRED`, severity
  promoted `warning` -> `error`** (rc.23 N64 / AMB-09, closing
  upstream `samjanny/entangled#10`). The pre-rc.23 catalog row was
  cataloged as `warning` even though section 08:183 attaches a
  MUST-block on rendering when the canary is in Expired state.
  `entangled_core::validation::DiagnosticCode::WCanaryExpired` is
  renamed to `ECanaryExpired`; the serde rename string moves from
  `"W_CANARY_EXPIRED"` to `"E_CANARY_EXPIRED"`; the variant leaves
  the `Severity::Warning` group in `severity()` and falls into the
  default `_ => Severity::Error` branch. The `stage()` classifier
  keeps the code at Stage 8. The module documentation in
  `validation/canary.rs` and the workspace `README` section "Canary
  state and the Expired user-override contract" are reworded to drop
  the historical "catalog warning vs section 08 MUST-block tension"
  framing (closed at rc.23) and to call out the section 08:185
  per-session user-override and the section 08 permissive-canary
  mode as spec-defined laxer-policy carve-outs to the default block,
  distinct from a section 11:87 client-side reclassification of
  severity.
- **`E_ORIGIN_INVALID` stage tag corrected Stage 9 -> Stage 5**
  (rc.23 N65 / AMB-05, closing upstream `samjanny/entangled#6`). The
  pre-rc.23 catalog row was placed under the Binding (Stage 9)
  section even though the actual emission per section 06:171 and
  section 10:191 is a Stage 5 cross-field semantic check on
  `origin.not_after` and `canary.issued_at`. The api's
  `validate_origin_not_after` already fired at Stage 5 (PR4 audit
  finding M-3); `DiagnosticCode::stage()` now returns `5` for
  `EOriginInvalid` where prior versions returned `9`. No
  emission-path change.
- **`W_HISTORICAL_RUNTIME_AMBIGUOUS` renamed to
  `E_HISTORICAL_RUNTIME_AMBIGUOUS`, severity promoted `warning` ->
  `error`** (rc.23 N66, surfaced by the upstream sweep, not by a
  filed issue). Same catalog-vs-behavior pattern as N64 / AMB-09:
  the catalog row was `warning` even though section 10:553
  normatively says "the client MUST reject the document and surface
  `W_HISTORICAL_RUNTIME_AMBIGUOUS`. The document is not rendered."
  `DiagnosticCode::WHistoricalRuntimeAmbiguous` is renamed to
  `EHistoricalRuntimeAmbiguous`; the serde rename string moves from
  `"W_HISTORICAL_RUNTIME_AMBIGUOUS"` to
  `"E_HISTORICAL_RUNTIME_AMBIGUOUS"`; the variant leaves the
  `Severity::Warning` group. Stage classification remains `0`
  (off-pipeline historical-content group).

### Changed (spec revision pin)

- **`entangled_core::SPEC_REVISION`** bumped from `"1.0-rc.22"` to
  `"1.0-rc.23"`.
- **CI conformance corpus pin** in `.github/workflows/ci.yml` bumped
  from `v1.0-rc.22` to `v1.0-rc.23`. The conformance harness asserts
  `corpus.rc_target == SPEC_REVISION`; both are now `"1.0-rc.23"`.

The diagnostic code renames are a public API break (downstream code
matching `DiagnosticCode::WCanaryExpired` or
`DiagnosticCode::WHistoricalRuntimeAmbiguous` will not compile
against the rc.23-aligned crate). The serde wire form of the `code`
field also changes: a diagnostic emitted by an rc.23-aligned
implementation serializes `code` as `"E_CANARY_EXPIRED"` or
`"E_HISTORICAL_RUNTIME_AMBIGUOUS"` where prior versions emitted the
`W_*` variants. `code.stage()` returns `5` for `EOriginInvalid`
where prior versions returned `9`. SEMVER MINOR bump in 0.x is the
appropriate classification for this break and will accompany the
next release tag.

No wire-format change to any signed document. JCS canonicalization,
NFC, byte caps, schema, and signature input construction are
unchanged. `spec_version` remains `"1.0"`. Conformance corpus
vectors are unchanged byte-for-byte (no vector targets the renamed
codes); only `corpus.json` `rc_target` is bumped to `"1.0-rc.23"`,
matching the upstream tag.

Four regression-test updates in `tests/validation/diagnostic_codes.rs`
pin the renamed-and-promoted codes at the corrected severity and the
relocated stage; the round-trip serialization test set is updated to
use the new enum variants and serde renames.

## [0.4.0] - 2026-05-28

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
plugged fifteen correctness/normative gaps unrelated to a single spec
revision (PR1-PR5). Conformance harness now matches the upstream rc.22 corpus
byte-equal at the `rc_target` boundary (60/60 vectors).

### Changed (internal review follow-ups, PR4 + PR5)

The PR4 commit (`6d3e0c5`) and the PR5 follow-ups together plug
eight further spec-vs-code gaps surfaced by an internal review
pass against rc.22. None of the items below changes the wire
protocol.

PR4:

- **Section 10 Stage 9 `origin.not_after` reached via the canonical
  pipeline** (audit finding C-1). `ManifestCanaryChecked::verify_origin`
  previously ran only the carrier (Tor v3 address) binding, leaving
  the `not_after` expiry check (`check_origin_not_after`,
  `validation::migration`) reachable only by callers who knew to
  invoke it manually after Stage 9. The canonical chain
  `parse_and_verify_manifest -> verify_canary -> verify_origin`
  therefore silently accepted manifests whose `origin.not_after`
  was past, violating the Section 10 MUST. `verify_origin` now takes
  a `now: &EntangledTimestamp` argument and runs
  `check_origin_not_after` after the address binding. The conformance
  runner no longer needs the manual post-call. New regression tests
  in `tests/document/type_state.rs` assert that the canonical
  pipeline emits `E_ORIGIN_EXPIRED` on a past `not_after` and accepts
  a future one.
- **Section 06 Stage 5 builder enforces `origin.not_after` semantic
  constraints** (audit finding M-3).
  `document::builder::build_manifest` ran `validate_manifest_fields`
  but never `validate_origin_not_after`, so a publisher could sign a
  manifest whose `not_after` was at or before `canary.issued_at`, or
  more than five years after it, and the bytes would only fail at
  parse time on the receiving side. The builder now calls
  `validate_origin_not_after`, matching the verifier path. Two
  regression tests in `tests/document/build_parse_roundtrip.rs`
  cover both rejection branches
  (`not_after_not_later_than_issued_at`, `not_after_beyond_5y`).
- **Section 11 `E_ORIGIN_INVALID` details use canonical vocabulary**
  (audit finding M-1). The diagnostic `details` emitted the
  non-canonical key `canary_issued_at` instead of the Section 11:273
  vocabulary `issued_at`. Renamed at both emission sites in
  `validation::schema`. New regression test in
  `tests/validation/stage5_schema.rs` pins the canonical key for
  both reason variants and asserts the old key is gone.
- **`DocumentKindLabel::ContentIndex` variant** (audit finding L-1).
  Content-index diagnostics were tagged `Manifest` because no
  `ContentIndex` variant existed. Added the variant (wire form
  `content_index`), updated all eight call sites in
  `validation::content_index`. Per-document diagnostics in
  `verify_content_against_index` keep `DocumentKindLabel::Content`,
  which is correct (they pertain to a content document, not the
  index). New regression test in `tests/validation/content_index.rs`
  covers six diagnostic paths.
- **`ORIGIN_NOT_AFTER_MAX_HORIZON_SECS` placement fix** (audit
  finding L-2). The constant lived under the Content index section
  header in `limits.rs` by mistake; the Origin not-after section
  header was empty. The constant was moved under its correct
  header.
- **Drive-by**: `crypto::ed25519::validate_pubkey_strict` docstring
  intra-doc link to `Self::from_pubkey_bytes` was broken because
  `Self` in a free-function context does not resolve, so
  `cargo doc -D warnings` (the CI doc job) was failing. Reworded to
  a plain prose reference to the private
  `VerifyingKey::from_pubkey_bytes` constructor.

PR5:

- **Caller-side transport obligations documented on
  `validation::content_index`** (audit finding M-4). The Section 09
  transport rules for the `/content_index.json` fetch are the
  fetching caller's responsibility: `Content-Type` MUST be
  `application/json` (not `application/entangled+json`),
  `Content-Length` MUST be present and exact, and `Content-Encoding`
  / `Transfer-Encoding` MUST be absent. Each violation maps to
  `E_CONTENT_INDEX_FETCH_FAILED` rather than to the generic Stage 1
  transport codes. The module docstring and the
  `validate_content_index` `# Errors` block now spell this out so a
  caller routing around the Stage 1 codes knows which code to emit.
  No library code change.
- **`W_CANARY_EXPIRED` per-session user-override caller contract
  documented** (audit finding M-5). Section 08:183 attaches a
  normative MUST-block on rendering when `CanaryState::Expired` is
  observed, and Section 08:185 attaches a normative MUST-provide
  per-session user-override affordance, even though Section 11:206
  catalogues `W_CANARY_EXPIRED` at warning severity and Section
  11:81 frames warnings as non-blocking by default. The library
  remains stateless: it classifies the canary and emits the
  diagnostic at the catalogued severity; the override state, the
  chrome affordance, and the persistent chrome warning while the
  override is active all live in the embedding caller. Documented
  on the `validation::canary` module, on `CanaryState::Expired`,
  and as a new top-level section "Canary state and the Expired
  user-override contract" in the workspace README. No library code
  change. A separate upstream issue raises the Section 08 vs
  Section 11 framing tension against the spec.
- **`ManifestContentIndexVerified` Stage 9b type-state** (audit
  finding C-2). The Section 09:114 hard-fail MUST ("when the
  manifest declares `content_root` and the content index cannot be
  obtained, the client MUST NOT render content documents from the
  site") is now enforced structurally by extending the type-state
  chain: `ManifestOriginBound::verify_content_index(content_index_bytes:
  Option<&[u8]>)` returns a new `ManifestContentIndexVerified`
  terminal wrapper, and
  `ManifestOriginBound::skip_content_index_check()` is the explicit
  opt-out (mirroring `skip_canary_check` /
  `skip_origin_check`). `ManifestOriginBound::into_parts` has been
  removed in favour of
  `ManifestContentIndexVerified::into_parts() -> (Manifest, CanaryState, Option<ContentIndex>)`.
  This is a public API break (SEMVER MINOR in 0.x): existing
  callers of `into_parts` on `ManifestOriginBound` must either
  insert `.verify_content_index(maybe_bytes)?` or call
  `.skip_content_index_check()`. The conformance runner and the
  Tor integration test use `skip_content_index_check` because
  content-index validation is exercised separately against the
  standalone `validate_content_index` helper. Three new regression
  tests in `tests/document/type_state.rs` cover the hard-fail on
  `None` bytes plus declared `content_root`, the happy path with
  matching bytes, and the explicit `skip_content_index_check`
  opt-out.

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
