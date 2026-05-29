//! Stage 8 canary state and structure validation (§08, §10).
//!
//! Three concerns live here:
//!
//! * [`compute_canary_state`] — pure time arithmetic; classifies a structurally
//!   valid canary into Fresh / NearExpiration / Expired given the current
//!   wall clock. Never returns `Invalid` or `Unavailable`.
//! * [`validate_canary_structure`] — Stage 8 structural checks: future-skew,
//!   ordering, and the [7..=30] day interval bound (§08; ceiling
//!   tightened from 90 to 30 days in v1.0-rc.18, N42).
//! * [`check_anti_downgrade`] — comparison against the most recent
//!   `issued_at` known for the same publisher pubkey in publisher history
//!   (§08 — "MUST NOT accept a canary older than the freshest one previously
//!   pinned for this publisher").
//!
//! String length caps for `statement` and `freshness_proof` are part of Stage
//! 5 schema validation and are not duplicated here.
//!
//! # Client UX obligations after `compute_canary_state`
//!
//! [`compute_canary_state`] classifies the canary; it does not
//! enforce the Section 10 client UX obligations attached to each
//! state. Those are the caller's responsibility:
//!
//! * [`CanaryState::Fresh`]: render content normally; chrome shows
//!   `canary.next_expected`.
//! * [`CanaryState::NearExpiration`]: render content normally;
//!   chrome surfaces the approaching deadline with visual emphasis.
//! * [`CanaryState::Expired`]: Section 08:183 MUST -- the client
//!   refuses to render current content. The content area MUST be
//!   blank or a client-generated placeholder; publisher-controlled
//!   content MUST NOT appear. Section 08:185 MUST -- the client
//!   provides a per-session user-override affordance with these
//!   properties:
//!     * an affirmative-action chrome control (button, key
//!       combination, or equivalent) whose semantics are
//!       unambiguously "accept the risk and proceed"; passive
//!       events MUST NOT count as acceptance;
//!     * scope is the remainder of the current session for the
//!       affected site only: the override does not persist across
//!       sessions, does not modify the canary state, and does not
//!       suppress the chrome warning;
//!     * while the override is active, a persistent,
//!       not-easily-dismissible warning MUST stay visible in
//!       chrome.
//! * [`CanaryState::Invalid`]: Section 08:197 MUST -- refuse to
//!   render any content from the site; chrome shows a prominent
//!   error.
//! * [`CanaryState::Unavailable`]: handle as the corresponding
//!   transport-failure UX (Section 09 / Section 10); the value
//!   carries no normative `W_*` code on its own.
//!
//! The Section 11 diagnostic `E_CANARY_EXPIRED` is catalogued at
//! `error` severity (rc.23 N64; the code was `W_CANARY_EXPIRED` at
//! `warning` severity in rc.10 through rc.22, and rc.23 closed the
//! catalog-vs-behavior mismatch by renaming and promoting). The
//! catalog now aligns with the Section 08:183 normative MUST that
//! rendering of current content is blocked. The Section 08:185
//! per-session user-override affordance and the Section 08
//! permissive-canary mode are the spec-defined laxer-policy
//! carve-outs to the default block, distinct from a Section 11:87
//! client-side reclassification of severity. The library remains
//! stateless: it classifies the canary, surfaces the state, emits
//! the diagnostic at the catalogued `error` severity, and the
//! embedding caller is responsible for the rendering block, the
//! per-session override affordance, and the chrome warning that
//! persists while the override is active. See also the crate
//! `README` section "Canary state and the Expired user-override
//! contract" for the corresponding public-docs framing.

use crate::crypto::validate_runtime_pubkey_strict;
use crate::types::keys::RuntimePubkey;
use crate::types::{Canary, EntangledTimestamp};
use crate::validation::clock::{check_future_timestamp, CANARY_ISSUED_AT_FIELD};
use crate::validation::diagnostic::{Diagnostic, DiagnosticCode, DocumentKindLabel};
use crate::validation::limits::{CANARY_INTERVAL_MAX_SECS, CANARY_INTERVAL_MIN_SECS};

const SECS_PER_DAY: i64 = 86_400;
const NEAR_EXPIRATION_FLOOR_SECS: i64 = SECS_PER_DAY;

/// Per §08, the four observable states for a canary plus a separate
/// `Unavailable` placeholder for the "no canary in hand" failure mode.
///
/// `compute_canary_state` only returns the time-derived states (Fresh /
/// NearExpiration / Expired). `Invalid` is the result of structural rejection
/// (see [`validate_canary_structure`]) and is included in the enum so callers
/// can express the full set in their own state machines. `Unavailable` covers
/// network/transport failure to fetch a canary at all and is likewise produced
/// by other layers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanaryState {
    /// Canary is well within its validity window.
    Fresh,
    /// Canary is within `max(10% of interval, 24h)` of its `next_expected`.
    NearExpiration,
    /// `now >= next_expected`. The Section 08:183/185 client
    /// rendering block and per-session user-override affordance
    /// are the caller's responsibility; see the module-level docs
    /// for the full contract.
    Expired,
    /// Canary failed structural validation (Stage 8).
    Invalid,
    /// No canary in hand (transport failure, missing field, etc.).
    Unavailable,
}

/// Classify a canary by `now`. Assumes the canary has already passed
/// [`validate_canary_structure`] — does no structural checks itself.
///
/// The "near-expiration window" is `max(10% of the interval, 24 hours)`
/// (§08). A canary is `Expired` if `now >= next_expected` (inclusive).
pub fn compute_canary_state(
    issued_at: &EntangledTimestamp,
    next_expected: &EntangledTimestamp,
    now: &EntangledTimestamp,
) -> CanaryState {
    let now_unix = now.unix_timestamp();
    let issued_unix = issued_at.unix_timestamp();
    let expected_unix = next_expected.unix_timestamp();

    if now_unix >= expected_unix {
        return CanaryState::Expired;
    }

    let interval = expected_unix.saturating_sub(issued_unix);
    let ten_percent = interval / 10;
    let near_window = ten_percent.max(NEAR_EXPIRATION_FLOOR_SECS);

    let remaining = expected_unix - now_unix;
    if remaining <= near_window {
        CanaryState::NearExpiration
    } else {
        CanaryState::Fresh
    }
}

/// Stage 8 structural validation of a canary. Emits `E_CANARY_INVALID` on
/// any structural violation.
pub fn validate_canary_structure(
    canary: &Canary,
    now: &EntangledTimestamp,
) -> Result<(EntangledTimestamp, EntangledTimestamp), Diagnostic> {
    // AMB-16: malformed canary timestamps are a Stage 8 canary-integrity
    // failure (E_CANARY_INVALID), not a Stage 5 schema/parse error. The
    // issued_at / next_expected fields deserialize leniently (MaybeTimestamp)
    // and are validated here, after Stage 6 has verified the signature.
    let issued_at = canary.issued_at.validate().map_err(|_| {
        Diagnostic::new(
            DiagnosticCode::ECanaryInvalid,
            DocumentKindLabel::Manifest,
            "canary.issued_at is not a valid YYYY-MM-DDTHH:MM:SSZ timestamp",
        )
    })?;
    let next_expected = canary.next_expected.validate().map_err(|_| {
        Diagnostic::new(
            DiagnosticCode::ECanaryInvalid,
            DocumentKindLabel::Manifest,
            "canary.next_expected is not a valid YYYY-MM-DDTHH:MM:SSZ timestamp",
        )
    })?;

    // (a) issued_at not too far in the future.
    check_future_timestamp(
        &issued_at,
        now,
        CANARY_ISSUED_AT_FIELD,
        DocumentKindLabel::Manifest,
    )?;

    // (b) next_expected strictly after issued_at.
    let issued_unix = issued_at.unix_timestamp();
    let expected_unix = next_expected.unix_timestamp();
    if expected_unix <= issued_unix {
        return Err(Diagnostic::new(
            DiagnosticCode::ECanaryInvalid,
            DocumentKindLabel::Manifest,
            "canary.next_expected must be strictly after canary.issued_at",
        ));
    }

    // (c) interval in the [7..=30] day range (§08:81; ceiling tightened
    // from 90 to 30 days in v1.0-rc.18, N42).
    let interval = expected_unix - issued_unix;
    if interval < CANARY_INTERVAL_MIN_SECS {
        return Err(Diagnostic::new(
            DiagnosticCode::ECanaryInvalid,
            DocumentKindLabel::Manifest,
            format!(
                "canary interval {interval}s is below the {CANARY_INTERVAL_MIN_SECS}s minimum (7 days)"
            ),
        ));
    }
    if interval > CANARY_INTERVAL_MAX_SECS {
        return Err(Diagnostic::new(
            DiagnosticCode::ECanaryInvalid,
            DocumentKindLabel::Manifest,
            format!(
                "canary interval {interval}s exceeds the {CANARY_INTERVAL_MAX_SECS}s maximum (30 days)"
            ),
        ));
    }

    // (d) §05 strict-profile validation of the embedded runtime pubkey.
    //
    // The signature pipeline only validates K_runtime when actually verifying
    // a content/transaction document under it (`verify_strict` rejects
    // small-order keys). Without this defensive check, a manifest declaring a
    // non-canonical or small-order runtime_pubkey would pass Stages 6/8/9
    // and the spec violation would surface only on the first content fetch.
    // Failing at canary structure time aligns the rejection point with
    // manifest acceptance.
    if validate_runtime_pubkey_strict(&canary.runtime_pubkey).is_err() {
        return Err(Diagnostic::new(
            DiagnosticCode::ECanaryInvalid,
            DocumentKindLabel::Manifest,
            "canary.runtime_pubkey fails the §05 strict profile (non-canonical or small-order)",
        )
        .with_details(serde_json::json!({
            "field_path": "canary.runtime_pubkey",
            "reason": "public_key_rejected",
        })));
    }

    Ok((issued_at, next_expected))
}

/// Anti-downgrade against publisher history (§08).
///
/// `newest_known` is the freshest `canary.issued_at` previously observed for
/// the same publisher pubkey. `None` means we have no history (first contact
/// or storage cleared).
///
/// The comparison is strict: equality is allowed (re-fetch of the same
/// manifest) and is policed separately by [`check_canary_conflict`] which
/// handles the equal-`issued_at` case. Only `new_issued_at < newest_known`
/// triggers `E_CANARY_DOWNGRADE` here.
///
/// `E_CANARY_DOWNGRADE` and `E_CANARY_CONFLICT` are mutually exclusive
/// (§08): the former applies when the fetched `issued_at` is strictly
/// older, the latter when it is equal but the signed payload differs.
pub fn check_anti_downgrade(
    new_issued_at: &EntangledTimestamp,
    newest_known: Option<&EntangledTimestamp>,
) -> Result<(), Diagnostic> {
    let Some(newest_known) = newest_known else {
        return Ok(());
    };
    if new_issued_at < newest_known {
        return Err(Diagnostic::new(
            DiagnosticCode::ECanaryDowngrade,
            DocumentKindLabel::Manifest,
            "canary.issued_at is older than the freshest pinned canary for this publisher",
        ));
    }
    Ok(())
}

/// Retained record of a previously verified manifest for a single
/// `K_publisher.pub`, supplied by the caller to [`check_canary_conflict`].
///
/// The 32-byte `manifest_payload_hash` is the SHA-256 digest of the
/// manifest's JCS-canonical signed payload (the bytes signed under
/// `K_publisher.pub` — i.e., the manifest object minus `sig`, with the
/// `kind` discriminator attached, then JCS-canonicalized). Two manifests
/// with the same `issued_at` but different `manifest_payload_hash` are a
/// conflict; two manifests with the same `manifest_payload_hash` are by
/// construction byte-equivalent and not a conflict (re-fetch). Persistence
/// of this record is the caller's responsibility.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedManifestRecord {
    /// `canary.issued_at` of the previously accepted manifest.
    pub issued_at: EntangledTimestamp,
    /// `canary.runtime_pubkey` of the previously accepted manifest.
    pub runtime_pubkey: RuntimePubkey,
    /// SHA-256 digest of the manifest's JCS-canonical signed payload.
    pub manifest_payload_hash: [u8; 32],
}

/// Equal-`issued_at` conflict check (§08).
///
/// A publisher MUST NOT issue two distinct manifests with the same
/// `canary.issued_at` for the same `K_publisher.pub`. A client that has
/// already accepted a manifest with `canary.issued_at = T` for
/// `K_publisher.pub = P` MUST reject any later manifest from any origin
/// with `canary.issued_at = T` for the same `P` whose JCS-canonical signed
/// payload differs (§08, §11 `E_CANARY_CONFLICT`).
///
/// Refetching the same manifest is permitted: a byte-for-byte equivalent
/// payload (matching `manifest_payload_hash`) is not a conflict.
///
/// Caller provides:
/// * `new_issued_at`, `new_runtime_pubkey`, `new_manifest_payload_hash` —
///   from the freshly fetched manifest;
/// * `retained` — the previously accepted record for the same
///   `K_publisher.pub`, or `None` if none.
///
/// Returns `Err` only when `retained.issued_at == new_issued_at` and the
/// new payload hash differs from the retained one. The diagnostic carries
/// `details = { issued_at, retained_runtime_pubkey, presented_runtime_pubkey }`
/// (§11).
///
/// # Reframing under §08 v1.0-rc.13
///
/// `E_CANARY_CONFLICT` is a **fault condition on the publisher
/// identity**, not a recoverable transient error. The client MUST NOT
/// pick a deterministic "winner" between conflicting manifests by
/// lexicographic comparison, payload size, `runtime_pubkey` value, or
/// any other tiebreaker over manifest content: a deterministic
/// tiebreaker is gameable by an attacker holding `K_publisher_priv`
/// and would mask the underlying fault.
///
/// The expected handling is:
/// * the retained pre-conflict manifest stays in place for current
///   rendering and anti-downgrade evaluation;
/// * the conflict is surfaced as a prominent chrome warning analogous
///   to Changed/mismatch, with an option to abandon the retained
///   publisher identity;
/// * the warning persists until the user explicitly resolves it.
///
/// Resolution is a chrome / trust-state concern outside this crate's
/// scope; this helper only emits the diagnostic.
pub fn check_canary_conflict(
    new_issued_at: &EntangledTimestamp,
    new_runtime_pubkey: &RuntimePubkey,
    new_manifest_payload_hash: &[u8; 32],
    retained: Option<&RetainedManifestRecord>,
) -> Result<(), Diagnostic> {
    let Some(retained) = retained else {
        return Ok(());
    };
    if &retained.issued_at != new_issued_at {
        return Ok(());
    }
    if &retained.manifest_payload_hash == new_manifest_payload_hash {
        return Ok(());
    }
    Err(Diagnostic::new(
        DiagnosticCode::ECanaryConflict,
        DocumentKindLabel::Manifest,
        "canary.issued_at matches a previously accepted manifest with a different signed payload",
    )
    .with_details(serde_json::json!({
        "issued_at": new_issued_at.to_string(),
        "retained_runtime_pubkey": retained.runtime_pubkey.to_string(),
        "presented_runtime_pubkey": new_runtime_pubkey.to_string(),
    })))
}

/// Stage 8 runtime-pubkey rotation-proof check (§08, rc.19 N55 + N60).
///
/// A new manifest's `canary.runtime_pubkey` MUST differ from the
/// immediately preceding verified manifest's `runtime_pubkey` for the
/// same `K_publisher.pub` (N55, MUST). Stateful clients that retain
/// publisher history SHOULD additionally reject reuse against any prior
/// entry in that history (N60, SHOULD), reporting the depth via
/// `details.window_position`.
///
/// Without this rule, a publisher (or attacker holding `K_runtime_priv`)
/// can maintain the same key indefinitely behind a stream of
/// fresh-looking canaries; with the SHOULD extension, an attacker also
/// cannot resurrect a key previously retired by ceremony discipline.
///
/// Arguments:
///
/// * `new_runtime_pubkey`, `new_issued_at` — fields of the freshly
///   verified manifest;
/// * `immediately_preceding` — the most recently retained manifest
///   record for the same `K_publisher.pub`, or `None` if none (first
///   contact). When `Some(r)` and `r.runtime_pubkey == new_runtime_pubkey`,
///   a MUST-level rejection fires with `window_position = 1`;
/// * `extended_history` — optional ordered history of prior manifests
///   for the same `K_publisher.pub`, *most-recent-first* and *excluding*
///   the immediately-preceding entry already supplied above. Empty for
///   stateless clients. When non-empty and any entry matches the new
///   pubkey, a SHOULD-level rejection fires with `window_position =
///   index_in_history + 2` (matching the §11 N60 schema where `1` is
///   the immediate-preceding match and `>= 2` walks backwards).
///
/// The MUST check fires before the SHOULD check. A client that does not
/// maintain extended history passes an empty slice; the MUST is still
/// enforced. The diagnostic carries `details = { runtime_pubkey,
/// previous_issued_at, current_issued_at, window_position }`.
pub fn check_runtime_pubkey_rotation(
    new_runtime_pubkey: &RuntimePubkey,
    new_issued_at: &EntangledTimestamp,
    immediately_preceding: Option<&RetainedManifestRecord>,
    extended_history: &[RetainedManifestRecord],
) -> Result<(), Diagnostic> {
    if let Some(prev) = immediately_preceding {
        if &prev.runtime_pubkey == new_runtime_pubkey {
            return Err(runtime_reuse_diagnostic(
                new_runtime_pubkey,
                &prev.issued_at,
                new_issued_at,
                1,
            ));
        }
    }
    for (idx, entry) in extended_history.iter().enumerate() {
        if &entry.runtime_pubkey == new_runtime_pubkey {
            // `idx == 0` is the entry one step behind the immediately
            // preceding one, i.e. window_position == 2.
            let window_position = idx + 2;
            return Err(runtime_reuse_diagnostic(
                new_runtime_pubkey,
                &entry.issued_at,
                new_issued_at,
                window_position,
            ));
        }
    }
    Ok(())
}

fn runtime_reuse_diagnostic(
    runtime_pubkey: &RuntimePubkey,
    previous_issued_at: &EntangledTimestamp,
    current_issued_at: &EntangledTimestamp,
    window_position: usize,
) -> Diagnostic {
    let message = if window_position == 1 {
        "canary.runtime_pubkey reuses the immediately preceding manifest's runtime key"
    } else {
        "canary.runtime_pubkey reuses a previously retired runtime key in publisher history"
    };
    Diagnostic::new(
        DiagnosticCode::ECanaryRuntimeReuse,
        DocumentKindLabel::Manifest,
        message,
    )
    .with_details(serde_json::json!({
        "runtime_pubkey": runtime_pubkey.to_string(),
        "previous_issued_at": previous_issued_at.to_string(),
        "current_issued_at": current_issued_at.to_string(),
        "window_position": window_position,
    }))
}
