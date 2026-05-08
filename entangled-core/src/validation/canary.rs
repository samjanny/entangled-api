//! Stage 8 canary state and structure validation (§08, §10).
//!
//! Three concerns live here:
//!
//! * [`compute_canary_state`] — pure time arithmetic; classifies a structurally
//!   valid canary into Fresh / NearExpiration / Expired given the current
//!   wall clock. Never returns `Invalid` or `Unavailable`.
//! * [`validate_canary_structure`] — Stage 8 structural checks: future-skew,
//!   ordering, and the [7..=90] day interval bound (§08).
//! * [`check_anti_downgrade`] — comparison against the most recent
//!   `issued_at` known for the same publisher pubkey in publisher history
//!   (§08 — "MUST NOT accept a canary older than the freshest one previously
//!   pinned for this publisher").
//!
//! String length caps for `statement` and `freshness_proof` are part of Stage
//! 5 schema validation and are not duplicated here.

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
    /// `now >= next_expected`.
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
pub fn compute_canary_state(canary: &Canary, now: &EntangledTimestamp) -> CanaryState {
    let now_unix = now.unix_timestamp();
    let issued_unix = canary.issued_at.unix_timestamp();
    let expected_unix = canary.next_expected.unix_timestamp();

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
) -> Result<(), Diagnostic> {
    // (a) issued_at not too far in the future.
    check_future_timestamp(
        &canary.issued_at,
        now,
        CANARY_ISSUED_AT_FIELD,
        DocumentKindLabel::Manifest,
    )?;

    // (b) next_expected strictly after issued_at.
    let issued_unix = canary.issued_at.unix_timestamp();
    let expected_unix = canary.next_expected.unix_timestamp();
    if expected_unix <= issued_unix {
        return Err(Diagnostic::new(
            DiagnosticCode::ECanaryInvalid,
            DocumentKindLabel::Manifest,
            "canary.next_expected must be strictly after canary.issued_at",
        ));
    }

    // (c) interval in the [7..=90] day range.
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
                "canary interval {interval}s exceeds the {CANARY_INTERVAL_MAX_SECS}s maximum (90 days)"
            ),
        ));
    }

    Ok(())
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
