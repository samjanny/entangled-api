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
    Fresh,
    NearExpiration,
    Expired,
    Invalid,
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
/// manifest), only `new_issued_at < newest_known` is a downgrade.
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
