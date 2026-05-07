//! Clock-skew tolerance helper (§10).
//!
//! §10 normatively bounds the future-direction clock skew at
//! [`CLOCK_SKEW_TOLERANCE_SECS`] (300 seconds). A timestamp more than that
//! ahead of the local clock MUST be rejected.
//!
//! The helper is shared by Stage 5 (`manifest.updated`) and Stage 8
//! (`canary.issued_at`), but the diagnostic code differs by call site:
//! `manifest.updated` is a generic out-of-range field, `canary.issued_at` is
//! semantically a canary integrity failure.
//!
//! This helper rejects future skew only. Past timestamps are always accepted
//! here — they may be editorial (`meta.published_at` is historical) or
//! re-fetched (`canary.issued_at` for an unchanged canary). Per-field rules
//! that further constrain "how far in the past" live with the field's other
//! validations (e.g. anti-downgrade in [`super::canary`]).

use crate::types::EntangledTimestamp;
use crate::validation::diagnostic::{Diagnostic, DiagnosticCode, DocumentKindLabel};
use crate::validation::limits::CLOCK_SKEW_TOLERANCE_SECS;

/// Field name discriminator for [`check_future_timestamp`]. Matching on the
/// literal string keeps this helper boundary-free with respect to the rest of
/// the validation crate.
pub const CANARY_ISSUED_AT_FIELD: &str = "canary.issued_at";

/// Reject `ts` if it is more than [`CLOCK_SKEW_TOLERANCE_SECS`] ahead of `now`.
///
/// Past timestamps (`ts <= now`) are accepted unconditionally. The boundary is
/// inclusive: exactly `+300` seconds is fine, `+301` seconds is not.
///
/// The diagnostic code depends on `field_name` because §10 does not pick a
/// single code for "timestamp too far in the future" — it borrows the
/// closest-fit code for the field being checked:
///
/// * `canary.issued_at` → `E_CANARY_INVALID` (Stage 8 — canary integrity).
/// * any other field → `E_SCHEMA_FIELD_RANGE` (Stage 5 — value out of range).
pub fn check_future_timestamp(
    ts: &EntangledTimestamp,
    now: &EntangledTimestamp,
    field_name: &'static str,
    document_kind: DocumentKindLabel,
) -> Result<(), Diagnostic> {
    let delta = ts.unix_timestamp() - now.unix_timestamp();
    if delta <= CLOCK_SKEW_TOLERANCE_SECS {
        return Ok(());
    }

    let code = if field_name == CANARY_ISSUED_AT_FIELD {
        DiagnosticCode::ECanaryInvalid
    } else {
        DiagnosticCode::ESchemaFieldRange
    };

    Err(Diagnostic::new(
        code,
        document_kind,
        format!(
            "{field_name} is {delta}s in the future, exceeds clock-skew tolerance of {CLOCK_SKEW_TOLERANCE_SECS}s"
        ),
    ))
}
