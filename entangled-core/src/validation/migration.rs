//! Stage 9 origin-migration and origin-not-after handling
//! (§10 v1.0-rc.14; details schema extended in v1.0-rc.15).
//!
//! When an announcing manifest carries a `migration_pointer`, a client
//! supporting publisher profiles fetches the successor manifest from
//! `successor_origin.address` and runs the full Stages 1-9 pipeline on
//! it. The publisher-identity continuity check belongs at Stage 9: the
//! successor manifest's `publisher_pubkey` MUST byte-equal the
//! announcing manifest's `publisher_pubkey`. A mismatch is reported as
//! `E_MIGRATION_MISMATCH` and the announcement is rejected.
//!
//! rc.14 adds two further Stage 9 concerns handled by this module:
//!
//! * [`check_origin_not_after`] — the `origin.not_after` expiry check.
//!   Runs after carrier origin binding succeeds; rejects a manifest whose
//!   declared `not_after` is at or before the client's clock under §10
//!   clock-skew tolerance with `E_ORIGIN_EXPIRED`.
//! * [`check_migration_chain_cycle`] — the per-flow `visited_origins`
//!   cycle guard. A `migration_pointer.successor_origin.address` that is
//!   already present in the navigation's `visited_origins` set is
//!   rejected as `E_MIGRATION_INVALID` with `details.reason =
//!   "chain_cycle"`. The depth-limit policy that complements this cycle
//!   guard is a client-chrome concern (user-confirmation cadence, see
//!   §10) and is out of scope for this crate.
//!
//! rc.15 extends the `E_MIGRATION_MISMATCH` `details` schema additively:
//!
//! * `mismatch_field` gains the value `"successor_stage9_failure"`,
//!   reported when the successor manifest fails any Stage 1-9 check
//!   independently of the migration-binding fields (publisher pubkey,
//!   address, origin pubkey);
//! * optional field `underlying_diagnostic` is attached only in that case
//!   and carries the structured diagnostic the successor's own pipeline
//!   would have raised in isolation;
//! * `successor_publisher_pubkey` is scoped to cases where the
//!   successor's own Stage 5 schema validation succeeded; for earlier
//!   stages there is no validated key to report. Wrapping a Stage 1-9
//!   failure into `E_MIGRATION_MISMATCH` is the job of
//!   [`wrap_successor_stage9_failure`].
//!
//! Structural well-formedness of the announcing manifest's
//! `migration_pointer` (self-pointing address, carrier mismatch,
//! `announced_at` after `updated`, semantic constraints on `not_after`)
//! is a Stage 5 schema concern handled by
//! [`crate::validation::schema::validate_migration_pointer`] and
//! [`crate::validation::schema::validate_origin_not_after`], reported as
//! `E_MIGRATION_INVALID` or `E_ORIGIN_INVALID` respectively.

use std::collections::HashSet;

use serde_json::{Map, Value};

use crate::types::keys::PublisherPubkey;
use crate::types::manifest::{Manifest, MigrationPointer, OnionAddress};
use crate::types::EntangledTimestamp;
use crate::validation::diagnostic::{Diagnostic, DiagnosticCode, DocumentKindLabel};
use crate::validation::limits::CLOCK_SKEW_TOLERANCE_SECS;

/// Verify a migration announcement: the successor manifest's
/// `publisher_pubkey` MUST equal the announcing manifest's
/// `publisher_pubkey`.
///
/// Returns `E_MIGRATION_MISMATCH` (§11 rc.13; `details` schema updated
/// in rc.15) on divergence, with `details` carrying the announced
/// successor address, the two publisher pubkeys, and
/// `mismatch_field: "publisher_pubkey"`. Both manifests are expected
/// to have already cleared their own Stages 1-9 pipelines; this helper
/// performs only the publisher-identity continuity check.
///
/// For wrapping a successor Stage 1-9 failure into a migration-level
/// rejection — for example, a successor whose own `origin.not_after`
/// has passed, or whose signature fails verification — see
/// [`wrap_successor_stage9_failure`].
///
/// # Errors
///
/// `E_MIGRATION_MISMATCH` when the successor's `publisher_pubkey` does
/// not byte-equal the announcing manifest's `publisher_pubkey`.
pub fn verify_migration_announcement(
    announcing: &Manifest,
    successor: &Manifest,
) -> Result<(), Diagnostic> {
    if announcing.publisher_pubkey != successor.publisher_pubkey {
        return Err(Diagnostic::new(
            DiagnosticCode::EMigrationMismatch,
            DocumentKindLabel::Manifest,
            "successor manifest publisher_pubkey does not match announcing publisher_pubkey",
        )
        .with_details(serde_json::json!({
            "mismatch_field": "publisher_pubkey",
            "announced_successor_address": successor.origin.address.as_str(),
            "announcing_publisher_pubkey": announcing.publisher_pubkey.to_string(),
            "successor_publisher_pubkey": successor.publisher_pubkey.to_string(),
        })));
    }
    Ok(())
}

/// Wrap a successor-manifest Stage 1-9 failure into an
/// `E_MIGRATION_MISMATCH` diagnostic (§11 v1.0-rc.15).
///
/// When the successor manifest fetched from the announced address fails
/// any check during its own Stages 1-9 — independently of the
/// migration-binding facets (`publisher_pubkey`, `address`,
/// `origin_pubkey`) — the migration is rejected at the announcement
/// level as `E_MIGRATION_MISMATCH`, but the underlying cause is
/// preserved in `details.underlying_diagnostic` so operators can tell
/// "the successor address is wired to the wrong key" apart from "the
/// successor manifest itself is broken" without an out-of-band lookup.
///
/// The returned diagnostic carries:
///
/// * `mismatch_field: "successor_stage9_failure"`;
/// * `underlying_diagnostic`: the structured payload of the original
///   failure (code, stage, severity, document_kind, message, details);
/// * `announced_successor_address`: the address declared by
///   `migration_pointer.successor_origin.address`;
/// * `announcing_publisher_pubkey`: the announcing manifest's
///   `publisher_pubkey`;
/// * `successor_publisher_pubkey`: the successor manifest's
///   `publisher_pubkey` — **only when supplied**, per rc.15. Callers
///   that are wrapping a Stage 1-4 failure (the successor has not yet
///   cleared schema validation, so no validated pubkey is available)
///   MUST pass `None`; callers wrapping a Stage 5-9 failure pass the
///   pubkey already read from the successor manifest.
///
/// The migration is rejected regardless of the underlying cause; the
/// `underlying_diagnostic` field is informational only.
pub fn wrap_successor_stage9_failure(
    announcing: &Manifest,
    announced_successor_address: &OnionAddress,
    successor_publisher_pubkey: Option<&PublisherPubkey>,
    underlying: &Diagnostic,
) -> Diagnostic {
    let mut details = Map::new();
    details.insert(
        "mismatch_field".to_owned(),
        Value::String("successor_stage9_failure".to_owned()),
    );
    details.insert(
        "announced_successor_address".to_owned(),
        Value::String(announced_successor_address.as_str().to_owned()),
    );
    details.insert(
        "announcing_publisher_pubkey".to_owned(),
        Value::String(announcing.publisher_pubkey.to_string()),
    );
    if let Some(pk) = successor_publisher_pubkey {
        details.insert(
            "successor_publisher_pubkey".to_owned(),
            Value::String(pk.to_string()),
        );
    }
    details.insert(
        "underlying_diagnostic".to_owned(),
        serde_json::to_value(underlying)
            .expect("Diagnostic is Serialize and contains only JSON-safe values"),
    );

    Diagnostic::new(
        DiagnosticCode::EMigrationMismatch,
        DocumentKindLabel::Manifest,
        format!(
            "successor manifest at {} failed its own Stage {} check ({}): migration rejected",
            announced_successor_address.as_str(),
            underlying.stage,
            underlying.code,
        ),
    )
    .with_details(Value::Object(details))
}

/// Stage 9 expiry check for `origin.not_after` (§06 / §10 v1.0-rc.14;
/// symmetric clock-skew formula codified in v1.0-rc.15).
///
/// Returns `E_ORIGIN_EXPIRED` when `now > not_after +
/// CLOCK_SKEW_TOLERANCE_SECS`. §10 rc.15 makes the past-bound
/// tolerance an explicit mirror of the future-bound tolerance already
/// applied to `manifest.updated` and `canary.issued_at`: a 300-second
/// margin in the publisher's favour absorbs both client clocks running
/// slightly fast and the publishing delay of a successor manifest near
/// the declared instant. Manifests without `origin.not_after`, or
/// whose declared `not_after` is still in the future (modulo
/// tolerance), return `Ok(())`.
///
/// The Stage 9 ordering rule applies: callers MUST run this check only
/// after [`crate::tor::verify_origin_binding`] has cleared carrier origin
/// binding. The function does not re-check the §06 semantic constraints
/// on `not_after`; those are Stage 5 and reported as `E_ORIGIN_INVALID`
/// from [`crate::validation::schema::validate_origin_not_after`].
///
/// Anti-downgrade is unaffected: an expired manifest does not become a
/// downgrade target for newer manifests, and a newer manifest from the
/// same `K_publisher.pub` supersedes it under the standard anti-downgrade
/// rule (§08).
///
/// # Errors
///
/// `E_ORIGIN_EXPIRED` when `now > not_after + CLOCK_SKEW_TOLERANCE_SECS`.
/// `details` carries the declared `not_after` and the `now` value used
/// for the comparison per §11.
pub fn check_origin_not_after(
    manifest: &Manifest,
    now: &EntangledTimestamp,
) -> Result<(), Diagnostic> {
    let Some(not_after) = manifest.origin.not_after else {
        return Ok(());
    };

    // §10 rc.15: rejection formula is `current_time > timestamp + 300s`,
    // the symmetric past-bound counterpart of the future-bound check
    // applied to `manifest.updated` and `canary.issued_at`. `now` within
    // `+CLOCK_SKEW_TOLERANCE_SECS` of `not_after` is treated as
    // not-yet-expired.
    let delta = now.unix_timestamp() - not_after.unix_timestamp();
    if delta <= CLOCK_SKEW_TOLERANCE_SECS {
        return Ok(());
    }

    Err(Diagnostic::new(
        DiagnosticCode::EOriginExpired,
        DocumentKindLabel::Manifest,
        format!(
            "origin.not_after {not_after} is {delta}s in the past, beyond clock-skew tolerance of {CLOCK_SKEW_TOLERANCE_SECS}s"
        ),
    )
    .with_details(serde_json::json!({
        "field_path": "origin.not_after",
        "reason": "origin_expired",
        "not_after": not_after.to_string(),
        "now": now.to_string(),
        "skew_tolerance_seconds": CLOCK_SKEW_TOLERANCE_SECS,
    })))
}

/// Stage 9 chain-cycle guard for `migration_pointer` (§10 v1.0-rc.14).
///
/// A client supporting publisher profiles maintains, for the duration of
/// a single migration-resolution flow, a `visited_origins` set containing
/// the address of every origin visited in that flow, beginning with the
/// announcing origin. Before adopting a successor announced by
/// `migration_pointer.successor_origin.address`, the client MUST check
/// that the address is not already present in `visited_origins`. A
/// successor address already in the set is a chain cycle and MUST be
/// rejected as `E_MIGRATION_INVALID` with `details.reason = "chain_cycle"`.
///
/// On `Ok(())` the helper returns the updated `visited_origins` with the
/// successor address inserted, so the caller can thread the set through
/// the next hop. The set itself is per-navigation and per-publisher
/// profile; reset / persistence policy lives with the caller (per §10,
/// the set is not persisted across sessions).
///
/// The complementary `MUST` from §10 — the automatic chain-depth limit
/// (at most one hop without user re-confirmation) — is a client-chrome
/// concern (user confirmation cadence, high-threat mode override) and is
/// not enforced by this crate.
///
/// # Errors
///
/// `E_MIGRATION_INVALID` with `details.reason = "chain_cycle"` when
/// `mp.successor_origin.address` is already present in `visited_origins`.
pub fn check_migration_chain_cycle(
    mp: &MigrationPointer,
    visited_origins: &mut HashSet<OnionAddress>,
) -> Result<(), Diagnostic> {
    let successor = &mp.successor_origin.address;
    if visited_origins.contains(successor) {
        return Err(Diagnostic::new(
            DiagnosticCode::EMigrationInvalid,
            DocumentKindLabel::Manifest,
            "migration_pointer.successor_origin.address is already in visited_origins (chain cycle)",
        )
        .with_details(serde_json::json!({
            "field_path": "migration_pointer.successor_origin.address",
            "reason": "chain_cycle",
            "successor_address": successor.as_str(),
        })));
    }
    visited_origins.insert(successor.clone());
    Ok(())
}
