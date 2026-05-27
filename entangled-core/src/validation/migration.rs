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
//! rc.15 extends the `E_MIGRATION_MISMATCH` `details` schema additively;
//! rc.16 renames one field for clarity:
//!
//! * `mismatch_field` gains the value `"successor_stage9_failure"` (rc.15),
//!   reported when the successor manifest fails any Stage 1-9 check
//!   independently of the migration-binding fields (publisher pubkey,
//!   address, origin pubkey);
//! * optional field `underlying_diagnostic_code` (rc.16; the rc.15 field
//!   `underlying_diagnostic` is renamed for clarity) is attached only in
//!   that case and carries the **code identifier string** the successor's
//!   own pipeline would have raised in isolation (e.g.
//!   `"E_ORIGIN_EXPIRED"`, `"E_SIG_VERIFICATION"`). It does **not** nest
//!   the successor's full structured diagnostic record; operators wanting
//!   to inspect the successor's own `details` fetch the successor
//!   manifest in isolation and observe the diagnostic produced by the
//!   standard pipeline;
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
//!
//! # Cross-session migration history (§10 v1.0-rc.16, N20; tightened
//! in v1.0-rc.18, N30 & N31; elevated to MUST in v1.0-rc.19, N50)
//!
//! rc.16 introduced a SHOULD-level mitigation for cross-session migration
//! ping-pong cycles (`A → B` in one session, `B → A` in the next, with
//! the per-flow `visited_origins` set freshly empty each navigation).
//!
//! rc.18 closes two gaps in the rc.16 rule:
//!
//! * **N30 — Replacement event covers the pre-Adoption current origin.**
//!   The rc.16 wording recorded a `Replacement` event only when a
//!   previously adopted successor was itself superseded, which left the
//!   `A → B → A → B` ping-pong detectable in only one direction (the
//!   original starting origin `A` was never marked replaced before the
//!   first hop). Under rc.18 the `Replacement` event MUST also be
//!   recorded at every Adoption against the pre-Adoption current origin
//!   (the announcing origin), so a later announcement of `A` as a
//!   successor triggers the recall check.
//! * **N31 — recall-window upper bound.** The recommended 30-day window
//!   gains an explicit SHOULD-NOT-exceed of 365 days. Clients with
//!   bounded storage MAY enforce a smaller cap, whether by time or by
//!   event count (e.g. the most recent 100 migration events per
//!   publisher profile, evicting the oldest first), provided the cap
//!   remains at or above the 7-day floor. Bounds migration-history
//!   storage per publisher profile.
//!
//! **rc.19 (N50)** elevates all SHOULD-level migration-history
//! requirements to MUST. Implementations MUST record Adoption and
//! Replacement events, MUST persist them across sessions (volatile-only
//! storage is non-conformant), and MUST consult the recall window
//! (30-day recommended, 7-day MUST floor, 365-day MUST ceiling, zero
//! not permitted) when processing new migration announcements. The
//! storage backend (serialization format, database technology) remains
//! implementation-defined; cross-session persistence is required.
//!
//! This is a trust-state-machine concern (publisher history persistence,
//! user dialog content) and remains the caller's responsibility; this
//! crate does not maintain publisher history. v1.0 leaves the storage
//! backend unspecified. The per-flow [`check_migration_chain_cycle`]
//! guard (MUST) and per-publisher migration history (MUST since rc.19)
//! are independent mitigations: the former rejects intra-flow cycles
//! outright; the latter raises friction without rejecting, since a
//! publisher legitimately rotating between addresses must remain
//! reachable.

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
/// `E_MIGRATION_MISMATCH` diagnostic (§11 v1.0-rc.15; field name
/// `underlying_diagnostic_code` per rc.16 clarification).
///
/// When the successor manifest fetched from the announced address fails
/// any check during its own Stages 1-9 — independently of the
/// migration-binding facets (`publisher_pubkey`, `address`,
/// `origin_pubkey`) — the migration is rejected at the announcement
/// level as `E_MIGRATION_MISMATCH`. The underlying failure's **code
/// identifier** (e.g. `"E_ORIGIN_EXPIRED"`, `"E_SIG_VERIFICATION"`) is
/// preserved in `details.underlying_diagnostic_code` so operators can
/// tell "the successor address is wired to the wrong key" apart from
/// "the successor manifest itself is broken" without an out-of-band
/// lookup. The code identifier is reported as a JSON string, not as the
/// full structured diagnostic record (rc.16 N22): an operator who needs
/// the successor's own `details` fetches the successor manifest in
/// isolation and observes the diagnostic produced by the standard
/// pipeline.
///
/// The returned diagnostic carries:
///
/// * `mismatch_field: "successor_stage9_failure"`;
/// * `underlying_diagnostic_code`: the §11 code identifier of the
///   successor's own diagnostic, as a JSON string;
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
/// `underlying_diagnostic_code` field is informational only.
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
        "underlying_diagnostic_code".to_owned(),
        Value::String(underlying.code.to_string()),
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

    // §11 v1.0-rc.18 (N18): `details.now` is rounded down to minute
    // precision (`YYYY-MM-DDTHH:MM:00Z`). The constraint limits any
    // clock-skew leak if the diagnostic is forwarded to third parties
    // (crash reports, support channels) without compromising the
    // diagnostic's usefulness for clock-skew troubleshooting, where
    // minute-level resolution is sufficient. `not_after` is publisher-
    // declared and already exposed on the wire, so no rounding applies.
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
        "now": minute_precision_utc(now),
        "skew_tolerance_seconds": CLOCK_SKEW_TOLERANCE_SECS,
    })))
}

/// Format an [`EntangledTimestamp`] as RFC 3339 UTC with seconds zeroed
/// (`YYYY-MM-DDTHH:MM:00Z`). Implements the §11 v1.0-rc.18 minute-
/// precision constraint on `E_ORIGIN_EXPIRED.details.now`.
fn minute_precision_utc(ts: &EntangledTimestamp) -> String {
    let dt = ts.as_offset_date_time();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:00Z",
        dt.year(),
        u8::from(dt.month()),
        dt.day(),
        dt.hour(),
        dt.minute(),
    )
}

/// Stage 9 chain-cycle guard for `migration_pointer` (§10 v1.0-rc.14;
/// post-rejection state clarified in v1.0-rc.18, N21).
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
/// Per rc.18 (N21), a cycle rejection invalidates only the new
/// adoption: the most recently verified successor adopted earlier in
/// the same flow remains the current origin for the publisher profile,
/// and any cached manifests held for origins in `visited_origins` MAY
/// still be served from cache within their refresh policy. This helper
/// rejects the new hop without touching the caller's existing state.
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
