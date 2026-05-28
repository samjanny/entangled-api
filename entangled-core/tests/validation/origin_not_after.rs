//! Stage 9 origin-not-after expiry and migration chain-cycle guard
//! (§06 / §10 v1.0-rc.14).
//!
//! Stage 5 (semantic constraints on `origin.not_after`) is exercised by
//! `stage5_schema.rs`. This file targets the Stage 9 helpers exported
//! from `crate::validation`:
//!
//! * `check_origin_not_after` — E_ORIGIN_EXPIRED on expired manifests,
//!   honouring the §10 clock-skew tolerance in the publisher's favour.
//! * `check_migration_chain_cycle` — E_MIGRATION_INVALID with
//!   `details.reason = "chain_cycle"` when the announced successor
//!   address is already in the per-flow `visited_origins` set; on
//!   acceptance the helper inserts the address so the caller can thread
//!   the set through the next hop.

use std::collections::HashSet;

use entangled_core::types::manifest::{Carrier, Manifest, MigrationPointer, OnionAddress, Origin};
use entangled_core::validation::{
    check_migration_chain_cycle, check_origin_not_after, DiagnosticCode,
};

use super::common::{minimal_manifest, ts};

const SUCCESSOR_ADDR: &str = "ssssssssssssssssssssssssssssssssssssssssssssssssssssssss.onion";
const ALT_ADDR: &str = "tttttttttttttttttttttttttttttttttttttttttttttttttttttttt.onion";

fn manifest_with_not_after(not_after: Option<&str>) -> Manifest {
    let mut m = minimal_manifest();
    m.origin.not_after = not_after.map(ts);
    m
}

#[test]
fn not_after_absent_accepts() {
    let m = manifest_with_not_after(None);
    check_origin_not_after(&m, &ts("2099-01-01T00:00:00Z"))
        .expect("absent origin.not_after must accept any now");
}

#[test]
fn not_after_in_future_accepts() {
    let m = manifest_with_not_after(Some("2027-05-07T00:00:00Z"));
    check_origin_not_after(&m, &ts("2026-05-07T00:00:00Z"))
        .expect("not_after strictly in the future must accept");
}

#[test]
fn not_after_within_skew_tolerance_accepts() {
    // The clock-skew tolerance applies in the publisher's favour: a `now`
    // up to 300 s past `not_after` is still treated as not-yet-expired.
    let m = manifest_with_not_after(Some("2026-05-07T00:00:00Z"));
    check_origin_not_after(&m, &ts("2026-05-07T00:05:00Z"))
        .expect("now == not_after + 300s is within tolerance");
}

#[test]
fn not_after_beyond_skew_rejected_with_e_origin_expired() {
    // 301 s past `not_after` exceeds the tolerance: rejection.
    let m = manifest_with_not_after(Some("2026-05-07T00:00:00Z"));
    let err = check_origin_not_after(&m, &ts("2026-05-07T00:05:01Z"))
        .expect_err("now > not_after + tolerance must reject");
    assert_eq!(err.code, DiagnosticCode::EOriginExpired);
    let details = err.details.as_ref().expect("details payload");
    assert_eq!(details["field_path"].as_str(), Some("origin.not_after"));
    assert_eq!(details["reason"].as_str(), Some("origin_expired"));
    // `not_after` is publisher-declared and exposed as-is.
    assert_eq!(details["not_after"].as_str(), Some("2026-05-07T00:00:00Z"));
    // §11 v1.0-rc.18 (N18): `details.now` is rounded down to minute
    // precision so the diagnostic does not leak sub-minute clock skew
    // if forwarded to third parties.
    assert_eq!(details["now"].as_str(), Some("2026-05-07T00:05:00Z"));
}

#[test]
fn not_after_far_in_the_past_rejected() {
    let m = manifest_with_not_after(Some("2020-01-01T00:00:00Z"));
    let err = check_origin_not_after(&m, &ts("2026-05-07T00:00:00Z"))
        .expect_err("years-old not_after must reject");
    assert_eq!(err.code, DiagnosticCode::EOriginExpired);
}

#[test]
fn details_now_rounds_down_at_seconds_59_boundary() {
    // §11 v1.0-rc.18 (N18): `details.now` rounds *down* to minute
    // precision. The same-minute boundary case — :59 truncated to :00 —
    // is the one most likely to surface a bug if rounding were
    // mis-implemented as nearest-minute or as truncation of the minute.
    let m = manifest_with_not_after(Some("2026-05-07T00:00:00Z"));
    let err = check_origin_not_after(&m, &ts("2026-05-07T00:10:59Z"))
        .expect_err("10m59s past not_after must reject");
    let details = err.details.as_ref().expect("details payload");
    assert_eq!(details["now"].as_str(), Some("2026-05-07T00:10:00Z"));
}

fn pointer_to(addr: &str) -> MigrationPointer {
    MigrationPointer {
        successor_origin: Origin {
            carrier: Carrier::TorV3,
            address: OnionAddress::try_from(addr).unwrap(),
            origin_pubkey: minimal_manifest().origin.origin_pubkey,
            not_after: None,
        },
        announced_at: ts("2026-05-06T00:00:00Z"),
    }
}

const ANNOUNCING_ADDR: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";

#[test]
fn chain_cycle_helper_threads_visited_set() {
    // Initial set seeded with the announcing origin (per §10): no successor
    // address is in the set yet, so the first hop succeeds and the helper
    // inserts the successor for the next hop.
    let announcing = OnionAddress::try_from(ANNOUNCING_ADDR).unwrap();
    let mut visited = HashSet::from([announcing.clone()]);
    let mp_first = pointer_to(SUCCESSOR_ADDR);
    check_migration_chain_cycle(&mp_first, &announcing, &mut visited)
        .expect("first hop to fresh successor must accept");
    assert!(visited.contains(&OnionAddress::try_from(SUCCESSOR_ADDR).unwrap()));

    // A subsequent hop to a different address still succeeds and extends
    // the set. The announcing origin for the second hop is the previously
    // adopted successor.
    let announcing_second = OnionAddress::try_from(SUCCESSOR_ADDR).unwrap();
    let mp_second = pointer_to(ALT_ADDR);
    check_migration_chain_cycle(&mp_second, &announcing_second, &mut visited)
        .expect("hop to a previously-unvisited successor must accept");
    assert!(visited.contains(&OnionAddress::try_from(ALT_ADDR).unwrap()));
}

#[test]
fn chain_cycle_rejects_revisited_address() {
    let announcing = OnionAddress::try_from(ANNOUNCING_ADDR).unwrap();
    let mut visited = HashSet::new();
    visited.insert(OnionAddress::try_from(SUCCESSOR_ADDR).unwrap());

    let mp = pointer_to(SUCCESSOR_ADDR);
    let err = check_migration_chain_cycle(&mp, &announcing, &mut visited)
        .expect_err("successor already in visited_origins must reject");
    assert_eq!(err.code, DiagnosticCode::EMigrationInvalid);
    let details = err.details.as_ref().expect("details payload");
    assert_eq!(details["reason"].as_str(), Some("chain_cycle"));
    // rc.19 N57: structured details carry both endpoint addresses.
    assert_eq!(
        details["announcing_origin_address"].as_str(),
        Some(ANNOUNCING_ADDR)
    );
    assert_eq!(
        details["successor_origin_address"].as_str(),
        Some(SUCCESSOR_ADDR)
    );
    assert_eq!(
        details["field_path"].as_str(),
        Some("migration_pointer.successor_origin.address")
    );
}

#[test]
fn chain_cycle_does_not_insert_on_rejection() {
    // The helper inserts only on acceptance: a rejection leaves the set
    // unchanged so the caller's higher-level flow can rely on it.
    let announcing = OnionAddress::try_from(ANNOUNCING_ADDR).unwrap();
    let mut visited = HashSet::new();
    visited.insert(OnionAddress::try_from(SUCCESSOR_ADDR).unwrap());
    let before = visited.clone();

    let mp = pointer_to(SUCCESSOR_ADDR);
    let _ = check_migration_chain_cycle(&mp, &announcing, &mut visited);
    assert_eq!(visited, before);
}
