//! `check_anti_downgrade` — comparison vs publisher history.

use entangled_core::types::timestamp::EntangledTimestamp;
use entangled_core::validation::canary::check_anti_downgrade;
use entangled_core::validation::DiagnosticCode;

fn ts(s: &str) -> EntangledTimestamp {
    EntangledTimestamp::try_from(s).unwrap()
}

#[test]
fn no_history_passes() {
    let new = ts("2026-05-07T00:00:00Z");
    check_anti_downgrade(&new, None).expect("must pass without history");
}

#[test]
fn equal_issued_at_passes() {
    let t = ts("2026-05-07T00:00:00Z");
    // Re-fetch of the same manifest: equality is allowed.
    check_anti_downgrade(&t, Some(&t)).expect("equality allowed");
}

#[test]
fn newer_issued_at_passes() {
    let older = ts("2026-05-01T00:00:00Z");
    let newer = ts("2026-05-07T00:00:00Z");
    check_anti_downgrade(&newer, Some(&older)).expect("must pass forward");
}

#[test]
fn older_issued_at_fails() {
    let newest_known = ts("2026-05-07T00:00:01Z");
    let new = ts("2026-05-07T00:00:00Z"); // 1s older
    let err = check_anti_downgrade(&new, Some(&newest_known)).expect_err("must fail");
    assert_eq!(err.code, DiagnosticCode::ECanaryDowngrade);
}
