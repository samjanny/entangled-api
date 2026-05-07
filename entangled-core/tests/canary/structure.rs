//! `validate_canary_structure` — Stage 8 structural checks.

use entangled_core::types::canary::Canary;
use entangled_core::types::keys::RuntimePubkey;
use entangled_core::types::timestamp::EntangledTimestamp;
use entangled_core::validation::canary::validate_canary_structure;
use entangled_core::validation::DiagnosticCode;

use super::common::KEY_ZEROS;

fn ts(s: &str) -> EntangledTimestamp {
    EntangledTimestamp::try_from(s).unwrap()
}

fn canary_with(issued: EntangledTimestamp, expected: EntangledTimestamp) -> Canary {
    Canary {
        runtime_pubkey: RuntimePubkey::try_from(KEY_ZEROS).unwrap(),
        issued_at: issued,
        next_expected: expected,
        statement: "All clear.".to_owned(),
        freshness_proof: None,
    }
}

#[test]
fn valid_30_day_interval() {
    let now = ts("2026-05-07T00:00:00Z");
    let c = canary_with(ts("2026-05-01T00:00:00Z"), ts("2026-05-31T00:00:00Z"));
    validate_canary_structure(&c, &now).expect("must pass");
}

#[test]
fn issued_at_far_future_rejected() {
    let now = ts("2026-05-07T00:00:00Z");
    // 400s ahead of `now` -> beyond the 300s skew tolerance.
    let issued = ts("2026-05-07T00:06:40Z"); // +400s
    let expected = ts("2026-06-07T00:00:00Z");
    let c = canary_with(issued, expected);
    let err = validate_canary_structure(&c, &now).expect_err("must reject");
    assert_eq!(err.code, DiagnosticCode::ECanaryInvalid);
}

#[test]
fn issued_at_near_future_within_skew() {
    let now = ts("2026-05-07T00:00:00Z");
    // 200s ahead -> inside the 300s tolerance.
    let issued = ts("2026-05-07T00:03:20Z"); // +200s
    let expected = ts("2026-06-08T00:00:00Z");
    let c = canary_with(issued, expected);
    validate_canary_structure(&c, &now).expect("within skew tolerance");
}

#[test]
fn next_expected_not_after_issued_rejected() {
    let now = ts("2026-05-07T00:00:00Z");
    let c = canary_with(ts("2026-05-07T00:00:00Z"), ts("2026-05-07T00:00:00Z"));
    let err = validate_canary_structure(&c, &now).expect_err("must reject");
    assert_eq!(err.code, DiagnosticCode::ECanaryInvalid);
}

#[test]
fn interval_too_short_rejected() {
    let now = ts("2026-05-07T00:00:00Z");
    // 6 days < 7 day minimum.
    let c = canary_with(ts("2026-05-01T00:00:00Z"), ts("2026-05-07T00:00:00Z"));
    let err = validate_canary_structure(&c, &now).expect_err("must reject");
    assert_eq!(err.code, DiagnosticCode::ECanaryInvalid);
}

#[test]
fn interval_min_boundary_accepted() {
    let now = ts("2026-05-07T00:00:00Z");
    // Exactly 7 days = 604800s.
    let c = canary_with(ts("2026-05-01T00:00:00Z"), ts("2026-05-08T00:00:00Z"));
    validate_canary_structure(&c, &now).expect("7-day boundary accepted");
}

#[test]
fn interval_too_long_rejected() {
    let now = ts("2026-05-07T00:00:00Z");
    // 91 days > 90 day max.
    let c = canary_with(ts("2026-02-05T00:00:00Z"), ts("2026-05-07T00:00:00Z"));
    let err = validate_canary_structure(&c, &now).expect_err("must reject");
    assert_eq!(err.code, DiagnosticCode::ECanaryInvalid);
}

#[test]
fn interval_max_boundary_accepted() {
    let now = ts("2026-05-07T00:00:00Z");
    // Exactly 90 days = 7776000s.
    let c = canary_with(ts("2026-02-06T00:00:00Z"), ts("2026-05-07T00:00:00Z"));
    validate_canary_structure(&c, &now).expect("90-day boundary accepted");
}
