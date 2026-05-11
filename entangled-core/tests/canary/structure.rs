//! `validate_canary_structure` — Stage 8 structural checks.

use entangled_core::types::canary::Canary;
use entangled_core::types::keys::RuntimePubkey;
use entangled_core::types::timestamp::EntangledTimestamp;
use entangled_core::validation::canary::validate_canary_structure;
use entangled_core::validation::DiagnosticCode;

use super::common::{runtime_key_real, KEY_ZEROS};

fn ts(s: &str) -> EntangledTimestamp {
    EntangledTimestamp::try_from(s).unwrap()
}

fn canary_with(issued: EntangledTimestamp, expected: EntangledTimestamp) -> Canary {
    Canary {
        // Strict-profile-clean runtime_pubkey; structural canary tests want
        // to exercise interval / ordering / future-skew without tripping the
        // §05 pubkey check.
        runtime_pubkey: runtime_key_real(),
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
    let expected = ts("2026-05-22T00:00:00Z");
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
    // 31 days > 30 day max (rc.18 N42 tightened from 90 to 30 days).
    let c = canary_with(ts("2026-04-06T00:00:00Z"), ts("2026-05-07T00:00:00Z"));
    let err = validate_canary_structure(&c, &now).expect_err("must reject");
    assert_eq!(err.code, DiagnosticCode::ECanaryInvalid);
}

#[test]
fn interval_max_boundary_accepted() {
    let now = ts("2026-05-07T00:00:00Z");
    // Exactly 30 days = 2592000s (rc.18 N42 ceiling).
    let c = canary_with(ts("2026-04-07T00:00:00Z"), ts("2026-05-07T00:00:00Z"));
    validate_canary_structure(&c, &now).expect("30-day boundary accepted");
}

// -----------------------------------------------------------------------------
// §05 strict-profile validation of `canary.runtime_pubkey` (Stage 8).
//
// The pubkey check fires after timestamps and interval clear; a canary that
// is structurally fine in every other respect but declares a small-order
// runtime pubkey must still be rejected as `E_CANARY_INVALID`. Without this
// test, a regression that drops the strict check could only be caught at
// first content fetch (where `verify_strict` would surface the same key as
// `E_SIG_VERIFICATION`).
// -----------------------------------------------------------------------------

#[test]
fn small_order_runtime_pubkey_rejected_with_field_path_detail() {
    let now = ts("2026-05-07T00:00:00Z");
    // 32-zero-byte pubkey is a 4-torsion point on Ed25519 (small-order).
    let weak = RuntimePubkey::try_from(KEY_ZEROS).unwrap();
    let mut c = Canary {
        runtime_pubkey: weak,
        issued_at: ts("2026-05-01T00:00:00Z"),
        next_expected: ts("2026-05-31T00:00:00Z"),
        statement: "All clear.".to_owned(),
        freshness_proof: None,
    };
    let err = validate_canary_structure(&c, &now).expect_err("small-order key rejected");
    assert_eq!(err.code, DiagnosticCode::ECanaryInvalid);
    let details = err.details.as_ref().expect("details payload");
    assert_eq!(
        details["field_path"].as_str(),
        Some("canary.runtime_pubkey")
    );
    assert_eq!(details["reason"].as_str(), Some("public_key_rejected"));

    // Strict-clean key fixes only the pubkey violation, leaving the canary
    // otherwise unchanged. Confirms the rejection above was specifically the
    // pubkey check, not a side effect of one of the earlier conditions.
    c.runtime_pubkey = runtime_key_real();
    validate_canary_structure(&c, &now).expect("strict-clean key passes");
}
