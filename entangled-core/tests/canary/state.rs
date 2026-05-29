//! `compute_canary_state` — Fresh / NearExpiration / Expired classification.

use entangled_core::types::canary::Canary;
use entangled_core::types::keys::RuntimePubkey;
use entangled_core::types::timestamp::EntangledTimestamp;
use entangled_core::validation::canary::{compute_canary_state, CanaryState};

use super::common::KEY_ZEROS;

fn ts(s: &str) -> EntangledTimestamp {
    EntangledTimestamp::try_from(s).unwrap()
}

fn canary(issued_at: &str, next_expected: &str) -> Canary {
    Canary {
        runtime_pubkey: RuntimePubkey::try_from(KEY_ZEROS).unwrap(),
        issued_at: ts(issued_at).into(),
        next_expected: ts(next_expected).into(),
        statement: "All clear.".to_owned(),
        freshness_proof: None,
    }
}

// The canary fields are lenient MaybeTimestamp (AMB-16); these state tests use
// well-formed timestamps, so promote them before exercising the time arithmetic.
fn state_of(c: &Canary, now: &EntangledTimestamp) -> CanaryState {
    compute_canary_state(
        &c.issued_at.validate().unwrap(),
        &c.next_expected.validate().unwrap(),
        now,
    )
}

#[test]
fn fresh_well_inside_window() {
    // 30-day interval, now 1 day past issuance -> 29 days remaining,
    // near-window = max(3 days, 24h) = 3 days. Plenty of room.
    let c = canary("2026-04-30T00:00:00Z", "2026-05-30T00:00:00Z");
    let now = ts("2026-05-01T00:00:00Z");
    assert_eq!(state_of(&c, &now), CanaryState::Fresh);
}

#[test]
fn near_expiration_24h_floor() {
    // 30-day interval, now exactly 1 day before next_expected.
    // near-window = max(3 days, 24h) = 3 days, so 1 day remaining is well
    // inside the near window.
    let c = canary("2026-04-08T00:00:00Z", "2026-05-08T00:00:00Z");
    let now = ts("2026-05-07T00:00:00Z");
    assert_eq!(state_of(&c, &now), CanaryState::NearExpiration);
}

#[test]
fn near_expiration_ten_percent_rule() {
    // 30-day interval (max, rc.18 N42). 10% = 3 days, 24h floor = 1 day.
    // 2 days remaining: inside the 10% window and above the 24h floor —
    // so the 10%-of-interval rule (not the floor) is what triggers
    // NearExpiration.
    let c = canary("2026-04-07T00:00:00Z", "2026-05-07T00:00:00Z");
    let now = ts("2026-05-05T00:00:00Z"); // 2 days before next_expected
    assert_eq!(state_of(&c, &now), CanaryState::NearExpiration);
}

#[test]
fn fresh_to_near_boundary() {
    // 30-day interval. Near window = max(3 days, 24h) = 3 days.
    // Exactly 3 days remaining -> NearExpiration (boundary inclusive).
    let c = canary("2026-04-07T00:00:00Z", "2026-05-07T00:00:00Z");
    let now_at_boundary = ts("2026-05-04T00:00:00Z");
    assert_eq!(state_of(&c, &now_at_boundary), CanaryState::NearExpiration);
    // One second earlier -> still Fresh.
    let now_just_before = ts("2026-05-03T23:59:59Z");
    assert_eq!(state_of(&c, &now_just_before), CanaryState::Fresh);
}

#[test]
fn expired_after_next_expected() {
    let c = canary("2026-04-07T00:00:00Z", "2026-05-06T00:00:00Z");
    let now = ts("2026-05-07T00:00:00Z");
    assert_eq!(state_of(&c, &now), CanaryState::Expired);
}

#[test]
fn expired_at_exact_second() {
    let c = canary("2026-04-07T00:00:00Z", "2026-05-07T00:00:00Z");
    let now = ts("2026-05-07T00:00:00Z");
    assert_eq!(state_of(&c, &now), CanaryState::Expired);
}
