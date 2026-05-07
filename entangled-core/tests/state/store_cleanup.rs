//! Garbage-collection helpers: cleanup_expired, clear_publisher,
//! clear_session.

use entangled_core::state::{ConsentDecision, StateStore};
use entangled_core::types::state::StateMode;

use crate::helpers::{pub_from_seed, set_op, ts};

const ACCEPTED: ConsentDecision = ConsentDecision {
    accepted: true,
    remembered: false,
};

#[test]
fn cleanup_expired_removes_expired_entries() {
    let pub_a = pub_from_seed(51);
    let now = ts("2026-05-07T00:00:00Z");
    let mut store = StateStore::new();

    for (i, ttl) in [300u32, 600, 900, 1200, 1500].iter().enumerate() {
        store
            .set(
                &pub_a,
                &set_op("ns", &format!("k{i}"), "v", *ttl),
                StateMode::Request,
                ACCEPTED,
                &now,
            )
            .unwrap();
    }

    // After 700s, ttl 300 and 600 are expired (≥ expires_at).
    let after = ts("2026-05-07T00:11:40Z");
    let removed = store.cleanup_expired(&after);
    assert_eq!(removed, 2);
    assert_eq!(store.bytes_used_for_publisher(&pub_a, &after), 3 * (1 + 4));
}

#[test]
fn clear_publisher_only_removes_targeted_publisher() {
    let pub_a = pub_from_seed(52);
    let pub_b = pub_from_seed(53);
    let now = ts("2026-05-07T00:00:00Z");
    let mut store = StateStore::new();

    store
        .set(
            &pub_a,
            &set_op("ns", "k", "v", 600),
            StateMode::Request,
            ACCEPTED,
            &now,
        )
        .unwrap();
    store
        .set(
            &pub_b,
            &set_op("ns", "k", "v", 600),
            StateMode::Request,
            ACCEPTED,
            &now,
        )
        .unwrap();

    let removed = store.clear_publisher(&pub_a);
    assert_eq!(removed, 1);
    assert_eq!(store.bytes_used_for_publisher(&pub_a, &now), 0);
    assert!(store.bytes_used_for_publisher(&pub_b, &now) > 0);
}

#[test]
fn clear_session_removes_everything() {
    let pub_a = pub_from_seed(54);
    let pub_b = pub_from_seed(55);
    let now = ts("2026-05-07T00:00:00Z");
    let mut store = StateStore::new();

    store
        .set(
            &pub_a,
            &set_op("ns", "k", "v", 600),
            StateMode::Request,
            ACCEPTED,
            &now,
        )
        .unwrap();
    store
        .set(
            &pub_b,
            &set_op("ns", "k", "v", 600),
            StateMode::ClientOnly,
            ACCEPTED,
            &now,
        )
        .unwrap();

    let removed = store.clear_session();
    assert_eq!(removed, 2);
    assert_eq!(store.bytes_used_for_publisher(&pub_a, &now), 0);
    assert_eq!(store.bytes_used_for_publisher(&pub_b, &now), 0);
}
