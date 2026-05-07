//! §07 "Stateless mode": the in-memory store accepts the same operations
//! and `clear_session` wipes everything.

use entangled_core::state::{ConsentDecision, StateStore};
use entangled_core::types::state::StateMode;

use crate::helpers::{pub_from_seed, set_op, slug, ts};

const ACCEPTED: ConsentDecision = ConsentDecision {
    accepted: true,
    remembered: false,
};

#[test]
fn stateless_supports_set_and_get() {
    let pub_a = pub_from_seed(61);
    let now = ts("2026-05-07T00:00:00Z");
    let mut store = StateStore::new_stateless();
    assert!(store.is_stateless());

    store
        .set(
            &pub_a,
            &set_op("session", "auth", "v", 600),
            StateMode::Request,
            ACCEPTED,
            &now,
        )
        .unwrap();
    assert!(store
        .get(&pub_a, &slug("session"), &slug("auth"), &now)
        .is_some());
}

#[test]
fn clear_session_wipes_everything_in_stateless() {
    let pub_a = pub_from_seed(62);
    let now = ts("2026-05-07T00:00:00Z");
    let mut store = StateStore::new_stateless();

    store
        .set(
            &pub_a,
            &set_op("session", "auth", "v", 600),
            StateMode::Request,
            ACCEPTED,
            &now,
        )
        .unwrap();
    let removed = store.clear_session();
    assert_eq!(removed, 1);
    assert!(store
        .get(&pub_a, &slug("session"), &slug("auth"), &now)
        .is_none());
}
