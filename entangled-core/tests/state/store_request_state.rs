//! `get_request_state` returns only non-expired Request-mode entries for
//! the given publisher (§07).

use entangled_core::state::{ConsentDecision, StateStore};
use entangled_core::types::state::StateMode;

use crate::helpers::{pub_from_seed, set_op, ts};

const ACCEPTED: ConsentDecision = ConsentDecision {
    accepted: true,
    remembered: false,
};

#[test]
fn returns_only_request_mode_non_expired() {
    let pub_a = pub_from_seed(41);
    let pub_b = pub_from_seed(42);
    let now = ts("2026-05-07T00:00:00Z");
    let later = ts("2026-05-07T00:30:00Z");
    let mut store = StateStore::new();

    // Request, fresh.
    store
        .set(
            &pub_a,
            &set_op("session", "auth", "alpha", 3600),
            StateMode::Request,
            ACCEPTED,
            &now,
        )
        .unwrap();
    // ClientOnly, fresh — must NOT appear.
    store
        .set(
            &pub_a,
            &set_op("prefs", "lang", "en", 3600),
            StateMode::ClientOnly,
            ACCEPTED,
            &now,
        )
        .unwrap();
    // Request, expired by `later` — ttl 300s, +30min → expired.
    store
        .set(
            &pub_a,
            &set_op("session", "stale", "old", 300),
            StateMode::Request,
            ACCEPTED,
            &now,
        )
        .unwrap();

    let items = store.get_request_state(&pub_a, &later);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].namespace.as_str(), "session");
    assert_eq!(items[0].key.as_str(), "auth");
    assert_eq!(items[0].value, "alpha");

    let items_b = store.get_request_state(&pub_b, &later);
    assert!(items_b.is_empty());
}
