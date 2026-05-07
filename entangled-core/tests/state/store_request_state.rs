//! `get_request_state` returns only non-expired Request-mode entries for
//! the given publisher (§07).

use entangled_core::state::{ConsentDecision, StateStore};
use entangled_core::types::state::StateMode;

use crate::helpers::{policy_entry, pub_from_seed, set_op, ts};

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

    let policy = vec![
        policy_entry("session", "auth", StateMode::Request, 512, 86_400),
        policy_entry("session", "stale", StateMode::Request, 512, 86_400),
        policy_entry("prefs", "lang", StateMode::ClientOnly, 512, 86_400),
    ];

    let items = store.get_request_state(&pub_a, &policy, &later);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].namespace.as_str(), "session");
    assert_eq!(items[0].key.as_str(), "auth");
    assert_eq!(items[0].value, "alpha");

    let items_b = store.get_request_state(&pub_b, &policy, &later);
    assert!(items_b.is_empty());
}

/// §07: state for `(namespace, key)` no longer declared in the current
/// policy MUST NOT appear in submit requests, even if the entry is fresh
/// and was committed in `Request` mode.
#[test]
fn excludes_request_entries_dropped_from_current_policy() {
    let pub_a = pub_from_seed(43);
    let now = ts("2026-05-07T00:00:00Z");
    let mut store = StateStore::new();

    store
        .set(
            &pub_a,
            &set_op("session", "auth", "alpha", 3600),
            StateMode::Request,
            ACCEPTED,
            &now,
        )
        .unwrap();

    // Old policy declared the entry — present here. New policy does not.
    let new_policy = vec![policy_entry(
        "session",
        "csrf",
        StateMode::Request,
        512,
        86_400,
    )];
    let items = store.get_request_state(&pub_a, &new_policy, &now);
    assert!(
        items.is_empty(),
        "entry whose (ns,key) is no longer declared must not be transmitted, got {items:?}"
    );

    // The entry is still in the store (retained for inspection/deletion).
    assert!(store.bytes_used_for_publisher(&pub_a, &now) > 0);
}
