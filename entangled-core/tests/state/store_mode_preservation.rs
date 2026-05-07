//! §07 "Mode change": existing entries retain the mode they had at commit
//! time. The store does not silently rewrite an existing mode when the
//! caller later re-sets with a different mode.

use entangled_core::state::{ConsentDecision, StateStore};
use entangled_core::types::state::StateMode;

use crate::helpers::{pub_from_seed, set_op, slug, ts};

const ACCEPTED: ConsentDecision = ConsentDecision {
    accepted: true,
    remembered: false,
};

#[test]
fn entry_mode_is_what_was_passed_at_set_time() {
    let pub_a = pub_from_seed(21);
    let now = ts("2026-05-07T00:00:00Z");
    let mut store = StateStore::new();

    store
        .set(
            &pub_a,
            &set_op("session", "auth", "v1", 3600),
            StateMode::Request,
            ACCEPTED,
            &now,
        )
        .unwrap();
    let e = store
        .get(&pub_a, &slug("session"), &slug("auth"), &now)
        .unwrap();
    assert_eq!(e.mode, StateMode::Request);
}

#[test]
fn rewriting_with_different_mode_replaces_entry_with_new_mode() {
    // The store is intentionally agnostic to policy; the caller is expected
    // to pass the mode resolved from the *current* policy. When the caller
    // does so for a fresh `set`, that becomes the new entry's mode (a fresh
    // consent prompt is required at the UX layer per §07; the store does
    // not enforce that).
    let pub_a = pub_from_seed(22);
    let now = ts("2026-05-07T00:00:00Z");
    let mut store = StateStore::new();

    store
        .set(
            &pub_a,
            &set_op("session", "auth", "v1", 3600),
            StateMode::Request,
            ACCEPTED,
            &now,
        )
        .unwrap();
    store
        .set(
            &pub_a,
            &set_op("session", "auth", "v2", 3600),
            StateMode::ClientOnly,
            ACCEPTED,
            &now,
        )
        .unwrap();

    let e = store
        .get(&pub_a, &slug("session"), &slug("auth"), &now)
        .unwrap();
    assert_eq!(e.mode, StateMode::ClientOnly);
    assert_eq!(e.value, "v2");
}

#[test]
fn entry_mode_field_is_immutable_from_outside() {
    // StateEntry exposes `mode` as a public field, but the store hands out
    // only `&StateEntry`, so the mode cannot be mutated through the public
    // API once committed. This test documents that contract by attempting
    // to read the mode through the borrowed reference and asserting it
    // matches the value passed to `set`.
    let pub_a = pub_from_seed(23);
    let now = ts("2026-05-07T00:00:00Z");
    let mut store = StateStore::new();

    store
        .set(
            &pub_a,
            &set_op("ns", "k", "v", 3600),
            StateMode::Request,
            ACCEPTED,
            &now,
        )
        .unwrap();

    let mode_before = {
        let e = store.get(&pub_a, &slug("ns"), &slug("k"), &now).unwrap();
        e.mode
    };
    // Re-borrow does not let us mutate; assert mode is still Request.
    let mode_after = {
        let e = store.get(&pub_a, &slug("ns"), &slug("k"), &now).unwrap();
        e.mode
    };
    assert_eq!(mode_before, mode_after);
    assert_eq!(mode_after, StateMode::Request);
}
