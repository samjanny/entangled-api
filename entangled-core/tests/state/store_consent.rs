//! Consent decision handling on `StateStore::set` (§07).

use entangled_core::state::{ConsentDecision, SetOutcome, StateStore};
use entangled_core::types::state::StateMode;

use crate::helpers::{pub_from_seed, set_op, slug, ts};

#[test]
fn consent_rejected_does_not_commit() {
    let pub_a = pub_from_seed(11);
    let now = ts("2026-05-07T00:00:00Z");
    let mut store = StateStore::new();

    let outcome = store
        .set(
            &pub_a,
            &set_op("session", "auth", "v", 600),
            StateMode::Request,
            ConsentDecision {
                accepted: false,
                remembered: false,
            },
            &now,
        )
        .unwrap();
    assert_eq!(outcome, SetOutcome::Rejected);
    assert!(store
        .get(&pub_a, &slug("session"), &slug("auth"), &now)
        .is_none());
}

#[test]
fn consent_accepted_not_remembered() {
    let pub_a = pub_from_seed(12);
    let now = ts("2026-05-07T00:00:00Z");
    let mut store = StateStore::new();

    let outcome = store
        .set(
            &pub_a,
            &set_op("session", "auth", "v", 600),
            StateMode::Request,
            ConsentDecision {
                accepted: true,
                remembered: false,
            },
            &now,
        )
        .unwrap();
    assert_eq!(outcome, SetOutcome::Committed { remembered: false });

    let e = store
        .get(&pub_a, &slug("session"), &slug("auth"), &now)
        .unwrap();
    assert!(!e.remembered_consent);
}

#[test]
fn consent_accepted_remembered() {
    let pub_a = pub_from_seed(13);
    let now = ts("2026-05-07T00:00:00Z");
    let mut store = StateStore::new();

    let outcome = store
        .set(
            &pub_a,
            &set_op("session", "auth", "v", 600),
            StateMode::Request,
            ConsentDecision {
                accepted: true,
                remembered: true,
            },
            &now,
        )
        .unwrap();
    assert_eq!(outcome, SetOutcome::Committed { remembered: true });

    let e = store
        .get(&pub_a, &slug("session"), &slug("auth"), &now)
        .unwrap();
    assert!(e.remembered_consent);
}
