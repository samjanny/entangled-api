//! Basic StateStore set/get/delete and per-publisher isolation (§07).

use entangled_core::state::{ConsentDecision, SetOutcome, StateStore};
use entangled_core::types::state::StateMode;

use crate::helpers::{delete_op, pub_from_seed, set_op, slug, ts};

const ACCEPTED: ConsentDecision = ConsentDecision {
    accepted: true,
    remembered: false,
};

#[test]
fn set_then_get_returns_entry() {
    let pub_a = pub_from_seed(1);
    let now = ts("2026-05-07T00:00:00Z");
    let mut store = StateStore::new();

    let op = set_op("session", "auth", "token-abc", 3600);
    let outcome = store
        .set(&pub_a, &op, StateMode::Request, ACCEPTED, &now)
        .unwrap();
    assert_eq!(outcome, SetOutcome::Committed { remembered: false });

    let entry = store
        .get(&pub_a, &slug("session"), &slug("auth"), &now)
        .expect("entry should be present");
    assert_eq!(entry.value, "token-abc");
    assert_eq!(entry.mode, StateMode::Request);
    assert_eq!(entry.consent_at, now);
    assert!(entry.expires_at > now);
}

#[test]
fn get_returns_none_when_expired() {
    let pub_a = pub_from_seed(2);
    let now = ts("2026-05-07T00:00:00Z");
    let later = ts("2026-05-07T00:10:00Z"); // +600s, ttl was 100s
    let mut store = StateStore::new();

    let op = set_op("session", "auth", "v", 300);
    store
        .set(&pub_a, &op, StateMode::ClientOnly, ACCEPTED, &now)
        .unwrap();
    // After ttl elapsed (now + 300 == later? Actually 600 > 300).
    let after_expiry = ts("2026-05-07T00:06:00Z");
    let _ = later;
    assert!(store
        .get(&pub_a, &slug("session"), &slug("auth"), &after_expiry)
        .is_none());
}

#[test]
fn delete_existing_returns_true_then_get_is_none() {
    let pub_a = pub_from_seed(3);
    let now = ts("2026-05-07T00:00:00Z");
    let mut store = StateStore::new();

    store
        .set(
            &pub_a,
            &set_op("session", "auth", "v", 600),
            StateMode::Request,
            ACCEPTED,
            &now,
        )
        .unwrap();

    let removed = store.delete(&pub_a, &delete_op("session", "auth")).unwrap();
    assert!(removed);

    assert!(store
        .get(&pub_a, &slug("session"), &slug("auth"), &now)
        .is_none());
}

#[test]
fn delete_nonexisting_is_noop() {
    let pub_a = pub_from_seed(4);
    let mut store = StateStore::new();
    let removed = store.delete(&pub_a, &delete_op("nope", "missing")).unwrap();
    assert!(!removed);
}

#[test]
fn per_publisher_isolation() {
    let pub_a = pub_from_seed(5);
    let pub_b = pub_from_seed(6);
    assert_ne!(pub_a, pub_b);
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

    assert!(store.get(&pub_a, &slug("ns"), &slug("k"), &now).is_some());
    assert!(store.get(&pub_b, &slug("ns"), &slug("k"), &now).is_none());
}

#[test]
fn round_trip_preserves_fields() {
    let pub_a = pub_from_seed(7);
    let now = ts("2026-05-07T00:00:00Z");
    let mut store = StateStore::new();
    let consent = ConsentDecision {
        accepted: true,
        remembered: true,
    };

    store
        .set(
            &pub_a,
            &set_op("session", "auth", "abcdef", 3600),
            StateMode::Request,
            consent,
            &now,
        )
        .unwrap();

    let e = store
        .get(&pub_a, &slug("session"), &slug("auth"), &now)
        .unwrap();
    assert_eq!(e.value, "abcdef");
    assert_eq!(e.mode, StateMode::Request);
    assert_eq!(e.consent_at, now);
    assert!(e.remembered_consent);
    assert_eq!(e.expires_at.unix_timestamp(), now.unix_timestamp() + 3600);
}

#[test]
fn variant_mismatch_set_with_delete_op_errors() {
    let pub_a = pub_from_seed(8);
    let now = ts("2026-05-07T00:00:00Z");
    let mut store = StateStore::new();

    let err = store
        .set(
            &pub_a,
            &delete_op("ns", "k"),
            StateMode::Request,
            ACCEPTED,
            &now,
        )
        .unwrap_err();
    assert_eq!(
        err.code,
        entangled_core::validation::DiagnosticCode::EStateOp
    );
}

#[test]
fn variant_mismatch_delete_with_set_op_errors() {
    let pub_a = pub_from_seed(9);
    let mut store = StateStore::new();
    let err = store
        .delete(&pub_a, &set_op("ns", "k", "v", 300))
        .unwrap_err();
    assert_eq!(
        err.code,
        entangled_core::validation::DiagnosticCode::EStateOp
    );
}
