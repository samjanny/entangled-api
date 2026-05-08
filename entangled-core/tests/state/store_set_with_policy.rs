//! `StateStore::set_with_policy` — atomic policy validation + commit (§07).

use entangled_core::state::{ConsentDecision, SetOutcome, StateStore};
use entangled_core::types::state::StateMode;
use entangled_core::validation::DiagnosticCode;

use crate::helpers::{delete_op, policy_entry, pub_from_seed, set_op, slug, ts};

const ACCEPTED: ConsentDecision = ConsentDecision {
    accepted: true,
    remembered: false,
};

#[test]
fn set_with_policy_resolves_mode_from_policy() {
    let pub_a = pub_from_seed(101);
    let now = ts("2026-05-07T00:00:00Z");
    let mut store = StateStore::new();
    let policy = vec![policy_entry(
        "session",
        "auth",
        StateMode::Request,
        512,
        86_400,
    )];

    let outcome = store
        .set_with_policy(
            &pub_a,
            &set_op("session", "auth", "tok", 3600),
            &policy,
            ACCEPTED,
            &now,
        )
        .unwrap();
    assert_eq!(outcome, SetOutcome::Committed { remembered: false });

    let entry = store
        .get(&pub_a, &slug("session"), &slug("auth"), &now)
        .unwrap();
    // Mode came from policy, not from a caller-supplied parameter.
    assert_eq!(entry.mode, StateMode::Request);
}

#[test]
fn set_with_policy_rejects_undeclared_pair() {
    let pub_a = pub_from_seed(102);
    let now = ts("2026-05-07T00:00:00Z");
    let mut store = StateStore::new();
    let policy = vec![policy_entry(
        "session",
        "auth",
        StateMode::Request,
        512,
        86_400,
    )];

    let err = store
        .set_with_policy(
            &pub_a,
            &set_op("session", "missing", "v", 600),
            &policy,
            ACCEPTED,
            &now,
        )
        .unwrap_err();
    assert_eq!(err.code, DiagnosticCode::EStateUndeclared);
}

#[test]
fn set_with_policy_rejects_value_over_max_size() {
    let pub_a = pub_from_seed(103);
    let now = ts("2026-05-07T00:00:00Z");
    let mut store = StateStore::new();
    let policy = vec![policy_entry("ns", "k", StateMode::ClientOnly, 4, 86_400)];

    let err = store
        .set_with_policy(
            &pub_a,
            &set_op("ns", "k", "12345", 600), // 5 > max_size 4
            &policy,
            ACCEPTED,
            &now,
        )
        .unwrap_err();
    assert_eq!(err.code, DiagnosticCode::EStateValueSize);
}

#[test]
fn set_with_policy_rejects_ttl_over_max_lifetime() {
    let pub_a = pub_from_seed(104);
    let now = ts("2026-05-07T00:00:00Z");
    let mut store = StateStore::new();
    let policy = vec![policy_entry("ns", "k", StateMode::ClientOnly, 64, 600)];

    let err = store
        .set_with_policy(
            &pub_a,
            &set_op("ns", "k", "v", 3600), // ttl 3600 > policy max_lifetime 600
            &policy,
            ACCEPTED,
            &now,
        )
        .unwrap_err();
    assert_eq!(err.code, DiagnosticCode::EStateTtl);
}

#[test]
fn set_with_policy_rejects_ttl_below_hard_minimum() {
    let pub_a = pub_from_seed(105);
    let now = ts("2026-05-07T00:00:00Z");
    let mut store = StateStore::new();
    let policy = vec![policy_entry("ns", "k", StateMode::ClientOnly, 64, 86_400)];

    let err = store
        .set_with_policy(
            &pub_a,
            &set_op("ns", "k", "v", 60), // 60 < absolute hard min 300
            &policy,
            ACCEPTED,
            &now,
        )
        .unwrap_err();
    assert_eq!(err.code, DiagnosticCode::EStateTtl);
}

#[test]
fn set_with_policy_refused_consent_does_not_commit() {
    let pub_a = pub_from_seed(106);
    let now = ts("2026-05-07T00:00:00Z");
    let mut store = StateStore::new();
    let policy = vec![policy_entry(
        "session",
        "auth",
        StateMode::Request,
        512,
        86_400,
    )];
    let refused = ConsentDecision {
        accepted: false,
        remembered: false,
    };

    let outcome = store
        .set_with_policy(
            &pub_a,
            &set_op("session", "auth", "tok", 3600),
            &policy,
            refused,
            &now,
        )
        .unwrap();
    assert_eq!(outcome, SetOutcome::Rejected);
    assert!(store
        .get(&pub_a, &slug("session"), &slug("auth"), &now)
        .is_none());
}

#[test]
fn set_with_policy_rejects_delete_op() {
    let pub_a = pub_from_seed(107);
    let now = ts("2026-05-07T00:00:00Z");
    let mut store = StateStore::new();
    let policy = vec![policy_entry("ns", "k", StateMode::ClientOnly, 64, 86_400)];

    let err = store
        .set_with_policy(&pub_a, &delete_op("ns", "k"), &policy, ACCEPTED, &now)
        .unwrap_err();
    assert_eq!(err.code, DiagnosticCode::EStateOp);
}
