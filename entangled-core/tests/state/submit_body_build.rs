//! `build_submit_body` end-to-end: empty store, request entries, and user
//! input fields wired through.

use std::collections::BTreeMap;

use entangled_core::state::{build_submit_body, ConsentDecision, StateStore};
use entangled_core::types::state::StateMode;

use crate::helpers::{policy_entry, pub_from_seed, set_op, ts};

const ACCEPTED: ConsentDecision = ConsentDecision {
    accepted: true,
    remembered: false,
};

#[test]
fn build_with_two_request_entries() {
    let pub_a = pub_from_seed(71);
    let now = ts("2026-05-07T00:00:00Z");
    let mut store = StateStore::new();

    store
        .set(
            &pub_a,
            &set_op("session", "auth", "alpha", 600),
            StateMode::Request,
            ACCEPTED,
            &now,
        )
        .unwrap();
    store
        .set(
            &pub_a,
            &set_op("session", "csrf", "beta", 600),
            StateMode::Request,
            ACCEPTED,
            &now,
        )
        .unwrap();

    let policy = vec![
        policy_entry("session", "auth", StateMode::Request, 512, 86_400),
        policy_entry("session", "csrf", StateMode::Request, 512, 86_400),
    ];
    let body = build_submit_body(BTreeMap::new(), &mut store, &pub_a, &policy, &now);
    assert_eq!(body.fields.len(), 0);
    assert_eq!(body.request_state.len(), 2);
}

#[test]
fn build_with_empty_store_yields_empty_request_state() {
    let pub_a = pub_from_seed(72);
    let now = ts("2026-05-07T00:00:00Z");
    let mut store = StateStore::new();
    let body = build_submit_body(BTreeMap::new(), &mut store, &pub_a, &[], &now);
    assert!(body.request_state.is_empty());
    assert!(body.fields.is_empty());
}

#[test]
fn build_includes_user_input_fields() {
    let pub_a = pub_from_seed(73);
    let now = ts("2026-05-07T00:00:00Z");
    let mut store = StateStore::new();

    let mut fields = BTreeMap::new();
    fields.insert("name".to_owned(), "alice".to_owned());
    fields.insert("message".to_owned(), "hello".to_owned());

    let body = build_submit_body(fields.clone(), &mut store, &pub_a, &[], &now);
    assert_eq!(body.fields, fields);
    assert!(body.request_state.is_empty());
}

#[test]
fn build_excludes_expired_request_state() {
    let pub_a = pub_from_seed(74);
    let now = ts("2026-05-07T00:00:00Z");
    let later = ts("2026-05-07T01:00:00Z");
    let mut store = StateStore::new();

    store
        .set(
            &pub_a,
            &set_op("session", "stale", "old", 300),
            StateMode::Request,
            ACCEPTED,
            &now,
        )
        .unwrap();

    let policy = vec![policy_entry(
        "session",
        "stale",
        StateMode::Request,
        512,
        86_400,
    )];
    let body = build_submit_body(BTreeMap::new(), &mut store, &pub_a, &policy, &later);
    assert!(body.request_state.is_empty());
}
