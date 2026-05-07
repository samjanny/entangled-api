//! End-to-end: policy → policy-aware update validation → consented set →
//! submit body construction → submit body validation → wire JSON.

use std::collections::BTreeMap;

use entangled_core::state::{build_submit_body, ConsentDecision, StateStore};
use entangled_core::types::state::StateMode;
use entangled_core::validation::policy_check::validate_state_updates_against_policy;
use entangled_core::validation::state::validate_state_policy;
use entangled_core::validation::submit::validate_submit_body;

use crate::helpers::{policy_entry, pub_from_seed, set_op, ts};

#[test]
fn full_submit_flow_end_to_end() {
    // 1. Publisher.
    let pub_a = pub_from_seed(91);

    // 2. Policy.
    let policy = vec![policy_entry(
        "session",
        "auth",
        StateMode::Request,
        512,
        86_400,
    )];
    // 3. Policy validates structurally.
    validate_state_policy(&policy).unwrap();

    // 4. Update.
    let op = set_op("session", "auth", "abc-token", 3600);

    // 5. Policy-aware check on the update.
    validate_state_updates_against_policy(std::slice::from_ref(&op), &policy).unwrap();

    // 6. Apply the set with consent.
    let now = ts("2026-05-07T00:00:00Z");
    let mut store = StateStore::new();
    let consent = ConsentDecision {
        accepted: true,
        remembered: true,
    };
    store
        .set(&pub_a, &op, StateMode::Request, consent, &now)
        .unwrap();

    // 7. Build the submit body.
    let mut fields = BTreeMap::new();
    fields.insert("name".to_owned(), "alice".to_owned());
    let body = build_submit_body(fields, &mut store, &pub_a, &policy, &now);

    // 8. The committed entry surfaces in the submit body's request_state.
    assert_eq!(body.request_state.len(), 1);
    let item = &body.request_state[0];
    assert_eq!(item.namespace.as_str(), "session");
    assert_eq!(item.key.as_str(), "auth");
    assert_eq!(item.value, "abc-token");

    // 9. Submit body passes validation.
    validate_submit_body(&body).unwrap();

    // 10. Serialize and confirm the wire shape.
    let json = serde_json::to_string(&body).unwrap();
    assert!(json.len() < 64 * 1024);
    assert!(json.contains(r#""fields":{"name":"alice"}"#));
    assert!(json.contains(r#""namespace":"session""#));
    assert!(json.contains(r#""key":"auth""#));
    assert!(json.contains(r#""value":"abc-token""#));
}
