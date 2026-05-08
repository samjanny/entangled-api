//! Stage 9 transaction binding helper: `verify_transaction_binding` checks
//! that a verified transaction echoes the originating submit's path,
//! `request_id`, and `request_hash` byte-exact (§10).

use std::collections::BTreeMap;

use entangled_core::canon::canonicalize;
use entangled_core::crypto::sha256_request;
use entangled_core::document::verify_transaction_binding;
use entangled_core::state::SubmitBody;
use entangled_core::types::keys::RequestId;
use entangled_core::validation::DiagnosticCode;

use super::common::{minimal_transaction_doc, path};

fn ok_submit_body(rid: RequestId) -> SubmitBody {
    let mut fields = BTreeMap::new();
    fields.insert("name".to_owned(), "alice".to_owned());
    SubmitBody {
        fields,
        request_state: vec![],
        request_id: rid,
    }
}

#[test]
fn matching_path_id_and_hash_pass() {
    let rid = RequestId::from_bytes([0u8; 16]);
    let body = ok_submit_body(rid);

    let body_value = serde_json::to_value(&body).unwrap();
    let canonical = canonicalize(&body_value).unwrap();
    let request_hash = sha256_request(&canonical);

    let mut tx = minimal_transaction_doc();
    tx.in_response_to = path("/contact");
    tx.request_id = rid;
    tx.request_hash = request_hash;

    verify_transaction_binding(&tx, &path("/contact"), &body)
        .expect("matching path/id/hash must pass");
}

#[test]
fn mismatched_path_emits_bind_response_path() {
    // §10 Stage 9 ordering: path mismatch is reported first.
    let rid = RequestId::from_bytes([0u8; 16]);
    let body = ok_submit_body(rid);

    let mut tx = minimal_transaction_doc();
    tx.in_response_to = path("/wrong-path");
    tx.request_id = rid;
    tx.request_hash = sha256_request(&canonicalize(&serde_json::to_value(&body).unwrap()).unwrap());

    let err = verify_transaction_binding(&tx, &path("/contact"), &body).expect_err("path mismatch");
    assert_eq!(err.code, DiagnosticCode::EBindResponsePath);
    let details = err.details.as_ref().expect("details payload");
    assert_eq!(details["expected"].as_str(), Some("/contact"));
    assert_eq!(details["received"].as_str(), Some("/wrong-path"));
}

#[test]
fn mismatched_request_id_emits_bind_request_id() {
    // After path matches, `request_id` mismatch is the next reported failure.
    let body_rid = RequestId::from_bytes([0u8; 16]);
    let body = ok_submit_body(body_rid);
    let canonical = canonicalize(&serde_json::to_value(&body).unwrap()).unwrap();

    let mut tx = minimal_transaction_doc();
    tx.in_response_to = path("/contact");
    tx.request_id = RequestId::from_bytes([1u8; 16]); // differs from body_rid
    tx.request_hash = sha256_request(&canonical);

    let err =
        verify_transaction_binding(&tx, &path("/contact"), &body).expect_err("request_id mismatch");
    assert_eq!(err.code, DiagnosticCode::EBindRequestId);
    let details = err.details.as_ref().expect("details payload");
    assert!(details["expected"].as_str().is_some());
    assert!(details["received"].as_str().is_some());
    assert_ne!(details["expected"], details["received"]);
}

#[test]
fn mismatched_request_hash_emits_bind_request_hash() {
    // Path and request_id match; only the canonical-body digest differs —
    // the helper recomputes the digest from `submit_body` and rejects.
    let rid = RequestId::from_bytes([0u8; 16]);
    let body = ok_submit_body(rid);

    let mut tx = minimal_transaction_doc();
    tx.in_response_to = path("/contact");
    tx.request_id = rid;
    // Forge a digest that doesn't match the canonical body.
    tx.request_hash = sha256_request(b"some other bytes");

    let err = verify_transaction_binding(&tx, &path("/contact"), &body)
        .expect_err("request_hash mismatch");
    assert_eq!(err.code, DiagnosticCode::EBindRequestHash);
    let details = err.details.as_ref().expect("details payload");
    let expected = details["expected"].as_str().unwrap();
    let received = details["received"].as_str().unwrap();
    assert!(expected.starts_with("sha-256:"));
    assert!(received.starts_with("sha-256:"));
    assert_ne!(expected, received);
}

#[test]
fn checks_run_in_path_then_id_then_hash_order() {
    // When all three would fail, the helper reports the path failure first
    // — matching §10's stage-ordered "first failure" rule.
    let rid_body = RequestId::from_bytes([0u8; 16]);
    let body = ok_submit_body(rid_body);

    let mut tx = minimal_transaction_doc();
    tx.in_response_to = path("/wrong");
    tx.request_id = RequestId::from_bytes([1u8; 16]);
    tx.request_hash = sha256_request(b"unrelated");

    let err = verify_transaction_binding(&tx, &path("/contact"), &body).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::EBindResponsePath);
}
