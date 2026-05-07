//! Direct exercises for `extract_sig` / `attach_sig`.

use entangled_core::document::{attach_sig, extract_sig};
use entangled_core::types::keys::Signature;
use entangled_core::validation::{DiagnosticCode, DocumentKindLabel};
use serde_json::{json, Value};

const VALID_SIG: &str =
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[test]
fn extract_sig_removes_field_and_returns_signature() {
    let mut value = json!({"foo": 1, "sig": VALID_SIG});
    let sig = extract_sig(&mut value, DocumentKindLabel::Manifest).expect("ok");
    assert_eq!(sig.to_string(), VALID_SIG);
    if let Value::Object(map) = &value {
        assert!(!map.contains_key("sig"));
        assert!(map.contains_key("foo"));
    } else {
        panic!("expected object");
    }
}

#[test]
fn extract_sig_missing_returns_kind_missing_fields() {
    let mut value = json!({"foo": 1});
    let err = extract_sig(&mut value, DocumentKindLabel::Manifest).expect_err("must fail");
    assert_eq!(err.code, DiagnosticCode::EKindMissingFields);
}

#[test]
fn extract_sig_non_string_returns_kind_missing_fields() {
    let mut value = json!({"sig": 123});
    let err = extract_sig(&mut value, DocumentKindLabel::Content).expect_err("must fail");
    assert_eq!(err.code, DiagnosticCode::EKindMissingFields);
}

#[test]
fn extract_sig_malformed_string_returns_sig_malformed() {
    let mut value = json!({"sig": "nope"});
    let err = extract_sig(&mut value, DocumentKindLabel::Transaction).expect_err("must fail");
    assert_eq!(err.code, DiagnosticCode::ESigMalformed);
}

#[test]
fn extract_sig_on_non_object_returns_parse_json() {
    let mut value = json!([1, 2, 3]);
    let err = extract_sig(&mut value, DocumentKindLabel::Manifest).expect_err("must fail");
    assert_eq!(err.code, DiagnosticCode::EParseJson);
}

#[test]
fn attach_sig_adds_field() {
    let mut value = json!({"foo": 1});
    let sig = Signature::try_from(VALID_SIG).unwrap();
    attach_sig(&mut value, &sig, DocumentKindLabel::Manifest).expect("ok");
    if let Value::Object(map) = &value {
        assert_eq!(map["sig"], Value::String(VALID_SIG.to_owned()));
    } else {
        panic!("expected object");
    }
}

#[test]
fn attach_sig_overwrites_existing() {
    let mut value = json!({"sig": "old"});
    let sig = Signature::try_from(VALID_SIG).unwrap();
    attach_sig(&mut value, &sig, DocumentKindLabel::Manifest).expect("ok");
    if let Value::Object(map) = &value {
        assert_eq!(map["sig"], Value::String(VALID_SIG.to_owned()));
    } else {
        panic!("expected object");
    }
}
