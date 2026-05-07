//! Submit body schema validation (§09).

use std::collections::BTreeMap;

use entangled_core::state::{RequestStateItem, SubmitBody};
use entangled_core::types::slug::Slug;
use entangled_core::validation::submit::{validate_submit_body, validate_submit_body_bytes};
use entangled_core::validation::DiagnosticCode;

fn slug(s: &str) -> Slug {
    Slug::try_from(s).unwrap()
}

fn ok_body() -> SubmitBody {
    let mut fields = BTreeMap::new();
    fields.insert("name".to_owned(), "alice".to_owned());
    fields.insert("message".to_owned(), "hello".to_owned());
    fields.insert("topic".to_owned(), "general".to_owned());
    SubmitBody {
        fields,
        request_state: vec![],
    }
}

#[test]
fn valid_body_ok() {
    validate_submit_body(&ok_body()).unwrap();
}

#[test]
fn fields_above_32_rejected() {
    let mut fields = BTreeMap::new();
    for i in 0..33 {
        fields.insert(format!("k{i}"), "v".to_owned());
    }
    let body = SubmitBody {
        fields,
        request_state: vec![],
    };
    let err = validate_submit_body(&body).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaFieldLength);
}

#[test]
fn field_key_invalid_slug_rejected() {
    let mut fields = BTreeMap::new();
    fields.insert("BAD_KEY".to_owned(), "v".to_owned());
    let body = SubmitBody {
        fields,
        request_state: vec![],
    };
    let err = validate_submit_body(&body).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaFieldSyntax);
}

#[test]
fn field_value_above_8_kib_rejected() {
    let mut fields = BTreeMap::new();
    fields.insert("k".to_owned(), "x".repeat(8 * 1024 + 1));
    let body = SubmitBody {
        fields,
        request_state: vec![],
    };
    let err = validate_submit_body(&body).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaFieldLength);
}

#[test]
fn request_state_above_32_rejected() {
    let request_state: Vec<RequestStateItem> = (0..33)
        .map(|i| RequestStateItem {
            namespace: slug("session"),
            key: Slug::try_from(format!("k{i}").as_str()).unwrap(),
            value: "v".to_owned(),
        })
        .collect();
    let body = SubmitBody {
        fields: BTreeMap::new(),
        request_state,
    };
    let err = validate_submit_body(&body).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaFieldLength);
}

#[test]
fn empty_field_key_rejected() {
    let mut fields = BTreeMap::new();
    fields.insert(String::new(), "v".to_owned());
    let body = SubmitBody {
        fields,
        request_state: vec![],
    };
    let err = validate_submit_body(&body).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaFieldSyntax);
}

#[test]
fn submit_bytes_over_64_kib_rejected() {
    // Build a syntactically OK body that already exceeds the byte cap.
    let mut s = String::from("{\"fields\":{");
    s.push_str("\"k\":\"");
    s.push_str(&"x".repeat(70 * 1024));
    s.push_str("\"},\"request_state\":[]}");
    let err = validate_submit_body_bytes(s.as_bytes()).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::EInputByteCap);
}

#[test]
fn unknown_top_level_field_rejected() {
    let s = r#"{"fields":{},"request_state":[],"foo":1}"#;
    let err = validate_submit_body_bytes(s.as_bytes()).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaUnknownField);
}

#[test]
fn round_trip_serialize_then_validate_bytes() {
    let mut fields = BTreeMap::new();
    fields.insert("name".to_owned(), "alice".to_owned());
    let body = SubmitBody {
        fields,
        request_state: vec![RequestStateItem {
            namespace: slug("session"),
            key: slug("auth"),
            value: "abc".to_owned(),
        }],
    };
    let bytes = serde_json::to_vec(&body).unwrap();
    let parsed = validate_submit_body_bytes(&bytes).unwrap();
    assert_eq!(parsed, body);
}
