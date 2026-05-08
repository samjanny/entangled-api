//! N+1 negative tests for spec-mandated array length limits.
//!
//! For each array bounded by §02/§03/§06/§07, this file verifies that the
//! validator rejects an array of N+1 elements with the appropriate
//! diagnostic code. Tests at exactly N (the upper bound, accept) and at
//! N-1 are already covered in module-specific test files; this file
//! focuses on the violation boundary.

use entangled_core::validation::{
    parse_and_validate_content, parse_and_validate_manifest, parse_and_validate_transaction,
    DiagnosticCode,
};
use serde_json::{json, Value};

use crate::common::{fixed_now, minimal_content_doc, minimal_manifest, minimal_transaction_doc};

fn manifest_value() -> Value {
    let mut v = serde_json::to_value(minimal_manifest()).unwrap();
    v.as_object_mut()
        .unwrap()
        .insert("kind".to_owned(), json!("manifest"));
    v
}

fn content_value() -> Value {
    let mut v = serde_json::to_value(minimal_content_doc()).unwrap();
    v.as_object_mut()
        .unwrap()
        .insert("kind".to_owned(), json!("content"));
    v
}

fn transaction_value() -> Value {
    let mut v = serde_json::to_value(minimal_transaction_doc()).unwrap();
    v.as_object_mut()
        .unwrap()
        .insert("kind".to_owned(), json!("transaction"));
    v
}

fn to_bytes(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}

/// 33 distinct `state_policy` entries — one over the §07 max of 32.
#[test]
fn state_policy_with_33_entries_rejected_field_length() {
    let entries: Vec<Value> = (0..33)
        .map(|i| {
            json!({
                "namespace": format!("ns{i}"),
                "key": format!("key{i}"),
                "mode": "client_only",
                "max_size": 100,
                "max_lifetime": 600,
                "purpose": format!("Entry {i}.")
            })
        })
        .collect();
    let mut v = manifest_value();
    v.as_object_mut()
        .unwrap()
        .insert("state_policy".to_owned(), json!(entries));

    let err = parse_and_validate_manifest(&to_bytes(&v), &fixed_now()).expect_err("must reject");
    assert_eq!(
        err.code,
        DiagnosticCode::ESchemaFieldLength,
        "state_policy 33 > MAX 32: expected E_SCHEMA_FIELD_LENGTH, got {}",
        err
    );
}

/// 33 navigation entries — one over the §06 max of 32.
#[test]
fn navigation_with_33_entries_rejected_field_length() {
    let entries: Vec<Value> = (0..33)
        .map(|i| json!({ "label": format!("Label {i}"), "path": format!("/p/{i}") }))
        .collect();
    let mut v = manifest_value();
    v.as_object_mut()
        .unwrap()
        .insert("navigation".to_owned(), json!(entries));

    let err = parse_and_validate_manifest(&to_bytes(&v), &fixed_now()).expect_err("must reject");
    assert_eq!(
        err.code,
        DiagnosticCode::ESchemaFieldLength,
        "navigation 33 > MAX 32: expected E_SCHEMA_FIELD_LENGTH, got {}",
        err
    );
}

/// 33 transaction `state_updates` — one over the §02 transaction max of 32.
#[test]
fn state_updates_with_33_entries_rejected_field_length() {
    let updates: Vec<Value> = (0..33)
        .map(|i| {
            json!({
                "op": "set",
                "namespace": format!("ns{i}"),
                "key": format!("key{i}"),
                "value": format!("v{i}"),
                "ttl": 600
            })
        })
        .collect();
    let mut v = transaction_value();
    v.as_object_mut()
        .unwrap()
        .insert("state_updates".to_owned(), json!(updates));

    let err = parse_and_validate_transaction(&to_bytes(&v)).expect_err("must reject");
    assert_eq!(
        err.code,
        DiagnosticCode::ESchemaFieldLength,
        "state_updates 33 > MAX 32: expected E_SCHEMA_FIELD_LENGTH, got {}",
        err
    );
}

/// 1025 content `blocks` — one over the §02 content max of 1024.
#[test]
fn content_blocks_with_1025_entries_rejected_field_length() {
    let block = json!({
        "kind": "paragraph",
        "content": [
            { "kind": "text", "value": "x", "marks": [] }
        ]
    });
    let blocks: Vec<Value> = (0..1025).map(|_| block.clone()).collect();
    let mut v = content_value();
    v.as_object_mut()
        .unwrap()
        .insert("blocks".to_owned(), json!(blocks));

    let err = parse_and_validate_content(&to_bytes(&v)).expect_err("must reject");
    assert_eq!(
        err.code,
        DiagnosticCode::ESchemaFieldLength,
        "content blocks 1025 > MAX 1024: expected E_SCHEMA_FIELD_LENGTH, got {}",
        err
    );
}

/// 257 inline elements inside a single block's content — one over the
/// §03 inline-array max of 256.
#[test]
fn inline_content_with_257_elements_rejected_field_length() {
    let inline_text = json!({ "kind": "text", "value": "x", "marks": [] });
    let elements: Vec<Value> = (0..257).map(|_| inline_text.clone()).collect();
    let mut v = content_value();
    let blocks = v.as_object_mut().unwrap().get_mut("blocks").unwrap();
    *blocks = json!([
        {
            "kind": "paragraph",
            "content": elements
        }
    ]);

    let err = parse_and_validate_content(&to_bytes(&v)).expect_err("must reject");
    assert_eq!(
        err.code,
        DiagnosticCode::ESchemaFieldLength,
        "inline content 257 > MAX 256: expected E_SCHEMA_FIELD_LENGTH, got {}",
        err
    );
}
