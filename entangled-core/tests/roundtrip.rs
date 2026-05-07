mod common;

use entangled_core::types::document::Document;

use crate::common::{minimal_content_doc, minimal_manifest, minimal_transaction_doc};

#[test]
fn manifest_roundtrip() {
    let m = minimal_manifest();
    let json = serde_json::to_string(&m).unwrap();
    let back: entangled_core::types::manifest::Manifest = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

#[test]
fn content_doc_roundtrip() {
    let c = minimal_content_doc();
    let json = serde_json::to_string(&c).unwrap();
    let back: entangled_core::types::document::ContentDocument =
        serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn transaction_doc_roundtrip() {
    let t = minimal_transaction_doc();
    let json = serde_json::to_string(&t).unwrap();
    let back: entangled_core::types::document::TransactionDocument =
        serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

#[test]
fn document_enum_dispatches_to_manifest() {
    let m = Document::Manifest(minimal_manifest());
    let json = serde_json::to_string(&m).unwrap();
    assert!(json.contains("\"kind\":\"manifest\""));
    let back: Document = serde_json::from_str(&json).unwrap();
    assert!(matches!(back, Document::Manifest(_)));
    assert_eq!(m, back);
}

#[test]
fn document_enum_dispatches_to_content() {
    let c = Document::Content(minimal_content_doc());
    let json = serde_json::to_string(&c).unwrap();
    assert!(json.contains("\"kind\":\"content\""));
    let back: Document = serde_json::from_str(&json).unwrap();
    assert!(matches!(back, Document::Content(_)));
    assert_eq!(c, back);
}

#[test]
fn document_enum_dispatches_to_transaction() {
    let t = Document::Transaction(minimal_transaction_doc());
    let json = serde_json::to_string(&t).unwrap();
    assert!(json.contains("\"kind\":\"transaction\""));
    let back: Document = serde_json::from_str(&json).unwrap();
    assert!(matches!(back, Document::Transaction(_)));
    assert_eq!(t, back);
}
