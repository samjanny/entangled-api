mod common;

use entangled_core::types::document::{ContentDocument, Document};
use serde_json::json;

use crate::common::{
    minimal_canary, minimal_content_doc, minimal_manifest, KEY_ZEROS, ONION_ADDR, SIG_ZEROS,
};

fn manifest_json_with_extra_top_level() -> serde_json::Value {
    let m = minimal_manifest();
    let mut v = serde_json::to_value(&m).unwrap();
    v.as_object_mut()
        .unwrap()
        .insert("extra_field".to_owned(), json!("evil"));
    // Add the kind tag for Document-level dispatch.
    v.as_object_mut()
        .unwrap()
        .insert("kind".to_owned(), json!("manifest"));
    v
}

#[test]
fn top_level_extra_field_rejected_on_manifest() {
    let v = manifest_json_with_extra_top_level();
    let parsed: Result<Document, _> = serde_json::from_value(v);
    assert!(
        parsed.is_err(),
        "manifest with extra top-level field should be rejected"
    );
}

#[test]
fn sub_object_extra_field_rejected() {
    // Sub-object: origin gains an `extra` field.
    let v = json!({
        "kind": "manifest",
        "spec_version": "1.0",
        "publisher_pubkey": KEY_ZEROS,
        "origin": {
            "carrier": "tor-v3",
            "address": ONION_ADDR,
            "origin_pubkey": KEY_ZEROS,
            "extra": "evil"
        },
        "canary": serde_json::to_value(minimal_canary()).unwrap(),
        "state_policy": [],
        "navigation": [],
        "min_refresh_interval": 86_400,
        "updated": "2026-05-07T00:00:00Z",
        "sig": SIG_ZEROS
    });
    let parsed: Result<Document, _> = serde_json::from_value(v);
    assert!(
        parsed.is_err(),
        "manifest with extra field in `origin` should be rejected"
    );
}

#[test]
fn block_extra_field_rejected() {
    // Build a content document, then inject `style` into the lone paragraph block.
    let mut v = serde_json::to_value(minimal_content_doc()).unwrap();
    let blocks = v.get_mut("blocks").unwrap().as_array_mut().unwrap();
    blocks[0]
        .as_object_mut()
        .unwrap()
        .insert("style".to_owned(), json!("bold"));

    let parsed: Result<ContentDocument, _> = serde_json::from_value(v);
    assert!(
        parsed.is_err(),
        "content doc with paragraph having extra `style` field should be rejected. \
         If this fails, deny_unknown_fields on internally-tagged enum is broken — \
         see Phase 1 prompt §0.2."
    );
}
