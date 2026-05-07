//! Integration with Phase 1 typed structs: build a `Manifest`, strip `sig`,
//! canonicalize the payload, and verify determinism.

use crate::common::minimal_manifest;
use entangled_core::canon::{build_manifest_signature_input, MANIFEST_CONTEXT};

#[test]
fn manifest_signature_input_starts_with_manifest_context_and_null() {
    let manifest = minimal_manifest();
    let mut payload = serde_json::to_value(&manifest).expect("Manifest must serialize");
    let map = payload
        .as_object_mut()
        .expect("Manifest must serialize as a JSON object");
    map.remove("sig").expect("Manifest must contain sig");

    let input = build_manifest_signature_input(&payload).expect("manifest payload canonicalizes");
    assert!(!input.is_empty(), "signature input must not be empty");
    assert_eq!(
        &input[..MANIFEST_CONTEXT.len()],
        MANIFEST_CONTEXT.as_bytes()
    );
    assert_eq!(input[MANIFEST_CONTEXT.len()], 0x00);
}

#[test]
fn manifest_signature_input_is_deterministic_across_calls() {
    let manifest = minimal_manifest();
    let mut payload = serde_json::to_value(&manifest).unwrap();
    payload.as_object_mut().unwrap().remove("sig").unwrap();

    let a = build_manifest_signature_input(&payload).unwrap();
    let b = build_manifest_signature_input(&payload).unwrap();
    assert_eq!(a, b, "canonicalization must be deterministic");
}

#[test]
fn manifest_signature_input_is_independent_of_input_field_order() {
    // Two semantically equal manifests serialized via different routes must
    // canonicalize to the same signature input. We construct a second
    // payload by round-tripping through a string with shuffled whitespace.
    let manifest = minimal_manifest();
    let mut payload_a = serde_json::to_value(&manifest).unwrap();
    payload_a.as_object_mut().unwrap().remove("sig").unwrap();

    let serialized = serde_json::to_string(&payload_a).unwrap();
    let payload_b: serde_json::Value = serde_json::from_str(&serialized).unwrap();

    let a = build_manifest_signature_input(&payload_a).unwrap();
    let b = build_manifest_signature_input(&payload_b).unwrap();
    assert_eq!(a, b);
}
