//! Signature-input envelope (§05): `context || 0x00 || JCS(payload)`.

use entangled_core::canon::{
    build_content_signature_input, build_manifest_signature_input, build_signature_input,
    build_transaction_signature_input, canonicalize, CanonError, CONTENT_CONTEXT, MANIFEST_CONTEXT,
    TRANSACTION_CONTEXT,
};
use serde_json::json;

#[test]
fn context_strings_have_the_expected_byte_lengths() {
    // Constants verified against §05.
    assert_eq!(MANIFEST_CONTEXT.len(), 21);
    assert_eq!(CONTENT_CONTEXT.len(), 20);
    assert_eq!(TRANSACTION_CONTEXT.len(), 24);
}

#[test]
fn manifest_and_content_inputs_differ_for_the_same_payload() {
    let v = json!({"a": 1});
    let m = build_manifest_signature_input(&v).unwrap();
    let c = build_content_signature_input(&v).unwrap();
    assert_ne!(m, c, "domain separation requires distinct outputs");
    // First MANIFEST_CONTEXT.len()=21 bytes are the manifest context;
    // first CONTENT_CONTEXT.len()=20 bytes are the content context. These
    // differ at byte 0 (both start with 'E') but must differ before the
    // canonicalized payload.
    assert_eq!(&m[..MANIFEST_CONTEXT.len()], MANIFEST_CONTEXT.as_bytes());
    assert_eq!(&c[..CONTENT_CONTEXT.len()], CONTENT_CONTEXT.as_bytes());
}

#[test]
fn manifest_input_starts_with_context_then_null_then_jcs() {
    let v = json!({"a": 1});
    let input = build_manifest_signature_input(&v).unwrap();
    let canonical = canonicalize(&v).unwrap();

    let mut expected = Vec::new();
    expected.extend_from_slice(MANIFEST_CONTEXT.as_bytes());
    expected.push(0x00);
    expected.extend_from_slice(&canonical);

    assert_eq!(input, expected);
    assert_eq!(input[MANIFEST_CONTEXT.len()], 0x00);
    assert_eq!(&input[..MANIFEST_CONTEXT.len()], b"ENTANGLED-v1 manifest");
}

#[test]
fn unknown_context_string_is_rejected() {
    let v = json!({"a": 1});
    assert_eq!(
        build_signature_input("ENTANGLED-v2 something", &v),
        Err(CanonError::UnknownContext)
    );
}

#[test]
fn empty_context_string_is_rejected() {
    let v = json!({"a": 1});
    assert_eq!(
        build_signature_input("", &v),
        Err(CanonError::UnknownContext)
    );
}

#[test]
fn content_signature_input_for_the_section_04_vector_has_exact_byte_length() {
    let v = json!({
        "kind": "content",
        "spec_version": "1.0",
        "value": "hello world",
        "count": 42
    });
    let input = build_content_signature_input(&v).unwrap();
    // 20 (context) + 1 (null) + 72 (canonical bytes per §04 hex dump) = 93.
    assert_eq!(input.len(), 93);
    assert_eq!(&input[..CONTENT_CONTEXT.len()], b"ENTANGLED-v1 content");
    assert_eq!(input[CONTENT_CONTEXT.len()], 0x00);
}

#[test]
fn transaction_signature_input_for_the_section_04_vector_has_exact_byte_length() {
    let v = json!({
        "kind": "content",
        "spec_version": "1.0",
        "value": "hello world",
        "count": 42
    });
    let input = build_transaction_signature_input(&v).unwrap();
    // 24 (context) + 1 (null) + 72 (canonical bytes per §04 hex dump) = 97.
    assert_eq!(input.len(), 97);
    assert_eq!(
        &input[..TRANSACTION_CONTEXT.len()],
        b"ENTANGLED-v1 transaction"
    );
    assert_eq!(input[TRANSACTION_CONTEXT.len()], 0x00);
}

#[test]
fn null_payload_propagates_canon_error_through_signature_input() {
    let v = json!({"a": null});
    assert_eq!(
        build_manifest_signature_input(&v),
        Err(CanonError::NullNotPermitted)
    );
}
