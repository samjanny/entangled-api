//! Stage 2-6 errors must propagate through the document parser with the
//! correct §11 code.

use entangled_core::crypto::SigningKey;
use entangled_core::document::{build_manifest, parse_and_verify_manifest};
use entangled_core::validation::DiagnosticCode;
use serde_json::Value;

use super::fixtures::unsigned_manifest_with_publisher;

fn build_valid_manifest_bytes() -> Vec<u8> {
    let publisher_key = SigningKey::from_seed(&[0x31; 32]);
    let publisher_pk = publisher_key.verifying_key().to_publisher_pubkey();
    let unsigned = unsigned_manifest_with_publisher(publisher_pk);
    build_manifest(&unsigned, &publisher_key).expect("build").1
}

#[test]
fn stage2_byte_cap_exceeded() {
    // Manifest cap is 64 KiB; pad an arbitrary blob beyond that.
    let huge = vec![b'x'; 100 * 1024];
    let err = parse_and_verify_manifest(&huge).expect_err("must reject");
    assert_eq!(err.code, DiagnosticCode::EInputByteCap);
}

#[test]
fn stage2_bom_rejected() {
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(&build_valid_manifest_bytes());
    let err = parse_and_verify_manifest(&bytes).expect_err("must reject BOM");
    assert_eq!(err.code, DiagnosticCode::EInputBom);
}

#[test]
fn stage2_invalid_utf8_rejected() {
    let bytes = vec![0xFF, 0xFE, 0x00, 0x7B, 0x7D];
    let err = parse_and_verify_manifest(&bytes).expect_err("must reject");
    assert_eq!(err.code, DiagnosticCode::EInputUtf8);
}

#[test]
fn stage3_malformed_json_rejected() {
    let bytes = b"{not json".to_vec();
    let err = parse_and_verify_manifest(&bytes).expect_err("must reject");
    assert_eq!(err.code, DiagnosticCode::EParseJson);
}

#[test]
fn stage4_missing_kind_rejected() {
    let bytes = build_valid_manifest_bytes();
    let mut value: Value = serde_json::from_slice(&bytes).unwrap();
    if let Value::Object(ref mut map) = value {
        map.remove("kind");
    }
    let altered = serde_json::to_vec(&value).unwrap();
    let err = parse_and_verify_manifest(&altered).expect_err("must reject missing kind");
    assert_eq!(err.code, DiagnosticCode::EKindMissingFields);
}

#[test]
fn stage5_missing_canary_rejected() {
    let bytes = build_valid_manifest_bytes();
    let mut value: Value = serde_json::from_slice(&bytes).unwrap();
    if let Value::Object(ref mut map) = value {
        map.remove("canary");
    }
    let altered = serde_json::to_vec(&value).unwrap();
    let err = parse_and_verify_manifest(&altered).expect_err("must reject missing canary");
    assert_eq!(err.code, DiagnosticCode::ESchemaRequiredField);
}

#[test]
fn stage5_missing_sig_field_rejected() {
    let bytes = build_valid_manifest_bytes();
    let mut value: Value = serde_json::from_slice(&bytes).unwrap();
    if let Value::Object(ref mut map) = value {
        map.remove("sig");
    }
    let altered = serde_json::to_vec(&value).unwrap();
    let err = parse_and_verify_manifest(&altered).expect_err("must reject missing sig");
    // §02 lists `sig` among the Stage 4 discriminator fields, so a missing
    // `sig` is reported as `E_KIND_MISSING_FIELDS` before Stage 5 ever runs.
    assert_eq!(err.code, DiagnosticCode::EKindMissingFields);
}

#[test]
fn stage5_malformed_sig_string_rejected() {
    let bytes = build_valid_manifest_bytes();
    let mut value: Value = serde_json::from_slice(&bytes).unwrap();
    if let Value::Object(ref mut map) = value {
        map.insert("sig".to_owned(), Value::String("too-short".to_owned()));
    }
    let altered = serde_json::to_vec(&value).unwrap();
    let err = parse_and_verify_manifest(&altered).expect_err("must reject");
    // Observed: Signature::try_from emits "expected 86 base64url characters
    // (no padding), got 9", which the serde-error mapping in
    // validation::schema classifies as E_SCHEMA_FIELD_LENGTH at Stage 5.
    assert_eq!(err.code, DiagnosticCode::ESchemaFieldLength);
}

#[test]
fn stage6_well_formed_sig_but_wrong_signature_rejected() {
    let bytes = build_valid_manifest_bytes();
    let mut value: Value = serde_json::from_slice(&bytes).unwrap();
    // Replace sig with a syntactically valid base64url-no-pad 86-char string
    // that decodes to 64 zero bytes — almost certainly not the right sig.
    let zeros = "A".repeat(86);
    if let Value::Object(ref mut map) = value {
        map.insert("sig".to_owned(), Value::String(zeros));
    }
    let altered = serde_json::to_vec(&value).unwrap();
    let err = parse_and_verify_manifest(&altered).expect_err("must reject");
    assert_eq!(err.code, DiagnosticCode::ESigVerification);
}
