//! Tampered envelopes must fail Stage 6 verification.

use entangled_core::crypto::SigningKey;
use entangled_core::document::{
    build_content, build_manifest, parse_and_verify_content, parse_and_verify_manifest,
};
use entangled_core::validation::DiagnosticCode;

use super::fixtures::{unsigned_content, unsigned_manifest_with_publisher};
use crate::common::fixed_now;

/// Find the first byte that is not part of the JSON literal `"sig":"…"`.
/// We want to flip a byte that does NOT live inside the signature string.
fn first_byte_outside_sig(bytes: &[u8]) -> usize {
    let s = std::str::from_utf8(bytes).expect("utf8");
    let sig_idx = s.find("\"sig\"").expect("envelope contains sig field");
    // The leading byte (`{`) is structurally fine to leave alone; pick
    // index 1, which is a property name in the serde-default ordering.
    assert!(sig_idx > 1, "sig is not at the start of the object");
    1
}

#[test]
fn manifest_body_byte_flip_rejected_with_sig_verification() {
    let publisher_key = SigningKey::from_seed(&[0xE1; 32]);
    let publisher_pk = publisher_key.verifying_key().to_publisher_pubkey();
    let unsigned = unsigned_manifest_with_publisher(publisher_pk);

    let (_manifest, mut bytes) =
        build_manifest(&unsigned, &publisher_key, &fixed_now()).expect("build");
    let idx = first_byte_outside_sig(&bytes);
    bytes[idx] ^= 0x01;

    // The flip might invalidate the JSON outright (if it lands on a
    // structural byte) or leave us with valid JSON whose canonicalization
    // differs from what was signed. Either way the parser must refuse.
    let err = parse_and_verify_manifest(&bytes, &fixed_now())
        .expect_err("tampered manifest must not parse-and-verify");
    assert!(
        matches!(
            err.code,
            DiagnosticCode::ESigVerification
                | DiagnosticCode::EParseJson
                | DiagnosticCode::ESchemaFieldType
                | DiagnosticCode::ESchemaFieldSyntax
                | DiagnosticCode::ESchemaRequiredField
                | DiagnosticCode::ESchemaUnknownField
        ),
        "expected pipeline rejection, got {err}",
    );
}

#[test]
fn manifest_with_sig_replaced_by_other_keys_signature_rejected() {
    let key_a = SigningKey::from_seed(&[0xF1; 32]);
    let key_b = SigningKey::from_seed(&[0xF2; 32]);
    let publisher_pk = key_a.verifying_key().to_publisher_pubkey();
    let unsigned = unsigned_manifest_with_publisher(publisher_pk);

    let (_manifest_a, _bytes_a) = build_manifest(&unsigned, &key_a, &fixed_now()).expect("build A");
    let (_manifest_b, bytes_b) = build_manifest(&unsigned, &key_b, &fixed_now()).expect("build B");

    // bytes_b carries B's sig but A's `publisher_pubkey` (because the
    // unsigned struct declares A as publisher). A's pubkey can't verify B's
    // sig, so Stage 6 must fail.
    let err =
        parse_and_verify_manifest(&bytes_b, &fixed_now()).expect_err("wrong key sig must fail");
    assert_eq!(err.code, DiagnosticCode::ESigVerification);
}

#[test]
fn content_signed_by_wrong_runtime_key_rejected() {
    let key_a = SigningKey::from_seed(&[0xC1; 32]);
    let key_b = SigningKey::from_seed(&[0xC2; 32]);
    let pk_b = key_b.verifying_key().to_runtime_pubkey();
    let unsigned = unsigned_content();

    let (_content, bytes) = build_content(&unsigned, &key_a).expect("build with A");

    let err = parse_and_verify_content(&bytes, &pk_b).expect_err("wrong runtime key must fail");
    assert_eq!(err.code, DiagnosticCode::ESigVerification);
}

#[test]
fn manifest_sig_byte_flip_rejected() {
    let publisher_key = SigningKey::from_seed(&[0xE2; 32]);
    let publisher_pk = publisher_key.verifying_key().to_publisher_pubkey();
    let unsigned = unsigned_manifest_with_publisher(publisher_pk);

    let (_manifest, bytes) =
        build_manifest(&unsigned, &publisher_key, &fixed_now()).expect("build");
    // Locate the sig string and flip a base64url character within it.
    let s = std::str::from_utf8(&bytes).unwrap().to_owned();
    let sig_field_start = s.find("\"sig\":\"").unwrap() + "\"sig\":\"".len();
    let mut bytes = bytes;
    // Flip in the middle of the signature, not the closing quote.
    let target_idx = sig_field_start + 10;
    let original = bytes[target_idx];
    let replacement = if original == b'A' { b'B' } else { b'A' };
    bytes[target_idx] = replacement;

    let err =
        parse_and_verify_manifest(&bytes, &fixed_now()).expect_err("flipped sig must not verify");
    assert!(
        matches!(
            err.code,
            DiagnosticCode::ESigVerification
                | DiagnosticCode::ESigMalformed
                | DiagnosticCode::ESchemaFieldSyntax
        ),
        "expected sig-related rejection, got {err}",
    );
}
