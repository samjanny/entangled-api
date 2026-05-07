//! Domain separation: a manifest must not parse as content (cross-kind), and
//! a manifest blob with `kind` rewritten to `"content"` must not verify even
//! if the deserialization were to succeed (it won't, schema differs, but the
//! signature input would also differ because of the context string).

use entangled_core::crypto::SigningKey;
use entangled_core::document::{
    build_content, build_manifest, build_transaction, parse_and_verify_content,
    parse_and_verify_manifest, parse_and_verify_transaction,
};
use entangled_core::validation::DiagnosticCode;
use serde_json::Value;

use super::fixtures::{unsigned_content, unsigned_manifest_with_publisher, unsigned_transaction};
use crate::common::fixed_now;

#[test]
fn manifest_bytes_parsed_as_content_rejected() {
    let publisher_key = SigningKey::from_seed(&[0x11; 32]);
    let publisher_pk = publisher_key.verifying_key().to_publisher_pubkey();
    let runtime_pk = publisher_key.verifying_key().to_runtime_pubkey();
    let unsigned = unsigned_manifest_with_publisher(publisher_pk);
    let (_manifest, bytes) =
        build_manifest(&unsigned, &publisher_key, &fixed_now()).expect("build manifest");

    // The Stage 4 discriminator reads the literal `kind` string from the
    // body; since it is `"manifest"`, parse_and_verify_content fails the
    // kind check before any schema work.
    let err = parse_and_verify_content(&bytes, &runtime_pk)
        .expect_err("content parse must reject manifest body");
    assert_eq!(
        err.code,
        DiagnosticCode::EKindUnknown,
        "expected E_KIND_UNKNOWN at Stage 4, got {err}"
    );
}

#[test]
fn content_bytes_parsed_as_transaction_rejected() {
    let runtime_key = SigningKey::from_seed(&[0x12; 32]);
    let runtime_pk = runtime_key.verifying_key().to_runtime_pubkey();
    let unsigned = unsigned_content();
    let (_content, bytes) = build_content(&unsigned, &runtime_key).expect("build content");

    let err = parse_and_verify_transaction(&bytes, &runtime_pk)
        .expect_err("transaction parse must reject content body");
    assert_eq!(err.code, DiagnosticCode::EKindUnknown);
}

#[test]
fn transaction_bytes_parsed_as_manifest_rejected() {
    let runtime_key = SigningKey::from_seed(&[0x13; 32]);
    let unsigned = unsigned_transaction();
    let (_tx, bytes) = build_transaction(&unsigned, &runtime_key).expect("build tx");

    let err = parse_and_verify_manifest(&bytes, &fixed_now())
        .expect_err("manifest parse must reject tx body");
    assert_eq!(err.code, DiagnosticCode::EKindUnknown);
}

/// Cryptographic domain separation: rewrite `kind` from `"manifest"` to
/// `"content"` while keeping the manifest sig. This usually fails Stage 5
/// schema (manifest schema doesn't match content), but if it ever passed,
/// the signature input under the content context would diverge from what
/// was signed under the manifest context, and Stage 6 would fail.
#[test]
fn manifest_with_kind_rewritten_to_content_rejected() {
    let publisher_key = SigningKey::from_seed(&[0x21; 32]);
    let publisher_pk = publisher_key.verifying_key().to_publisher_pubkey();
    let runtime_pk = publisher_key.verifying_key().to_runtime_pubkey();
    let unsigned = unsigned_manifest_with_publisher(publisher_pk);
    let (_manifest, bytes) =
        build_manifest(&unsigned, &publisher_key, &fixed_now()).expect("build manifest");

    let mut value: Value = serde_json::from_slice(&bytes).expect("parse json");
    if let Value::Object(ref mut map) = value {
        map.insert("kind".to_owned(), Value::String("content".to_owned()));
    }
    let rewritten = serde_json::to_vec(&value).expect("re-serialize");

    let err = parse_and_verify_content(&rewritten, &runtime_pk)
        .expect_err("rewritten manifest body must not pass content pipeline");

    // Observed: Stage 5 schema rejects the rewritten body with
    // E_SCHEMA_UNKNOWN_FIELD ("unknown field `canary`") because the content
    // schema does not declare manifest-only fields. Stage 6 is never
    // reached, but if it were, the divergent context string would also
    // cause E_SIG_VERIFICATION — the parser provides defense in depth.
    assert_eq!(err.code, DiagnosticCode::ESchemaUnknownField);
}
