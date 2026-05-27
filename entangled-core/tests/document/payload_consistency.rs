//! `to_signed_payload` on an `Unsigned*` must produce the exact same JCS
//! byte stream as the corresponding signed struct with `sig` removed and
//! `kind` injected. This is the canary: if it fails, builder and parser
//! cannot agree on the signature input, and no signature produced by the
//! builder will verify in the parser.

use entangled_core::canon::canonicalize;
use entangled_core::document::{UnsignedContent, UnsignedManifest, UnsignedTransaction};
use entangled_core::types::document::{ContentDocument, TransactionDocument};
use entangled_core::types::manifest::Manifest;
use serde_json::Value;

use super::common::{pubkey_zero, signature_zero};
use super::fixtures::{unsigned_content, unsigned_manifest_with_publisher, unsigned_transaction};

fn strip_sig_inject_kind(mut value: Value, kind: &str) -> Value {
    if let Value::Object(ref mut map) = value {
        map.remove("sig");
        map.insert("kind".to_owned(), Value::String(kind.to_owned()));
    }
    value
}

#[test]
fn manifest_unsigned_and_signed_produce_byte_identical_payload() {
    let unsigned: UnsignedManifest = unsigned_manifest_with_publisher(pubkey_zero());
    let signed = Manifest {
        spec_version: unsigned.spec_version,
        publisher_pubkey: unsigned.publisher_pubkey,
        origin: unsigned.origin.clone(),
        canary: unsigned.canary.clone(),
        state_policy: unsigned.state_policy.clone(),
        navigation: unsigned.navigation.clone(),
        min_refresh_interval: unsigned.min_refresh_interval,
        updated: unsigned.updated,
        migration_pointer: unsigned.migration_pointer.clone(),
        content_root: unsigned.content_root,
        sig: signature_zero(),
    };

    let unsigned_payload = unsigned.to_signed_payload().expect("to_signed_payload");
    let signed_value = serde_json::to_value(&signed).expect("to_value(signed)");
    let signed_payload = strip_sig_inject_kind(signed_value, "manifest");

    assert_eq!(
        unsigned_payload, signed_payload,
        "structural Value equality"
    );

    let unsigned_jcs = canonicalize(&unsigned_payload).expect("canon unsigned");
    let signed_jcs = canonicalize(&signed_payload).expect("canon signed");
    assert_eq!(unsigned_jcs, signed_jcs, "JCS byte-equal");
}

#[test]
fn content_unsigned_and_signed_produce_byte_identical_payload() {
    let unsigned: UnsignedContent = unsigned_content();
    let signed = ContentDocument {
        spec_version: unsigned.spec_version,
        path: unsigned.path.clone(),
        meta: unsigned.meta.clone(),
        blocks: unsigned.blocks.clone(),
        seq: unsigned.seq,
        sig: signature_zero(),
    };

    let unsigned_payload = unsigned.to_signed_payload().expect("to_signed_payload");
    let signed_value = serde_json::to_value(&signed).expect("to_value(signed)");
    let signed_payload = strip_sig_inject_kind(signed_value, "content");

    assert_eq!(unsigned_payload, signed_payload);
    assert_eq!(
        canonicalize(&unsigned_payload).unwrap(),
        canonicalize(&signed_payload).unwrap(),
    );
}

#[test]
fn transaction_unsigned_and_signed_produce_byte_identical_payload() {
    let unsigned: UnsignedTransaction = unsigned_transaction();
    let signed = TransactionDocument {
        spec_version: unsigned.spec_version,
        in_response_to: unsigned.in_response_to.clone(),
        request_id: unsigned.request_id,
        request_hash: unsigned.request_hash,
        state_updates: unsigned.state_updates.clone(),
        blocks: unsigned.blocks.clone(),
        sig: signature_zero(),
    };

    let unsigned_payload = unsigned.to_signed_payload().expect("to_signed_payload");
    let signed_value = serde_json::to_value(&signed).expect("to_value(signed)");
    let signed_payload = strip_sig_inject_kind(signed_value, "transaction");

    assert_eq!(unsigned_payload, signed_payload);
    assert_eq!(
        canonicalize(&unsigned_payload).unwrap(),
        canonicalize(&signed_payload).unwrap(),
    );
}
