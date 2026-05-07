//! End-to-end round trip: a signed document produced by the builder must
//! parse and verify via the corresponding parser.

use entangled_core::crypto::SigningKey;
use entangled_core::document::{
    build_content, build_manifest, build_transaction, parse_and_verify_content,
    parse_and_verify_manifest, parse_and_verify_transaction,
};

use super::fixtures::{unsigned_content, unsigned_manifest_with_publisher, unsigned_transaction};

#[test]
fn manifest_round_trip() {
    let publisher_key = SigningKey::from_seed(&[0xA1; 32]);
    let publisher_pk = publisher_key.verifying_key().to_publisher_pubkey();
    let unsigned = unsigned_manifest_with_publisher(publisher_pk);

    let (manifest, bytes) = build_manifest(&unsigned, &publisher_key).expect("build_manifest");
    let parsed = parse_and_verify_manifest(&bytes).expect("parse_and_verify_manifest");

    assert_eq!(
        parsed, manifest,
        "round-tripped manifest must equal builder output"
    );
}

#[test]
fn content_round_trip() {
    let runtime_key = SigningKey::from_seed(&[0xA2; 32]);
    let runtime_pk = runtime_key.verifying_key().to_runtime_pubkey();
    let unsigned = unsigned_content();

    let (content, bytes) = build_content(&unsigned, &runtime_key).expect("build_content");
    let parsed = parse_and_verify_content(&bytes, &runtime_pk).expect("parse_and_verify_content");

    assert_eq!(parsed, content);
}

#[test]
fn transaction_round_trip() {
    let runtime_key = SigningKey::from_seed(&[0xA3; 32]);
    let runtime_pk = runtime_key.verifying_key().to_runtime_pubkey();
    let unsigned = unsigned_transaction();

    let (tx, bytes) = build_transaction(&unsigned, &runtime_key).expect("build_transaction");
    let parsed =
        parse_and_verify_transaction(&bytes, &runtime_pk).expect("parse_and_verify_transaction");

    assert_eq!(parsed, tx);
}
