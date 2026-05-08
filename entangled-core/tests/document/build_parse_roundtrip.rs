//! End-to-end round trip: a signed document produced by the builder must
//! parse and verify via the corresponding parser.

use entangled_core::crypto::{PublisherSigningKey, RuntimeSigningKey};
use entangled_core::document::{
    build_content, build_manifest, build_transaction, parse_and_verify_content,
    parse_and_verify_manifest, parse_and_verify_transaction,
};

use super::fixtures::{unsigned_content, unsigned_manifest_with_publisher, unsigned_transaction};
use crate::common::fixed_now;

#[test]
fn manifest_round_trip() {
    let publisher_key = PublisherSigningKey::from_seed(&[0xA1; 32]);
    let publisher_pk = publisher_key.verifying_key();
    let unsigned = unsigned_manifest_with_publisher(publisher_pk);
    let now = fixed_now();

    let (manifest, bytes) =
        build_manifest(&unsigned, &publisher_key, &now).expect("build_manifest");
    let parsed = parse_and_verify_manifest(&bytes, &now)
        .expect("parse_and_verify_manifest")
        .skip_canary_check();

    assert_eq!(
        parsed, manifest,
        "round-tripped manifest must equal builder output"
    );
}

#[test]
fn content_round_trip() {
    let runtime_key = RuntimeSigningKey::from_seed(&[0xA2; 32]);
    let runtime_pk = runtime_key.verifying_key();
    let unsigned = unsigned_content();

    let (content, bytes) = build_content(&unsigned, &runtime_key).expect("build_content");
    let parsed = parse_and_verify_content(&bytes, &runtime_pk).expect("parse_and_verify_content");

    assert_eq!(parsed, content);
}

#[test]
fn transaction_round_trip() {
    let runtime_key = RuntimeSigningKey::from_seed(&[0xA3; 32]);
    let runtime_pk = runtime_key.verifying_key();
    let unsigned = unsigned_transaction();

    let (tx, bytes) = build_transaction(&unsigned, &runtime_key).expect("build_transaction");
    let parsed =
        parse_and_verify_transaction(&bytes, &runtime_pk).expect("parse_and_verify_transaction");

    assert_eq!(parsed, tx);
}
