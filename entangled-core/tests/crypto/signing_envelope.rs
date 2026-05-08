//! High-level sign/verify helpers — round-trip per signed-object kind plus
//! domain-separation checks across kinds.

use entangled_core::crypto::{
    sign_content_payload, sign_manifest_payload, sign_transaction_payload, verify_content_payload,
    verify_manifest_payload, verify_transaction_payload, PublisherSigningKey, RuntimeSigningKey,
    SigningError,
};
use entangled_core::types::keys::RuntimePubkey;
use serde_json::json;

fn sample_payload() -> serde_json::Value {
    json!({"foo": "bar", "x": 1})
}

#[test]
fn manifest_round_trip() {
    let key = PublisherSigningKey::from_seed(&[0xA1; 32]);
    let pk = key.verifying_key();
    let payload = sample_payload();
    let sig = sign_manifest_payload(&payload, &key).expect("sign");
    verify_manifest_payload(&payload, &sig, &pk).expect("verify");
}

#[test]
fn content_round_trip() {
    let key = RuntimeSigningKey::from_seed(&[0xA2; 32]);
    let pk = key.verifying_key();
    let payload = sample_payload();
    let sig = sign_content_payload(&payload, &key).expect("sign");
    verify_content_payload(&payload, &sig, &pk).expect("verify");
}

#[test]
fn transaction_round_trip() {
    let key = RuntimeSigningKey::from_seed(&[0xA3; 32]);
    let pk = key.verifying_key();
    let payload = sample_payload();
    let sig = sign_transaction_payload(&payload, &key).expect("sign");
    verify_transaction_payload(&payload, &sig, &pk).expect("verify");
}

#[test]
fn domain_separation_manifest_signature_does_not_verify_as_content() {
    // The same physical key bytes under two role wrappers — exercising
    // the §05 domain-separation property: a manifest sig made with
    // K_publisher does not verify as content under the byte-equal
    // K_runtime, because the per-context preamble differs.
    let seed = [0xB1; 32];
    let publisher_key = PublisherSigningKey::from_seed(&seed);
    let payload = sample_payload();
    let manifest_sig = sign_manifest_payload(&payload, &publisher_key).expect("sign");

    let runtime_pk = RuntimeSigningKey::from_seed(&seed).verifying_key();
    let result = verify_content_payload(&payload, &manifest_sig, &runtime_pk);
    assert!(
        matches!(result, Err(SigningError::Crypto(_))),
        "manifest sig must not verify as content even with the right key, got {result:?}"
    );
}

#[test]
fn domain_separation_content_signature_does_not_verify_as_transaction() {
    let key = RuntimeSigningKey::from_seed(&[0xB2; 32]);
    let payload = sample_payload();
    let content_sig = sign_content_payload(&payload, &key).expect("sign");

    let runtime_pk: RuntimePubkey = key.verifying_key();
    let result = verify_transaction_payload(&payload, &content_sig, &runtime_pk);
    assert!(
        matches!(result, Err(SigningError::Crypto(_))),
        "content sig must not verify as transaction, got {result:?}"
    );
}

#[test]
fn modified_payload_fails_verification() {
    let key = PublisherSigningKey::from_seed(&[0xC1; 32]);
    let pk = key.verifying_key();
    let payload = sample_payload();
    let sig = sign_manifest_payload(&payload, &key).expect("sign");

    let modified = json!({"foo": "BAZ", "x": 1});
    let result = verify_manifest_payload(&modified, &sig, &pk);
    assert!(
        matches!(result, Err(SigningError::Crypto(_))),
        "modified payload must fail verification, got {result:?}"
    );
}

#[test]
fn wrong_key_fails_verification() {
    let signing_a = PublisherSigningKey::from_seed(&[0xD1; 32]);
    let signing_b = PublisherSigningKey::from_seed(&[0xD2; 32]);
    let payload = sample_payload();
    let sig_a = sign_manifest_payload(&payload, &signing_a).expect("sign");

    let pk_b = signing_b.verifying_key();
    let result = verify_manifest_payload(&payload, &sig_a, &pk_b);
    assert!(
        matches!(result, Err(SigningError::Crypto(_))),
        "wrong-key verify must fail, got {result:?}"
    );
}
