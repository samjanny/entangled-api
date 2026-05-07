//! Ed25519 wrapper sanity, including the RFC 8032 §7.1 TEST 1 vector.

use entangled_core::crypto::{CryptoError, SigningKey, VerifyingKey};
use entangled_core::types::{PublisherPubkey, Signature};

fn hex_to_bytes(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn rfc8032_section_7_1_test_1() {
    // RFC 8032 §7.1 TEST 1 — the canonical Ed25519 test vector.
    let seed_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    let pubkey_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    let sig_hex = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hex_to_bytes(seed_hex));
    let signing = SigningKey::from_seed(&seed);

    // Pubkey derivation matches the spec.
    let derived: [u8; 32] = *signing.verifying_key().to_publisher_pubkey().as_bytes();
    let mut expected_pk = [0u8; 32];
    expected_pk.copy_from_slice(&hex_to_bytes(pubkey_hex));
    assert_eq!(
        derived, expected_pk,
        "RFC 8032 §7.1 TEST 1: derived public key must match"
    );

    // Signature on empty message matches the spec, byte-for-byte.
    let sig: Signature = signing.sign(b"");
    let mut expected_sig = [0u8; 64];
    expected_sig.copy_from_slice(&hex_to_bytes(sig_hex));
    assert_eq!(
        *sig.as_bytes(),
        expected_sig,
        "RFC 8032 §7.1 TEST 1: signature must be byte-exact"
    );

    // And it verifies.
    let pk = PublisherPubkey::from_bytes(expected_pk);
    let vk = VerifyingKey::from_publisher_pubkey(&pk).expect("valid pubkey");
    vk.verify(b"", &sig).expect("verify must succeed");
}

// Integration tests run as a separate crate and cannot see lib-internal
// `#[cfg(test)]` items. `SigningKey::generate` is gated for test/test-utils,
// so these tests use deterministic seeds via `from_seed` instead — equally
// effective for the verifier-fails-with-wrong-key / wrong-message cases below
// and reproducible across runs.

#[test]
fn deterministic_keypair_round_trip_signs_and_verifies() {
    let signing = SigningKey::from_seed(&[0x11; 32]);
    let pk = signing.verifying_key().to_publisher_pubkey();
    let msg = b"hello entangled";
    let sig = signing.sign(msg);

    let vk = VerifyingKey::from_publisher_pubkey(&pk).unwrap();
    vk.verify(msg, &sig).expect("verify ok");
}

#[test]
fn verify_fails_with_wrong_key() {
    let a = SigningKey::from_seed(&[0x21; 32]);
    let b = SigningKey::from_seed(&[0x22; 32]);
    let msg = b"some message";
    let sig = a.sign(msg);

    let vk_b =
        VerifyingKey::from_publisher_pubkey(&b.verifying_key().to_publisher_pubkey()).unwrap();
    assert_eq!(vk_b.verify(msg, &sig), Err(CryptoError::VerificationFailed));
}

#[test]
fn verify_fails_with_modified_message() {
    let signing = SigningKey::from_seed(&[0x31; 32]);
    let pk = signing.verifying_key().to_publisher_pubkey();
    let mut msg = *b"hello world";
    let sig = signing.sign(&msg);

    msg[0] ^= 0x01;
    let vk = VerifyingKey::from_publisher_pubkey(&pk).unwrap();
    assert_eq!(vk.verify(&msg, &sig), Err(CryptoError::VerificationFailed));
}

#[test]
fn malformed_pubkey_rejected_at_construction() {
    // 32-byte sequence whose Edwards-Y compressed form does not decompress to
    // a valid curve point. Empirically determined: not every 32-byte string
    // is rejected by ed25519-dalek's `from_bytes` (e.g. all-0xFF and y=p both
    // round-trip), but this incrementing pattern fails decompression.
    let bad_bytes: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];
    let bad = PublisherPubkey::from_bytes(bad_bytes);
    assert_eq!(
        VerifyingKey::from_publisher_pubkey(&bad).err(),
        Some(CryptoError::InvalidPublicKey)
    );
}
