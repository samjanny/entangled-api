//! `OnionAddress::decode` and `verify_strict` exercises.

use data_encoding::BASE32;
use entangled_core::crypto::PublisherSigningKey;
use entangled_core::tor::TorError;
use entangled_core::types::manifest::OnionAddress;
use sha3::{Digest, Sha3_256};

/// Build a canonical Tor v3 onion address from a 32-byte Ed25519 pubkey.
fn make_onion_address(pubkey: &[u8; 32]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(pubkey);
    hasher.update([0x03]);
    let digest = hasher.finalize();
    let checksum = [digest[0], digest[1]];

    let mut payload = [0u8; 35];
    payload[..32].copy_from_slice(pubkey);
    payload[32..34].copy_from_slice(&checksum);
    payload[34] = 0x03;

    let body = BASE32.encode(&payload).to_ascii_lowercase();
    assert_eq!(body.len(), 56);
    format!("{body}.onion")
}

fn pubkey_from_seed(seed: u8) -> [u8; 32] {
    // Tests need the raw 32 pubkey bytes for a deterministic seed; the
    // bytes are independent of which role newtype wraps the signing key.
    *PublisherSigningKey::from_seed(&[seed; 32])
        .verifying_key()
        .as_bytes()
}

#[test]
fn self_consistent_round_trip() {
    let pubkey = pubkey_from_seed(0xCC);
    let addr_str = make_onion_address(&pubkey);
    let addr = OnionAddress::try_from(addr_str.as_str()).expect("valid syntax");
    let decoded = addr.verify_strict().expect("must verify");
    assert_eq!(decoded.pubkey.as_bytes(), &pubkey);
    assert_eq!(decoded.version, 0x03);
}

#[test]
fn rejects_uppercase_first_letter() {
    let pubkey = pubkey_from_seed(0xCC);
    let addr_str = make_onion_address(&pubkey);
    let mut bytes: Vec<u8> = addr_str.into_bytes();
    // Find a lowercase letter we can flip to uppercase.
    let i = bytes
        .iter()
        .position(|b| b.is_ascii_lowercase() && *b >= b'a' && *b <= b'z')
        .expect("at least one lowercase letter");
    bytes[i] = bytes[i].to_ascii_uppercase();
    let upper = String::from_utf8(bytes).unwrap();

    // The crate's `OnionAddress` constructor itself rejects uppercase via
    // `OnionAddressError::InvalidBase32`. The Tor decoder layer is reached
    // only on already-syntactically-valid addresses, so we exercise the
    // decoder directly by bypassing the constructor through a private path:
    // build a fresh lowercase address and tamper *after* the constructor
    // accepts it.
    //
    // To test the decoder's `NotLowercase` branch in isolation, we use the
    // unsafe-from-tests pattern of constructing via a permissive helper:
    // since we don't have that, this test checks that the `OnionAddress`
    // constructor itself rejects uppercase (the decoder will never see it).
    let err = OnionAddress::try_from(upper.as_str()).expect_err("constructor rejects uppercase");
    let msg = format!("{err}");
    assert!(msg.contains("base32"), "got: {msg}");
}

#[test]
fn rejects_bad_checksum() {
    let pubkey = pubkey_from_seed(0xCC);
    let addr_str = make_onion_address(&pubkey);
    let mut bytes: Vec<u8> = addr_str.into_bytes();
    // Char index 53 corresponds to a checksum byte. Flip it to a different
    // valid base32 char.
    let idx = 53;
    let original = bytes[idx];
    let replacement = if original == b'a' { b'b' } else { b'a' };
    bytes[idx] = replacement;
    let tampered = String::from_utf8(bytes).unwrap();

    let addr = OnionAddress::try_from(tampered.as_str()).expect("syntactically valid");
    let err = addr.verify_strict().expect_err("must reject");
    assert_eq!(err, TorError::BadChecksum);
}

#[test]
fn rejects_wrong_version() {
    // Build a body whose decoded version byte is 0x02 instead of 0x03.
    // We pick an arbitrary pubkey, then compute a *correct* checksum for
    // that pubkey with version 0x02, so that the only failure surfaced is
    // `WrongVersion(0x02)` and not `BadChecksum`.
    let pubkey = pubkey_from_seed(0xAA);
    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(pubkey);
    hasher.update([0x02]);
    let digest = hasher.finalize();
    let checksum = [digest[0], digest[1]];

    let mut payload = [0u8; 35];
    payload[..32].copy_from_slice(&pubkey);
    payload[32..34].copy_from_slice(&checksum);
    payload[34] = 0x02;
    let body = BASE32.encode(&payload).to_ascii_lowercase();
    let addr_str = format!("{body}.onion");

    let addr = OnionAddress::try_from(addr_str.as_str()).expect("syntactically valid");
    let err = addr.verify_strict().expect_err("must reject");
    assert_eq!(err, TorError::WrongVersion(0x02));
}

#[test]
fn rejects_wrong_length() {
    // 55-char base32 body.
    let too_short = "a".repeat(55) + ".onion";
    let err = OnionAddress::try_from(too_short.as_str()).expect_err("must reject");
    assert!(format!("{err}").contains("characters"));

    // 57-char base32 body.
    let too_long = "a".repeat(57) + ".onion";
    let err = OnionAddress::try_from(too_long.as_str()).expect_err("must reject");
    assert!(format!("{err}").contains("characters"));
}

/// Public test vector: DuckDuckGo's onion service v3 address. We can't verify
/// "the right pubkey" without their key material, but the checksum and version
/// byte must verify under our decoder for the implementation to be
/// interoperable with real onion services.
#[test]
fn duckduckgo_test_vector() {
    let addr_str = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion";
    let addr = OnionAddress::try_from(addr_str).expect("syntactically valid");
    let decoded = addr
        .verify_strict()
        .expect("DuckDuckGo address must verify");
    assert_eq!(decoded.version, 0x03);
}
