//! `verify_origin_binding` exercises (Stage 9, §10).

use data_encoding::BASE32;
use entangled_core::crypto::PublisherSigningKey;
use entangled_core::tor::verify_origin_binding;
use entangled_core::types::keys::OriginPubkey;
use entangled_core::types::manifest::{Carrier, OnionAddress, Origin};
use entangled_core::validation::{DiagnosticCode, DocumentKindLabel};
use sha3::{Digest, Sha3_256};

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
    format!("{body}.onion")
}

fn pubkey_from_seed(seed: u8) -> [u8; 32] {
    // Origin keys do not sign anything in the public crate API; tests need
    // the raw 32 pubkey bytes corresponding to a deterministic seed. The
    // bytes are independent of which role newtype wraps the signing key.
    *PublisherSigningKey::from_seed(&[seed; 32])
        .verifying_key()
        .as_bytes()
}

#[test]
fn binding_succeeds_when_address_and_pubkey_align() {
    let pubkey = pubkey_from_seed(0x11);
    let addr = OnionAddress::try_from(make_onion_address(&pubkey).as_str()).unwrap();
    let origin = Origin {
        carrier: Carrier::TorV3,
        address: addr.clone(),
        origin_pubkey: OriginPubkey::from_bytes(pubkey),
    };
    verify_origin_binding(&addr, &origin).expect("must succeed");
}

#[test]
fn binding_fails_on_address_mismatch() {
    let pubkey_a = pubkey_from_seed(0x11);
    let pubkey_b = pubkey_from_seed(0x22);
    let addr_a = OnionAddress::try_from(make_onion_address(&pubkey_a).as_str()).unwrap();
    let addr_b = OnionAddress::try_from(make_onion_address(&pubkey_b).as_str()).unwrap();
    let origin = Origin {
        carrier: Carrier::TorV3,
        address: addr_b,
        origin_pubkey: OriginPubkey::from_bytes(pubkey_b),
    };
    let err = verify_origin_binding(&addr_a, &origin).expect_err("must fail");
    assert_eq!(err.code, DiagnosticCode::EBindOrigin);
    assert_eq!(err.document_kind, DocumentKindLabel::Manifest);
}

#[test]
fn binding_fails_on_pubkey_mismatch() {
    let pubkey_a = pubkey_from_seed(0x33);
    let pubkey_b = pubkey_from_seed(0x44);
    // The manifest claims `origin_pubkey = pubkey_b` but the address embeds
    // `pubkey_a`. The address-vs-pubkey mismatch must fail with E_BIND_ORIGIN.
    let addr = OnionAddress::try_from(make_onion_address(&pubkey_a).as_str()).unwrap();
    let origin = Origin {
        carrier: Carrier::TorV3,
        address: addr.clone(),
        origin_pubkey: OriginPubkey::from_bytes(pubkey_b),
    };
    let err = verify_origin_binding(&addr, &origin).expect_err("must fail");
    assert_eq!(err.code, DiagnosticCode::EBindOrigin);
}

/// `Carrier` is a closed enum with a single variant in v1.0, so the
/// "wrong carrier" branch is currently unreachable through the public API.
/// This test documents the pattern match.
#[test]
fn carrier_variant_is_exhaustive_in_v1() {
    let pubkey = pubkey_from_seed(0x55);
    let addr = OnionAddress::try_from(make_onion_address(&pubkey).as_str()).unwrap();
    let origin = Origin {
        carrier: Carrier::TorV3,
        address: addr.clone(),
        origin_pubkey: OriginPubkey::from_bytes(pubkey),
    };
    // The match in `verify_origin_binding` is exhaustive; matching on the
    // single variant is enough to assert the branch is reachable.
    assert!(matches!(origin.carrier, Carrier::TorV3));
    verify_origin_binding(&addr, &origin).unwrap();
}
