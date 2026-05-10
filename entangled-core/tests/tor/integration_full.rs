//! End-to-end Pillar B closure: build a manifest signed by the publisher,
//! parse and verify the signature, then verify the origin binding against the
//! `.onion` address derived from the origin key.

use data_encoding::BASE32;
use entangled_core::crypto::{PublisherSigningKey, RuntimeSigningKey};
use entangled_core::document::{build_manifest, parse_and_verify_manifest, UnsignedManifest};
use entangled_core::types::canary::Canary;
use entangled_core::types::keys::{OriginPubkey, SpecVersion};
use entangled_core::types::manifest::{Carrier, OnionAddress, Origin};
use entangled_core::types::timestamp::EntangledTimestamp;
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

fn ts(s: &str) -> EntangledTimestamp {
    EntangledTimestamp::try_from(s).unwrap()
}

#[test]
fn full_pillar_b_closure() {
    // Distinct publisher, origin, and runtime keys (the spec separates the
    // roles). Origin keys are not exposed as a role-typed signing newtype
    // because the crate's public API does not have origin keys signing
    // anything; tests derive the pubkey bytes from a fresh seed via the
    // publisher-role newtype and re-tag the bytes as `OriginPubkey`.
    let publisher_key = PublisherSigningKey::from_seed(&[0xB1; 32]);
    let runtime_key = RuntimeSigningKey::from_seed(&[0xB3; 32]);

    let publisher_pk = publisher_key.verifying_key();
    let origin_pk_bytes = *PublisherSigningKey::from_seed(&[0xB2; 32])
        .verifying_key()
        .as_bytes();
    let runtime_pk = runtime_key.verifying_key();

    // Derive the onion address from the origin pubkey via the canonical
    // Tor v3 procedure.
    let addr_str = make_onion_address(&origin_pk_bytes);
    let onion = OnionAddress::try_from(addr_str.as_str()).expect("syntactically valid");

    let unsigned = UnsignedManifest {
        spec_version: SpecVersion,
        publisher_pubkey: publisher_pk,
        origin: Origin {
            carrier: Carrier::TorV3,
            address: onion.clone(),
            origin_pubkey: OriginPubkey::from_bytes(origin_pk_bytes),
        },
        canary: Canary {
            runtime_pubkey: runtime_pk,
            issued_at: ts("2026-05-07T00:00:00Z"),
            next_expected: ts("2026-06-07T00:00:00Z"),
            statement: "All clear.".to_owned(),
            freshness_proof: None,
        },
        state_policy: vec![],
        navigation: vec![],
        min_refresh_interval: 86_400,
        updated: ts("2026-05-07T00:00:00Z"),
        migration_pointer: None,
    };

    // (a) Sign it.
    let now = ts("2026-05-07T00:00:00Z");
    let (manifest, bytes) =
        build_manifest(&unsigned, &publisher_key, &now).expect("build_manifest");

    // (b) Parse + signature verify, then walk the type-state chain through
    // Stage 8 (canary structure) and Stage 9 (origin binding). The chain is
    // the public way to close Pillar B end-to-end; Stage 9 succeeds iff the
    // address we would have fetched from matches both `manifest.origin.address`
    // and the embedded origin pubkey.
    let (parsed, _canary_state) = parse_and_verify_manifest(&bytes, &now)
        .expect("parse_and_verify_manifest")
        .verify_canary(&now)
        .expect("canary structure")
        .verify_origin(&onion)
        .expect("origin binding must succeed")
        .into_parts();
    assert_eq!(parsed, manifest);
}
