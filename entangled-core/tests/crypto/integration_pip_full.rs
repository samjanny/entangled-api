//! End-to-end Pillar B trust-architecture check: PIP is a faithful and
//! complete representation of the publisher pubkey used to verify a manifest
//! signature.

use entangled_core::crypto::{
    derive_pip, pip_to_pubkey, sign_manifest_payload, verify_manifest_payload, SigningKey,
};
use serde_json::json;

#[test]
fn pip_round_trip_then_verifies_manifest_signature() {
    // 1. Publisher derives a SigningKey.
    let publisher_key = SigningKey::from_seed(&[0xAB; 32]);

    // 2. Extract publisher pubkey.
    let publisher_pk = publisher_key.verifying_key().to_publisher_pubkey();

    // 3. Compute the PIP, which is what the publisher communicates out-of-band.
    let pip = derive_pip(&publisher_pk);

    // 4. Sign a manifest payload with the publisher key.
    let manifest_payload = json!({
        "spec_version": "1.0",
        "kind": "manifest",
        "title": "Example",
    });
    let sig = sign_manifest_payload(&manifest_payload, &publisher_key).expect("sign");

    // 5. From only the PIP (out-of-band), recover the pubkey.
    let recovered_pk = pip_to_pubkey(&pip).expect("PIP must round-trip");
    assert_eq!(
        recovered_pk.as_bytes(),
        publisher_pk.as_bytes(),
        "PIP must yield the original pubkey byte-for-byte"
    );

    // 6. Verify the manifest signature using only the pubkey recovered from the PIP.
    verify_manifest_payload(&manifest_payload, &sig, &recovered_pk)
        .expect("verify with pubkey-from-PIP must succeed");
}
