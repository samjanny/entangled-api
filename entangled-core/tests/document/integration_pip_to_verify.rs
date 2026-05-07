//! Pillar B end-to-end: the PIP alone is enough to recover the publisher
//! pubkey and verify a manifest signature, with no external trust anchor.

use entangled_core::crypto::{derive_pip, pip_to_pubkey, SigningKey};
use entangled_core::document::{build_manifest, parse_and_verify_manifest};

use super::fixtures::unsigned_manifest_with_publisher;

#[test]
fn pip_round_trip_to_verified_manifest() {
    let publisher_key = SigningKey::from_seed(&[0xC0; 32]);
    let publisher_pk = publisher_key.verifying_key().to_publisher_pubkey();
    let pip = derive_pip(&publisher_pk);

    let unsigned = unsigned_manifest_with_publisher(publisher_pk);
    let (manifest, bytes) = build_manifest(&unsigned, &publisher_key).expect("build");

    // Out-of-band, the user receives only the PIP and recovers the pubkey.
    let recovered = pip_to_pubkey(&pip).expect("pip round-trip");
    assert_eq!(
        recovered.as_bytes(),
        manifest.publisher_pubkey.as_bytes(),
        "PIP must yield the same pubkey byte-for-byte",
    );

    // The same PIP-recovered pubkey appears in the verified manifest.
    let parsed = parse_and_verify_manifest(&bytes).expect("parse_and_verify");
    assert_eq!(
        parsed.publisher_pubkey.as_bytes(),
        recovered.as_bytes(),
        "verified manifest pubkey must equal PIP-recovered pubkey",
    );
}
