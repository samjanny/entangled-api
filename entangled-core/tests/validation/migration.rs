//! `verify_migration_announcement` — Stage 9 publisher-identity continuity
//! check across an announcing manifest and its successor (§10 v1.0-rc.13).

use entangled_core::crypto::PublisherSigningKey;
use entangled_core::types::manifest::{Carrier, Manifest, OnionAddress, Origin};
use entangled_core::validation::{verify_migration_announcement, DiagnosticCode};

use super::common::{minimal_manifest, ts};

fn manifest_with_publisher_seed(seed: u8) -> Manifest {
    let publisher_pk = PublisherSigningKey::from_seed(&[seed; 32]).verifying_key();
    let mut m = minimal_manifest();
    m.publisher_pubkey = publisher_pk;
    m
}

fn alt_origin() -> Origin {
    Origin {
        carrier: Carrier::TorV3,
        address: OnionAddress::try_from(
            "ssssssssssssssssssssssssssssssssssssssssssssssssssssssss.onion",
        )
        .unwrap(),
        origin_pubkey: minimal_manifest().origin.origin_pubkey,
    }
}

#[test]
fn matching_publisher_pubkey_accepted() {
    let announcing = manifest_with_publisher_seed(0xA1);
    let mut successor = manifest_with_publisher_seed(0xA1);
    successor.origin = alt_origin();
    successor.updated = ts("2026-06-01T00:00:00Z");
    verify_migration_announcement(&announcing, &successor)
        .expect("identical publisher_pubkey must accept");
}

#[test]
fn diverging_publisher_pubkey_rejected_with_e_migration_mismatch() {
    let announcing = manifest_with_publisher_seed(0xA1);
    let successor = manifest_with_publisher_seed(0xB2);
    let err = verify_migration_announcement(&announcing, &successor)
        .expect_err("different publisher_pubkey must reject");
    assert_eq!(err.code, DiagnosticCode::EMigrationMismatch);
    let details = err.details.as_ref().expect("details payload");
    assert_eq!(
        details["reason"].as_str(),
        Some("publisher_identity_mismatch")
    );
    assert!(details["announcing_pubkey"].is_string());
    assert!(details["successor_pubkey"].is_string());
}
