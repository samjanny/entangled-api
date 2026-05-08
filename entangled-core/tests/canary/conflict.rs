//! `check_canary_conflict` — equal-`issued_at` reconciliation (§08).

use entangled_core::types::keys::RuntimePubkey;
use entangled_core::types::timestamp::EntangledTimestamp;
use entangled_core::validation::canary::{check_canary_conflict, RetainedManifestRecord};
use entangled_core::validation::DiagnosticCode;

use super::common::KEY_ZEROS;

fn ts(s: &str) -> EntangledTimestamp {
    EntangledTimestamp::try_from(s).unwrap()
}

fn rt_zero() -> RuntimePubkey {
    RuntimePubkey::try_from(KEY_ZEROS).unwrap()
}

fn rt_one() -> RuntimePubkey {
    let mut bytes = [0u8; 32];
    bytes[0] = 1;
    RuntimePubkey::from_bytes(bytes)
}

#[test]
fn no_history_no_conflict() {
    let now = ts("2026-05-07T00:00:00Z");
    let hash = [0u8; 32];
    check_canary_conflict(&now, &rt_zero(), &hash, None).expect("no history is not a conflict");
}

#[test]
fn different_issued_at_no_conflict() {
    // Strictly-greater issued_at is not a conflict — anti-downgrade
    // (§08) handles that case separately. `check_canary_conflict` only
    // fires on equal issued_at.
    let retained = RetainedManifestRecord {
        issued_at: ts("2026-05-01T00:00:00Z"),
        runtime_pubkey: rt_zero(),
        manifest_payload_hash: [1u8; 32],
    };
    let new_issued_at = ts("2026-05-07T00:00:00Z");
    let new_hash = [2u8; 32];
    check_canary_conflict(&new_issued_at, &rt_one(), &new_hash, Some(&retained))
        .expect("different issued_at is not a conflict");
}

#[test]
fn equal_issued_at_same_payload_is_refetch_not_conflict() {
    // §08: a byte-for-byte equivalent manifest (same JCS payload, same
    // signature) is a permitted re-fetch, not a conflict.
    let retained = RetainedManifestRecord {
        issued_at: ts("2026-05-07T00:00:00Z"),
        runtime_pubkey: rt_zero(),
        manifest_payload_hash: [42u8; 32],
    };
    let new_issued_at = ts("2026-05-07T00:00:00Z");
    let new_hash = [42u8; 32];
    check_canary_conflict(&new_issued_at, &rt_zero(), &new_hash, Some(&retained))
        .expect("identical re-fetch must not conflict");
}

#[test]
fn equal_issued_at_different_payload_is_conflict() {
    // §08: the publisher MUST NOT issue two distinct manifests with the
    // same canary.issued_at for the same K_publisher.pub. A divergent
    // signed payload at the same issued_at is the classic split-brain
    // attack and triggers E_CANARY_CONFLICT.
    let retained = RetainedManifestRecord {
        issued_at: ts("2026-05-07T00:00:00Z"),
        runtime_pubkey: rt_zero(),
        manifest_payload_hash: [42u8; 32],
    };
    let new_issued_at = ts("2026-05-07T00:00:00Z");
    let new_hash = [99u8; 32];
    let err =
        check_canary_conflict(&new_issued_at, &rt_one(), &new_hash, Some(&retained)).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ECanaryConflict);
    let details = err.details.as_ref().expect("details payload");
    assert_eq!(details["retained_runtime_pubkey"], rt_zero().to_string());
    assert_eq!(details["presented_runtime_pubkey"], rt_one().to_string());
    // The timestamp value is rendered through `EntangledTimestamp::Display`;
    // we just assert that the field is present and non-empty.
    assert!(details["issued_at"].as_str().is_some_and(|s| !s.is_empty()));
}
