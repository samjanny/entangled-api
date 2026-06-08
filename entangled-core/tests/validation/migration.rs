//! `verify_migration_announcement` and `wrap_successor_stage9_failure` -
//! Stage 9 publisher-identity continuity check and the rc.15 wrapper that
//! preserves a successor's underlying Stage 1-9 failure under
//! `E_MIGRATION_MISMATCH` (§10 v1.0-rc.13; details schema in v1.0-rc.15).

use entangled_core::crypto::PublisherSigningKey;
use entangled_core::types::manifest::{Carrier, Manifest, MigrationPointer, OnionAddress, Origin};
use entangled_core::validation::{
    verify_migration_announcement, wrap_successor_stage9_failure, Diagnostic, DiagnosticCode,
    DocumentKindLabel,
};

use super::common::{minimal_manifest, origin_key_real, ts};

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
        not_after: None,
    }
}

/// An announcing manifest that commits (via its `migration_pointer`) to a
/// successor at `announced_origin`, signed by publisher seed `seed`.
fn announcing_with_pointer(seed: u8, announced_origin: Origin) -> Manifest {
    let mut m = manifest_with_publisher_seed(seed);
    m.migration_pointer = Some(MigrationPointer {
        successor_origin: announced_origin,
        announced_at: ts("2026-05-01T00:00:00Z"),
    });
    m
}

/// A successor manifest signed by publisher seed `seed`, fetched from `origin`.
fn successor_at(seed: u8, origin: Origin) -> Manifest {
    let mut m = manifest_with_publisher_seed(seed);
    m.origin = origin;
    m.updated = ts("2026-06-01T00:00:00Z");
    m
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
fn diverging_publisher_pubkey_rejected_with_rc15_details_schema() {
    // §11 v1.0-rc.15: `mismatch_field = "publisher_pubkey"` plus both
    // `announcing_publisher_pubkey` and `successor_publisher_pubkey`.
    let announcing = manifest_with_publisher_seed(0xA1);
    let successor = manifest_with_publisher_seed(0xB2);
    let err = verify_migration_announcement(&announcing, &successor)
        .expect_err("different publisher_pubkey must reject");
    assert_eq!(err.code, DiagnosticCode::EMigrationMismatch);
    let details = err.details.as_ref().expect("details payload");
    assert_eq!(details["mismatch_field"].as_str(), Some("publisher_pubkey"));
    assert_eq!(
        details["announcing_publisher_pubkey"].as_str(),
        Some(announcing.publisher_pubkey.to_string().as_str())
    );
    assert_eq!(
        details["successor_publisher_pubkey"].as_str(),
        Some(successor.publisher_pubkey.to_string().as_str())
    );
    assert_eq!(
        details["announced_successor_address"].as_str(),
        Some(successor.origin.address.as_str())
    );
    // No `underlying_diagnostic_code` for the direct-mismatch path
    // (only the wrap helper attaches it, per rc.16).
    assert!(details.get("underlying_diagnostic_code").is_none());
    // The rc.15 name (`underlying_diagnostic`, an object) is gone in
    // rc.16; the wrapper now emits a string-keyed code identifier under
    // a different field name.
    assert!(details.get("underlying_diagnostic").is_none());
    // Legacy rc.13 keys must not appear under rc.15+.
    assert!(details.get("reason").is_none());
    assert!(details.get("announcing_pubkey").is_none());
    assert!(details.get("successor_pubkey").is_none());
}

#[test]
fn wrap_successor_stage9_failure_preserves_underlying_code_for_stage_5_plus() {
    // §11 v1.0-rc.15 + rc.16: when the successor's own Stage 5
    // succeeded, the wrapper attaches `successor_publisher_pubkey` and
    // records the successor's diagnostic *code identifier* (a JSON
    // string, not a nested record) under `underlying_diagnostic_code`.
    let announcing = manifest_with_publisher_seed(0xA1);
    let successor_address = alt_origin().address;
    let successor_pubkey = manifest_with_publisher_seed(0xA1).publisher_pubkey;

    // Simulate a successor manifest that cleared schema but failed Stage
    // 9 with E_ORIGIN_EXPIRED. The diagnostic mirrors what
    // `check_origin_not_after` would have raised.
    let underlying = Diagnostic::new(
        DiagnosticCode::EOriginExpired,
        DocumentKindLabel::Manifest,
        "origin.not_after 2026-05-07T00:00:00Z is in the past",
    )
    .with_details(serde_json::json!({
        "field_path": "origin.not_after",
        "reason": "origin_expired",
        "not_after": "2026-05-07T00:00:00Z",
        "now": "2026-07-01T00:00:00Z",
    }));

    let wrapped = wrap_successor_stage9_failure(
        &announcing,
        &successor_address,
        Some(&successor_pubkey),
        &underlying,
    );

    assert_eq!(wrapped.code, DiagnosticCode::EMigrationMismatch);
    assert_eq!(wrapped.stage, 9);
    let details = wrapped.details.as_ref().expect("details payload");
    assert_eq!(
        details["mismatch_field"].as_str(),
        Some("successor_stage9_failure")
    );
    assert_eq!(
        details["announced_successor_address"].as_str(),
        Some(successor_address.as_str())
    );
    assert_eq!(
        details["announcing_publisher_pubkey"].as_str(),
        Some(announcing.publisher_pubkey.to_string().as_str())
    );
    assert_eq!(
        details["successor_publisher_pubkey"].as_str(),
        Some(successor_pubkey.to_string().as_str())
    );

    // Code identifier only - rc.16 N22.
    assert_eq!(
        details["underlying_diagnostic_code"].as_str(),
        Some("E_ORIGIN_EXPIRED")
    );
    // The successor's own structured `details` is NOT nested.
    assert!(
        details.get("underlying_diagnostic").is_none(),
        "rc.15 nested-record key must not appear under rc.16"
    );
}

#[test]
fn wrap_successor_stage9_failure_omits_successor_pubkey_for_pre_schema_failure() {
    // §11 v1.0-rc.15: for failures before Stage 5 (parse, byte cap, kind
    // discrimination) the successor's `publisher_pubkey` is not yet
    // validated; callers MUST pass `None` and the wrapper MUST NOT emit
    // the field. The `underlying_diagnostic_code` (rc.16) still records
    // the §11 code identifier of the failure.
    let announcing = manifest_with_publisher_seed(0xA1);
    let successor_address = alt_origin().address;

    let underlying = Diagnostic::new(
        DiagnosticCode::EParseJson,
        DocumentKindLabel::Manifest,
        "malformed JSON",
    );

    let wrapped = wrap_successor_stage9_failure(&announcing, &successor_address, None, &underlying);

    assert_eq!(wrapped.code, DiagnosticCode::EMigrationMismatch);
    let details = wrapped.details.as_ref().expect("details payload");
    assert_eq!(
        details["mismatch_field"].as_str(),
        Some("successor_stage9_failure")
    );
    assert!(
        details.get("successor_publisher_pubkey").is_none(),
        "successor_publisher_pubkey must be omitted for Stage 1-4 failures"
    );
    assert_eq!(
        details["underlying_diagnostic_code"].as_str(),
        Some("E_PARSE_JSON")
    );
}

// --- §10:412 successor origin binding (address + origin_pubkey) ---

#[test]
fn successor_matching_announced_origin_accepted() {
    // The successor is fetched from exactly the address and origin key the
    // announcing publisher committed to: all three §10:412 checks pass.
    let announced = alt_origin();
    let announcing = announcing_with_pointer(0xA1, announced.clone());
    let successor = successor_at(0xA1, announced);
    verify_migration_announcement(&announcing, &successor)
        .expect("successor matching the announced origin must accept");
}

#[test]
fn successor_address_not_announced_rejected() {
    // Same publisher key, but the successor is fetched from a DIFFERENT origin
    // than the one the publisher announced - the §10:412 substitution this
    // binding exists to stop. Rejected with mismatch_field = "address".
    let announced = alt_origin();
    let announcing = announcing_with_pointer(0xA1, announced);
    // The successor's actual origin is the default `onion()`, not the announced
    // `alt_origin()` address.
    let successor = successor_at(0xA1, minimal_manifest().origin);
    let err = verify_migration_announcement(&announcing, &successor)
        .expect_err("a non-announced successor address must reject");
    assert_eq!(err.code, DiagnosticCode::EMigrationMismatch);
    let details = err.details.as_ref().expect("details payload");
    assert_eq!(details["mismatch_field"].as_str(), Some("address"));
    assert_eq!(
        details["announced_successor_address"].as_str(),
        Some(announced_address_str().as_str())
    );
    assert_eq!(
        details["successor_origin_address"].as_str(),
        Some(successor.origin.address.as_str())
    );
}

#[test]
fn successor_origin_pubkey_not_announced_rejected() {
    // The address matches the announcement, but the successor's origin_pubkey
    // differs from the committed one. Rejected with mismatch_field =
    // "origin_pubkey".
    let announced = alt_origin();
    let announcing = announcing_with_pointer(0xA1, announced.clone());
    // Same announced address, but a different origin key than committed.
    let mut tampered = announced;
    tampered.origin_pubkey = origin_key_real();
    let successor = successor_at(0xA1, tampered);
    let err = verify_migration_announcement(&announcing, &successor)
        .expect_err("a successor origin_pubkey that was not announced must reject");
    assert_eq!(err.code, DiagnosticCode::EMigrationMismatch);
    let details = err.details.as_ref().expect("details payload");
    assert_eq!(details["mismatch_field"].as_str(), Some("origin_pubkey"));
}

#[test]
fn announcing_without_pointer_skips_origin_binding() {
    // Defensive arm: with no migration_pointer there is no announced origin to
    // bind against, so only the publisher-pubkey continuity check runs. A
    // matching publisher key accepts regardless of the successor's origin.
    let announcing = manifest_with_publisher_seed(0xA1); // migration_pointer: None
    let successor = successor_at(0xA1, alt_origin());
    verify_migration_announcement(&announcing, &successor)
        .expect("with no announced origin, only publisher continuity is checked");
}

fn announced_address_str() -> String {
    alt_origin().address.as_str().to_owned()
}
