//! `verify_migration_announcement` and `wrap_successor_stage9_failure` —
//! Stage 9 publisher-identity continuity check and the rc.15 wrapper that
//! preserves a successor's underlying Stage 1-9 failure under
//! `E_MIGRATION_MISMATCH` (§10 v1.0-rc.13; details schema in v1.0-rc.15).

use entangled_core::crypto::PublisherSigningKey;
use entangled_core::types::manifest::{Carrier, Manifest, OnionAddress, Origin};
use entangled_core::validation::{
    verify_migration_announcement, wrap_successor_stage9_failure, Diagnostic, DiagnosticCode,
    DocumentKindLabel,
};

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
        not_after: None,
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

    // Code identifier only — rc.16 N22.
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
