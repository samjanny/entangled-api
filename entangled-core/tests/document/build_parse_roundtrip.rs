//! End-to-end round trip: a signed document produced by the builder must
//! parse and verify via the corresponding parser.

use entangled_core::crypto::{PublisherSigningKey, RuntimeSigningKey};
use entangled_core::document::{
    build_content, build_manifest, build_transaction, parse_and_verify_content,
    parse_and_verify_manifest, parse_and_verify_transaction, DocumentError,
};
use entangled_core::validation::DiagnosticCode;

use super::fixtures::{unsigned_content, unsigned_manifest_with_publisher, unsigned_transaction};
use crate::common::{fixed_now, ts};

#[test]
fn manifest_round_trip() {
    let publisher_key = PublisherSigningKey::from_seed(&[0xA1; 32]);
    let publisher_pk = publisher_key.verifying_key();
    let unsigned = unsigned_manifest_with_publisher(publisher_pk);
    let now = fixed_now();

    let (manifest, bytes) =
        build_manifest(&unsigned, &publisher_key, &now).expect("build_manifest");
    let parsed = parse_and_verify_manifest(&bytes, &now)
        .expect("parse_and_verify_manifest")
        .skip_canary_check();

    assert_eq!(
        parsed, manifest,
        "round-tripped manifest must equal builder output"
    );
}

#[test]
fn content_round_trip() {
    let runtime_key = RuntimeSigningKey::from_seed(&[0xA2; 32]);
    let runtime_pk = runtime_key.verifying_key();
    let unsigned = unsigned_content();

    let (content, bytes) = build_content(&unsigned, &runtime_key).expect("build_content");
    let parsed = parse_and_verify_content(&bytes, &runtime_pk).expect("parse_and_verify_content");

    assert_eq!(parsed, content);
}

#[test]
fn transaction_round_trip() {
    let runtime_key = RuntimeSigningKey::from_seed(&[0xA3; 32]);
    let runtime_pk = runtime_key.verifying_key();
    let unsigned = unsigned_transaction();

    let (tx, bytes) = build_transaction(&unsigned, &runtime_key).expect("build_transaction");
    let parsed =
        parse_and_verify_transaction(&bytes, &runtime_pk).expect("parse_and_verify_transaction");

    assert_eq!(parsed, tx);
}

#[test]
fn build_manifest_rejects_origin_not_after_at_or_before_issued_at() {
    // M-3 regression: builder must enforce the same Stage 5 semantic
    // constraints on `origin.not_after` that the verifier enforces, so a
    // malformed publisher cannot sign a manifest the parser will later
    // reject. Section 06: not_after MUST be strictly later than
    // canary.issued_at.
    let publisher_key = PublisherSigningKey::from_seed(&[0xA4; 32]);
    let publisher_pk = publisher_key.verifying_key();
    let mut unsigned = unsigned_manifest_with_publisher(publisher_pk);
    unsigned.origin.not_after = Some(
        unsigned
            .canary
            .issued_at
            .validate()
            .expect("fixture issued_at is valid"),
    );
    let now = fixed_now();

    let err = build_manifest(&unsigned, &publisher_key, &now)
        .expect_err("not_after == issued_at must be rejected by the builder");
    match err {
        DocumentError::Validation(d) => {
            assert_eq!(d.code, DiagnosticCode::EOriginInvalid);
        }
        other => panic!("expected DocumentError::Validation, got {other:?}"),
    }
}

#[test]
fn build_manifest_rejects_origin_not_after_beyond_five_year_horizon() {
    // M-3 companion: not_after more than five years after
    // canary.issued_at must also be rejected at build time (Section 06).
    let publisher_key = PublisherSigningKey::from_seed(&[0xA5; 32]);
    let publisher_pk = publisher_key.verifying_key();
    let mut unsigned = unsigned_manifest_with_publisher(publisher_pk);
    unsigned.origin.not_after = Some(ts("2031-05-08T00:00:00Z"));
    let now = fixed_now();

    let err = build_manifest(&unsigned, &publisher_key, &now)
        .expect_err("not_after beyond 5y must be rejected by the builder");
    match err {
        DocumentError::Validation(d) => {
            assert_eq!(d.code, DiagnosticCode::EOriginInvalid);
        }
        other => panic!("expected DocumentError::Validation, got {other:?}"),
    }
}
