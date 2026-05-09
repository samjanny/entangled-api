//! Tests for `validation::clock::check_future_timestamp`.

use entangled_core::types::timestamp::EntangledTimestamp;
use entangled_core::validation::clock::{check_future_timestamp, CANARY_ISSUED_AT_FIELD};
use entangled_core::validation::{DiagnosticCode, DocumentKindLabel};

fn ts(s: &str) -> EntangledTimestamp {
    EntangledTimestamp::try_from(s).unwrap()
}

#[test]
fn within_skew_tolerance_passes() {
    let now = ts("2026-05-07T00:00:00Z");
    let later = ts("2026-05-07T00:03:20Z"); // +200s
    check_future_timestamp(
        &later,
        &now,
        "manifest.updated",
        DocumentKindLabel::Manifest,
    )
    .expect("within tolerance");
}

#[test]
fn at_exact_tolerance_boundary_passes() {
    let now = ts("2026-05-07T00:00:00Z");
    let later = ts("2026-05-07T00:05:00Z"); // +300s — boundary inclusive
    check_future_timestamp(
        &later,
        &now,
        "manifest.updated",
        DocumentKindLabel::Manifest,
    )
    .expect("boundary inclusive");
}

#[test]
fn beyond_tolerance_for_manifest_field_emits_field_syntax() {
    // §10 (rc.10): a `manifest.updated` future-skew rejection is
    // `E_SCHEMA_FIELD_SYNTAX` (temporal-domain syntax), with structured
    // `details` carrying `reason: "future_beyond_skew_tolerance"` to
    // distinguish it from lexical RFC 3339 violations.
    let now = ts("2026-05-07T00:00:00Z");
    let later = ts("2026-05-07T00:05:01Z"); // +301s
    let err = check_future_timestamp(
        &later,
        &now,
        "manifest.updated",
        DocumentKindLabel::Manifest,
    )
    .expect_err("must reject");
    assert_eq!(err.code, DiagnosticCode::ESchemaFieldSyntax);
    let details = err.details.as_ref().expect("details payload");
    assert_eq!(
        details["reason"].as_str(),
        Some("future_beyond_skew_tolerance")
    );
    assert_eq!(details["field_path"].as_str(), Some("manifest.updated"));
}

#[test]
fn beyond_tolerance_for_canary_field_emits_canary_invalid() {
    let now = ts("2026-05-07T00:00:00Z");
    let later = ts("2026-05-07T00:05:01Z"); // +301s
    let err = check_future_timestamp(
        &later,
        &now,
        CANARY_ISSUED_AT_FIELD,
        DocumentKindLabel::Manifest,
    )
    .expect_err("must reject");
    assert_eq!(err.code, DiagnosticCode::ECanaryInvalid);
}

#[test]
fn timestamp_in_past_passes() {
    let now = ts("2026-05-07T00:00:00Z");
    let earlier = ts("2026-05-06T00:00:00Z"); // -1 day
    check_future_timestamp(
        &earlier,
        &now,
        "manifest.updated",
        DocumentKindLabel::Manifest,
    )
    .expect("past timestamps always pass this helper");
}
