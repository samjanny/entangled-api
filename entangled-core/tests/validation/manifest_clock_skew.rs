//! §06 / §10 clock-skew enforcement on `manifest.updated`.
//!
//! Two layers of coverage:
//!
//! - The standalone helper [`check_manifest_clock_skew`].
//! - The **integration canary**: `parse_and_verify_manifest` and
//!   `validate_manifest` MUST reject manifests with `updated` more than
//!   300 s ahead of `now`. These tests catch the regression the prior
//!   audit found, where the helper existed but was never invoked from the
//!   public pipeline.

use entangled_core::crypto::PublisherSigningKey;
use entangled_core::document::{build_manifest, parse_and_verify_manifest, UnsignedManifest};
use entangled_core::types::canary::Canary;
use entangled_core::types::keys::RuntimePubkey;
use entangled_core::types::manifest::{Carrier, OnionAddress, Origin};
use entangled_core::types::SpecVersion;
use entangled_core::validation::{
    check_manifest_clock_skew, parse_and_validate_manifest, validate_manifest, DiagnosticCode,
};

use super::common::{minimal_manifest, ts, KEY_ZEROS};

#[test]
fn updated_within_skew_tolerance_accepted() {
    let mut m = minimal_manifest();
    m.updated = ts("2026-05-07T00:03:20Z"); // +200s
    let now = ts("2026-05-07T00:00:00Z");
    check_manifest_clock_skew(&m, &now).expect("within 300s tolerance");
}

#[test]
fn updated_at_exact_skew_boundary_accepted() {
    let mut m = minimal_manifest();
    m.updated = ts("2026-05-07T00:05:00Z"); // +300s
    let now = ts("2026-05-07T00:00:00Z");
    check_manifest_clock_skew(&m, &now).expect("exactly +300s is inside the inclusive boundary");
}

#[test]
fn updated_beyond_skew_rejected_as_field_syntax() {
    // §10 (rc.10): future-skew rejection on `manifest.updated` is a
    // temporal-domain syntax violation; details carry `reason`.
    let mut m = minimal_manifest();
    m.updated = ts("2026-05-07T00:06:40Z"); // +400s
    let now = ts("2026-05-07T00:00:00Z");
    let err = check_manifest_clock_skew(&m, &now).expect_err("must reject");
    assert_eq!(err.code, DiagnosticCode::ESchemaFieldSyntax);
    let details = err.details.as_ref().expect("details payload");
    assert_eq!(
        details["reason"].as_str(),
        Some("future_beyond_skew_tolerance")
    );
}

#[test]
fn updated_in_the_past_accepted() {
    let mut m = minimal_manifest();
    m.updated = ts("2026-05-01T00:00:00Z");
    let now = ts("2026-05-07T00:00:00Z");
    check_manifest_clock_skew(&m, &now).expect("past timestamps are unconditionally fine");
}

// -----------------------------------------------------------------------------
// Pipeline-level: `validate_manifest` (Stage 5) directly
// -----------------------------------------------------------------------------

#[test]
fn validate_manifest_accepts_updated_within_tolerance() {
    let mut m = minimal_manifest();
    m.updated = ts("2026-05-07T00:04:00Z"); // +240s
    let now = ts("2026-05-07T00:00:00Z");
    validate_manifest(&m, &now).expect("Stage 5 should accept");
}

#[test]
fn validate_manifest_rejects_updated_beyond_tolerance() {
    let mut m = minimal_manifest();
    m.updated = ts("2026-05-07T00:06:40Z"); // +400s
    let now = ts("2026-05-07T00:00:00Z");
    let err = validate_manifest(&m, &now).expect_err("Stage 5 must reject");
    assert_eq!(err.code, DiagnosticCode::ESchemaFieldSyntax);
}

// -----------------------------------------------------------------------------
// Pipeline-level: `parse_and_validate_manifest` reads from raw bytes
// -----------------------------------------------------------------------------

fn manifest_bytes_with_updated(updated: entangled_core::types::EntangledTimestamp) -> Vec<u8> {
    let mut m = minimal_manifest();
    m.updated = updated;
    let mut v = serde_json::to_value(&m).unwrap();
    v.as_object_mut()
        .unwrap()
        .insert("kind".to_owned(), serde_json::json!("manifest"));
    serde_json::to_vec(&v).unwrap()
}

#[test]
fn parse_and_validate_manifest_rejects_future_updated() {
    let now = ts("2026-05-07T00:00:00Z");
    let bytes = manifest_bytes_with_updated(ts("2026-05-07T00:16:40Z")); // +1000s
    let err = parse_and_validate_manifest(&bytes, &now)
        .expect_err("manifest with updated 1000s in the future must be rejected");
    assert_eq!(err.code, DiagnosticCode::ESchemaFieldSyntax);
    assert!(
        err.message.contains("manifest.updated"),
        "diagnostic should name the offending field, got {}",
        err.message
    );
}

// -----------------------------------------------------------------------------
// Integration canary: end-to-end via `parse_and_verify_manifest`.
//
// This is the canary the prior audit was missing. A manifest is signed by
// its publisher *with* a far-future `updated`, then handed to the public
// parse-and-verify entry point. If the clock-skew check is wired into the
// pipeline, the bytes are rejected with `E_SCHEMA_FIELD_RANGE` and Stage 6
// is never reached. If the wiring regresses, the manifest will pass schema
// and verify the signature successfully, exposing the gap.
// -----------------------------------------------------------------------------

fn unsigned_manifest_for_clock_skew_canary(
    publisher_pk: entangled_core::types::keys::PublisherPubkey,
    updated: entangled_core::types::EntangledTimestamp,
) -> UnsignedManifest {
    unsigned_manifest_with_dates(
        publisher_pk,
        updated,
        ts("2026-05-07T00:00:00Z"),
        ts("2026-06-06T00:00:00Z"),
    )
}

fn unsigned_manifest_with_dates(
    publisher_pk: entangled_core::types::keys::PublisherPubkey,
    updated: entangled_core::types::EntangledTimestamp,
    canary_issued_at: entangled_core::types::EntangledTimestamp,
    canary_next_expected: entangled_core::types::EntangledTimestamp,
) -> UnsignedManifest {
    UnsignedManifest {
        spec_version: SpecVersion,
        publisher_pubkey: publisher_pk,
        origin: Origin {
            carrier: Carrier::TorV3,
            address: OnionAddress::try_from(
                "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion",
            )
            .unwrap(),
            origin_pubkey: entangled_core::types::keys::OriginPubkey::try_from(KEY_ZEROS).unwrap(),
            not_after: None,
        },
        canary: Canary {
            runtime_pubkey: RuntimePubkey::try_from(KEY_ZEROS).unwrap(),
            issued_at: canary_issued_at,
            next_expected: canary_next_expected,
            statement: "All clear.".to_owned(),
            freshness_proof: None,
        },
        state_policy: vec![],
        navigation: vec![],
        min_refresh_interval: 86_400,
        updated,
        migration_pointer: None,
    }
}

#[test]
fn integration_canary_parse_and_verify_rejects_future_dated_manifest() {
    // Publisher signs at a "moment" that allows the future-dated `updated`
    // through the builder. We then hand the bytes to the parser with a `now`
    // that exposes the skew, and expect rejection at Stage 5 — *before* the
    // signature is even checked.
    let publisher_key = PublisherSigningKey::from_seed(&[0x77; 32]);
    let publisher_pk = publisher_key.verifying_key();

    let signing_now = ts("2026-05-07T00:00:00Z");
    let future_updated = ts("2026-05-07T00:16:40Z"); // +1000s vs verifier's `now`

    // Pre-condition: `signing_now` lets the builder accept the future
    // `updated` (the field equals `signing_now`-ish, not in the future
    // relative to itself). The check fires when the verifier later compares
    // `updated` to its own clock.
    let unsigned = unsigned_manifest_for_clock_skew_canary(publisher_pk, future_updated);
    let (_signed, bytes) = build_manifest(&unsigned, &publisher_key, &future_updated)
        .expect("build_manifest with updated == signing_now must succeed");

    // The verifier's clock is 1000s behind the manifest's `updated`.
    let verifier_now = signing_now;
    let err = parse_and_verify_manifest(&bytes, &verifier_now)
        .expect_err("future-dated manifest must be rejected before signature verification");
    assert_eq!(
        err.code,
        DiagnosticCode::ESchemaFieldSyntax,
        "expected Stage 5 clock-skew rejection, got {err}",
    );
    let details = err.details.as_ref().expect("details payload");
    assert_eq!(
        details["reason"].as_str(),
        Some("future_beyond_skew_tolerance")
    );
    assert_eq!(details["field_path"].as_str(), Some("manifest.updated"));
    assert!(
        err.message.contains("manifest.updated"),
        "diagnostic should name `manifest.updated`, got {}",
        err.message,
    );
}

// -----------------------------------------------------------------------------
// Discrimination + precedence: §10 (rc.10) treats `manifest.updated` and
// `canary.issued_at` as separate clock-skew sites with separate diagnostic
// codes. The pair below pins the discriminator behavior of `clock.rs` against
// any future regression that would unify them.
// -----------------------------------------------------------------------------

#[test]
fn integration_future_canary_issued_at_emits_canary_invalid_via_pipeline() {
    // Only `canary.issued_at` is in the future; `manifest.updated` is fine.
    // §10 routes this to Stage 8 (`E_CANARY_INVALID`). It surfaces from
    // `verify_canary`, not from the schema phase.
    let publisher_key = PublisherSigningKey::from_seed(&[0xA1; 32]);
    let publisher_pk = publisher_key.verifying_key();
    let verifier_now = ts("2026-05-07T00:00:00Z");

    let updated = verifier_now;
    // +400s ahead of `now` -> beyond the 300s tolerance.
    let canary_issued = ts("2026-05-07T00:06:40Z");
    let canary_next = ts("2026-06-06T00:06:40Z");

    // Build under a `signing_now` that lets the future-issued canary pass
    // the builder's own clock-skew gate.
    let signing_now = canary_issued;
    let unsigned = unsigned_manifest_with_dates(publisher_pk, updated, canary_issued, canary_next);
    let (_signed, bytes) =
        build_manifest(&unsigned, &publisher_key, &signing_now).expect("build_manifest");

    // Stage 5 (`manifest.updated`) must accept; Stage 8 (`canary.issued_at`)
    // must reject with E_CANARY_INVALID.
    let sig_verified = parse_and_verify_manifest(&bytes, &verifier_now)
        .expect("Stages 2-6 must clear when only canary.issued_at is in the future");
    let err = sig_verified
        .verify_canary(&verifier_now)
        .expect_err("Stage 8 must reject canary.issued_at +400s in the future");
    assert_eq!(err.code, DiagnosticCode::ECanaryInvalid);
    assert!(
        err.message.contains("canary.issued_at"),
        "diagnostic should name `canary.issued_at`, got {}",
        err.message,
    );
}

#[test]
fn integration_both_future_resolves_to_field_syntax_by_pipeline_precedence() {
    // §10 first-failing-stage precedence: when both `manifest.updated` and
    // `canary.issued_at` are in the future, Stage 5 fires first and the
    // surfaced diagnostic is `E_SCHEMA_FIELD_SYNTAX`. Stage 8's
    // `E_CANARY_INVALID` is never reached.
    let publisher_key = PublisherSigningKey::from_seed(&[0xA2; 32]);
    let publisher_pk = publisher_key.verifying_key();
    let verifier_now = ts("2026-05-07T00:00:00Z");

    // Both timestamps are +1000s relative to verifier_now.
    let future = ts("2026-05-07T00:16:40Z");
    let canary_next = ts("2026-06-06T00:16:40Z");

    let unsigned = unsigned_manifest_with_dates(publisher_pk, future, future, canary_next);
    let (_signed, bytes) =
        build_manifest(&unsigned, &publisher_key, &future).expect("build_manifest");

    let err = parse_and_verify_manifest(&bytes, &verifier_now)
        .expect_err("manifest.updated future-skew must trip Stage 5 first");
    assert_eq!(
        err.code,
        DiagnosticCode::ESchemaFieldSyntax,
        "Stage 5 must precede Stage 8 — got {err}",
    );
    let details = err.details.as_ref().expect("details payload");
    assert_eq!(
        details["reason"].as_str(),
        Some("future_beyond_skew_tolerance")
    );
}

#[test]
fn integration_canary_parse_and_verify_accepts_well_dated_manifest() {
    // The mirror of the canary: when `updated` is within tolerance the
    // pipeline still completes successfully. This guards against an
    // over-eager Stage 5 implementation that rejects too aggressively.
    let publisher_key = PublisherSigningKey::from_seed(&[0x88; 32]);
    let publisher_pk = publisher_key.verifying_key();

    let now = ts("2026-05-07T00:00:00Z");
    let unsigned = unsigned_manifest_for_clock_skew_canary(publisher_pk, now);
    let (signed, bytes) =
        build_manifest(&unsigned, &publisher_key, &now).expect("build_manifest must succeed");

    let parsed = parse_and_verify_manifest(&bytes, &now)
        .expect("manifest within skew must be accepted")
        .skip_canary_check();
    assert_eq!(
        parsed, signed,
        "round-tripped manifest must equal builder output",
    );
}
