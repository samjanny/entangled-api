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

use entangled_core::crypto::SigningKey;
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
fn updated_beyond_skew_rejected_as_field_range() {
    let mut m = minimal_manifest();
    m.updated = ts("2026-05-07T00:06:40Z"); // +400s
    let now = ts("2026-05-07T00:00:00Z");
    let err = check_manifest_clock_skew(&m, &now).expect_err("must reject");
    assert_eq!(err.code, DiagnosticCode::ESchemaFieldRange);
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
    assert_eq!(err.code, DiagnosticCode::ESchemaFieldRange);
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
    assert_eq!(err.code, DiagnosticCode::ESchemaFieldRange);
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
        },
        canary: Canary {
            runtime_pubkey: RuntimePubkey::try_from(KEY_ZEROS).unwrap(),
            issued_at: ts("2026-05-07T00:00:00Z"),
            next_expected: ts("2026-06-07T00:00:00Z"),
            statement: "All clear.".to_owned(),
            freshness_proof: None,
        },
        state_policy: vec![],
        navigation: vec![],
        min_refresh_interval: 86_400,
        updated,
    }
}

#[test]
fn integration_canary_parse_and_verify_rejects_future_dated_manifest() {
    // Publisher signs at a "moment" that allows the future-dated `updated`
    // through the builder. We then hand the bytes to the parser with a `now`
    // that exposes the skew, and expect rejection at Stage 5 — *before* the
    // signature is even checked.
    let publisher_key = SigningKey::from_seed(&[0x77; 32]);
    let publisher_pk = publisher_key.verifying_key().to_publisher_pubkey();

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
        DiagnosticCode::ESchemaFieldRange,
        "expected Stage 5 clock-skew rejection, got {err}",
    );
    assert!(
        err.message.contains("manifest.updated"),
        "diagnostic should name `manifest.updated`, got {}",
        err.message,
    );
}

#[test]
fn integration_canary_parse_and_verify_accepts_well_dated_manifest() {
    // The mirror of the canary: when `updated` is within tolerance the
    // pipeline still completes successfully. This guards against an
    // over-eager Stage 5 implementation that rejects too aggressively.
    let publisher_key = SigningKey::from_seed(&[0x88; 32]);
    let publisher_pk = publisher_key.verifying_key().to_publisher_pubkey();

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
