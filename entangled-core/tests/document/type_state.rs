//! Type-state pipeline coverage for `parse_and_verify_manifest`.
//!
//! These tests exercise the chain shape — Stage 6 → Stage 8 → Stage 9 — and
//! the explicit opt-out methods. They complement the per-stage standalone
//! tests in `tests/canary/structure.rs` and `tests/tor/origin_binding.rs`.
//!
//! The `#[must_use]` attribute on `ManifestSigVerified` and
//! `ManifestCanaryChecked` is what closes the foot-gun: a caller cannot
//! silently drop the wrapper without either traversing the chain or
//! explicitly calling `skip_*`. We assert that here at runtime by walking
//! every supported chain shape; the *compile-time* enforcement is a
//! warning under `#[warn(unused_must_use)]` (and a hard error in CI under
//! `-D warnings`). See the `compile_fail` doctest in
//! `entangled-core/src/document/verified.rs` for the must_use canary.
//!
//! Closing the related `manifest().clone()` bypass — i.e. the
//! short-circuit that previously let a caller obtain a bare `Manifest`
//! without traversing Stage 8 / Stage 9 — is enforced by the
//! `compile_fail` doctests on `ManifestRead` in
//! `entangled-core/src/document/verified.rs`, which assert that
//! `wrapper.manifest()` does not resolve for any of the three wrapper
//! types.

use data_encoding::BASE32;
use entangled_core::crypto::SigningKey;
use entangled_core::document::{
    build_manifest, parse_and_verify_manifest, ManifestRead, UnsignedManifest,
};
use entangled_core::types::canary::Canary;
use entangled_core::types::keys::{OriginPubkey, SpecVersion};
use entangled_core::types::manifest::{Carrier, Manifest, OnionAddress, Origin};
use entangled_core::types::EntangledTimestamp;
use entangled_core::validation::canary::CanaryState;
use entangled_core::validation::DiagnosticCode;
use sha3::{Digest, Sha3_256};

use crate::common::{fixed_now, runtime_key_zero, ts};

const ALT_ONION_ADDR: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion";

/// Derive the canonical Tor v3 onion address for a 32-byte service pubkey,
/// per `rend-spec-v3.txt`. Mirrors the helper in `tests/tor/integration_full.rs`.
fn derive_onion_address(pubkey: &[u8; 32]) -> OnionAddress {
    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(pubkey);
    hasher.update([0x03]);
    let digest = hasher.finalize();
    let checksum = [digest[0], digest[1]];
    let mut payload = [0u8; 35];
    payload[..32].copy_from_slice(pubkey);
    payload[32..34].copy_from_slice(&checksum);
    payload[34] = 0x03;
    let body = BASE32.encode(&payload).to_ascii_lowercase();
    let s = format!("{body}.onion");
    OnionAddress::try_from(s.as_str()).expect("derived onion is syntactically valid")
}

/// Build a self-consistent unsigned manifest: the origin block's address
/// is the canonical Tor v3 derivation of the origin pubkey, so Stage 9
/// `verify_origin_binding` can succeed when the same address is presented
/// as the fetch origin.
fn unsigned_manifest_with_consistent_origin(
    publisher_seed: u8,
    origin_seed: u8,
    canary_issued_at: EntangledTimestamp,
    canary_next_expected: EntangledTimestamp,
) -> (SigningKey, OnionAddress, UnsignedManifest) {
    let publisher_key = SigningKey::from_seed(&[publisher_seed; 32]);
    let publisher_pk = publisher_key.verifying_key().to_publisher_pubkey();
    let origin_key = SigningKey::from_seed(&[origin_seed; 32]);
    let origin_pk_bytes = *origin_key.verifying_key().to_origin_pubkey().as_bytes();
    let onion = derive_onion_address(&origin_pk_bytes);

    let unsigned = UnsignedManifest {
        spec_version: SpecVersion,
        publisher_pubkey: publisher_pk,
        origin: Origin {
            carrier: Carrier::TorV3,
            address: onion.clone(),
            origin_pubkey: OriginPubkey::from_bytes(origin_pk_bytes),
        },
        canary: Canary {
            runtime_pubkey: runtime_key_zero(),
            issued_at: canary_issued_at,
            next_expected: canary_next_expected,
            statement: "All clear.".to_owned(),
            freshness_proof: None,
        },
        state_policy: vec![],
        navigation: vec![],
        min_refresh_interval: 86_400,
        updated: ts("2026-05-07T00:00:00Z"),
    };

    (publisher_key, onion, unsigned)
}

/// Build + sign a default-canary manifest with a self-consistent origin
/// block. Returns the signed manifest, its bytes, and the onion address
/// to feed into Stage 9.
fn build_default_consistent_manifest() -> (Manifest, Vec<u8>, OnionAddress) {
    let (publisher_key, onion, unsigned) = unsigned_manifest_with_consistent_origin(
        0xD1,
        0xE1,
        ts("2026-05-07T00:00:00Z"),
        ts("2026-06-07T00:00:00Z"),
    );
    let (manifest, bytes) = build_manifest(&unsigned, &publisher_key, &fixed_now()).expect("build");
    (manifest, bytes, onion)
}

#[test]
fn full_chain_stage_6_8_9_completes() {
    let (built, bytes, onion) = build_default_consistent_manifest();

    let (parsed, canary_state) = parse_and_verify_manifest(&bytes, &fixed_now())
        .expect("Stage 6")
        .verify_canary(&fixed_now())
        .expect("Stage 8")
        .verify_origin(&onion)
        .expect("Stage 9")
        .into_parts();

    assert_eq!(parsed, built, "round-tripped manifest must match");
    // Default canary: issued 2026-05-07, expires 2026-06-07; at `fixed_now()`
    // the full 31-day window is ahead → Fresh.
    assert_eq!(canary_state, CanaryState::Fresh);
}

#[test]
fn skip_canary_check_yields_bare_manifest() {
    let (built, bytes, _onion) = build_default_consistent_manifest();

    // The annotation makes the type explicit; if `skip_canary_check` ever
    // started returning a wrapper, this would stop compiling.
    let parsed: Manifest = parse_and_verify_manifest(&bytes, &fixed_now())
        .expect("Stage 6")
        .skip_canary_check();

    assert_eq!(parsed, built);
}

#[test]
fn skip_origin_check_after_canary_yields_bare_manifest() {
    let (built, bytes, _onion) = build_default_consistent_manifest();

    let parsed: Manifest = parse_and_verify_manifest(&bytes, &fixed_now())
        .expect("Stage 6")
        .verify_canary(&fixed_now())
        .expect("Stage 8")
        .skip_origin_check();

    assert_eq!(parsed, built);
}

#[test]
fn manifest_and_canary_state_readable_pre_into_parts() {
    let (built, bytes, onion) = build_default_consistent_manifest();

    let canary_checked = parse_and_verify_manifest(&bytes, &fixed_now())
        .expect("Stage 6")
        .verify_canary(&fixed_now())
        .expect("Stage 8");

    // Field-level read-only access via `ManifestRead` and the
    // post-canary `canary()` accessor — neither consumes the wrapper, and
    // neither hands out a bare `&Manifest`.
    assert_eq!(canary_checked.publisher_pubkey(), &built.publisher_pubkey);
    assert_eq!(canary_checked.origin(), &built.origin);
    assert_eq!(canary_checked.state_policy(), built.state_policy.as_slice());
    assert_eq!(canary_checked.navigation(), built.navigation.as_slice());
    assert_eq!(
        canary_checked.min_refresh_interval(),
        built.min_refresh_interval
    );
    assert_eq!(canary_checked.updated(), &built.updated);
    assert_eq!(canary_checked.canary(), &built.canary);
    assert_eq!(canary_checked.canary_state(), CanaryState::Fresh);

    // Same for `ManifestOriginBound`.
    let origin_bound = canary_checked.verify_origin(&onion).expect("Stage 9");
    assert_eq!(origin_bound.publisher_pubkey(), &built.publisher_pubkey);
    assert_eq!(origin_bound.origin(), &built.origin);
    assert_eq!(origin_bound.canary(), &built.canary);
    assert_eq!(origin_bound.canary_state(), CanaryState::Fresh);

    // `into_parts` finally consumes and yields the bare `Manifest`.
    let (m, s) = origin_bound.into_parts();
    assert_eq!(m, built);
    assert_eq!(s, CanaryState::Fresh);
}

#[test]
fn sig_verified_wrapper_exposes_field_level_reads() {
    let (built, bytes, _onion) = build_default_consistent_manifest();

    let sig_verified = parse_and_verify_manifest(&bytes, &fixed_now()).expect("Stage 6");
    // The wrapper exposes field-level borrows via `ManifestRead` so
    // callers can read e.g. `state_policy` before deciding to traverse
    // further. The bare `Manifest` is intentionally unreachable here.
    assert_eq!(sig_verified.publisher_pubkey(), &built.publisher_pubkey);
    assert_eq!(sig_verified.origin(), &built.origin);
    assert_eq!(sig_verified.state_policy(), built.state_policy.as_slice());
    assert_eq!(sig_verified.navigation(), built.navigation.as_slice());
    assert_eq!(
        sig_verified.min_refresh_interval(),
        built.min_refresh_interval
    );
    assert_eq!(sig_verified.updated(), &built.updated);

    // We still need to consume the wrapper for the chain to be considered
    // resolved (must_use compliance); skip_canary_check is the explicit
    // opt-out terminal.
    let _bare: Manifest = sig_verified.skip_canary_check();
}

#[test]
fn expired_canary_propagates_as_state_not_error() {
    // 7-day interval (the §08 minimum), entirely in the past relative to
    // `fixed_now()` (2026-05-07): structure is valid, state is Expired.
    let (publisher_key, _onion, unsigned) = unsigned_manifest_with_consistent_origin(
        0xD2,
        0xE2,
        ts("2026-04-01T00:00:00Z"),
        ts("2026-04-08T00:00:00Z"),
    );
    let (_manifest, bytes) =
        build_manifest(&unsigned, &publisher_key, &fixed_now()).expect("build");

    let canary_checked = parse_and_verify_manifest(&bytes, &fixed_now())
        .expect("Stage 6 — signature still verifies for an expired canary")
        .verify_canary(&fixed_now())
        .expect("Stage 8 — Expired is a state, not a structural error");

    assert_eq!(
        canary_checked.canary_state(),
        CanaryState::Expired,
        "canary whose next_expected is in the past must be classified Expired"
    );
}

#[test]
fn structurally_invalid_canary_fails_with_e_canary_invalid() {
    // 1-day interval — below the §08 minimum of 7 days.
    let (publisher_key, _onion, unsigned) = unsigned_manifest_with_consistent_origin(
        0xD3,
        0xE3,
        ts("2026-05-06T00:00:00Z"),
        ts("2026-05-07T00:00:00Z"),
    );
    let (_manifest, bytes) =
        build_manifest(&unsigned, &publisher_key, &fixed_now()).expect("build");

    let err = parse_and_verify_manifest(&bytes, &fixed_now())
        .expect("Stage 6")
        .verify_canary(&fixed_now())
        .expect_err("interval below 7-day minimum must fail Stage 8");

    assert_eq!(err.code, DiagnosticCode::ECanaryInvalid);
}

#[test]
fn origin_mismatch_fails_with_e_bind_origin() {
    let (_built, bytes, _real_onion) = build_default_consistent_manifest();
    let wrong_onion = OnionAddress::try_from(ALT_ONION_ADDR).expect("syntactically valid");

    let err = parse_and_verify_manifest(&bytes, &fixed_now())
        .expect("Stage 6")
        .verify_canary(&fixed_now())
        .expect("Stage 8")
        .verify_origin(&wrong_onion)
        .expect_err("address mismatch must fail Stage 9");

    assert_eq!(err.code, DiagnosticCode::EBindOrigin);
}
