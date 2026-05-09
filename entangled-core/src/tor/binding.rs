//! Stage 9 fetch-origin binding (§10).
//!
//! Given the `.onion` address from which a manifest was fetched and the
//! `origin` block declared inside that manifest, verify:
//!
//! 1. The carrier is `tor-v3` (the only carrier defined in v1.0).
//! 2. The fetched address byte-equals `origin.address`.
//! 3. The address verifies strictly (correct version + checksum).
//! 4. The pubkey embedded in the address matches `origin.origin_pubkey`.
//! 5. `origin.origin_pubkey` satisfies the §05 Ed25519 strict profile
//!    (canonical encoding, non-small-order). Without this check, a manifest
//!    could declare a small-order origin pubkey that no other pipeline
//!    stage rejects (the onion address binding is byte-equality, and
//!    K_origin never verifies a signature in v1).
//!
//! All five checks emit `E_BIND_ORIGIN` on failure, attached to the manifest.

use serde_json::json;

use crate::crypto::validate_origin_pubkey_strict;
use crate::types::manifest::{Carrier, OnionAddress, Origin};
use crate::validation::diagnostic::{Diagnostic, DiagnosticCode, DocumentKindLabel};

/// Verify that a fetched onion address is consistent with the `origin` block
/// of the manifest delivered through it.
pub fn verify_origin_binding(
    fetched_address: &OnionAddress,
    manifest_origin: &Origin,
) -> Result<(), Diagnostic> {
    // (1) carrier sanity. v1.0 only defines `tor-v3`; this is defensive
    // against a future spec extension where additional carriers exist.
    match manifest_origin.carrier {
        Carrier::TorV3 => {}
    }

    // (2) byte-exact address comparison. Both values are already normalized
    // to lowercase by `OnionAddress::try_from`, so a string comparison is
    // equivalent to "byte-exact after lowercasing and adding .onion".
    if fetched_address.as_str() != manifest_origin.address.as_str() {
        return Err(Diagnostic::new(
            DiagnosticCode::EBindOrigin,
            DocumentKindLabel::Manifest,
            "fetched onion address does not match manifest.origin.address",
        )
        .with_details(json!({
            "fetched": fetched_address.as_str(),
            "manifest": manifest_origin.address.as_str(),
        })));
    }

    // (3) strict address verification: version + checksum.
    let decoded = fetched_address
        .verify_strict()
        .map_err(|e| e.into_diagnostic(DocumentKindLabel::Manifest))?;

    // (4) pubkey embedded in the address must equal the declared origin_pubkey.
    if decoded.pubkey != manifest_origin.origin_pubkey {
        return Err(Diagnostic::new(
            DiagnosticCode::EBindOrigin,
            DocumentKindLabel::Manifest,
            "origin_pubkey does not match key derived from .onion address",
        ));
    }

    // (5) §05 strict profile applies to K_origin.pub for Ed25519 carriers
    // (Tor v3). The address-binding check above is byte-equality between two
    // 32-byte values; it does not reject a small-order or non-canonical
    // origin pubkey. K_origin never verifies a signature in v1, so this is
    // the only stage at which the strict profile can be enforced for it.
    if validate_origin_pubkey_strict(&manifest_origin.origin_pubkey).is_err() {
        return Err(Diagnostic::new(
            DiagnosticCode::EBindOrigin,
            DocumentKindLabel::Manifest,
            "origin.origin_pubkey fails the §05 strict profile (non-canonical or small-order)",
        )
        .with_details(json!({
            "field_path": "origin.origin_pubkey",
            "reason": "public_key_rejected",
        })));
    }

    Ok(())
}
