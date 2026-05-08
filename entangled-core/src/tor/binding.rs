//! Stage 9 fetch-origin binding (§10).
//!
//! Given the `.onion` address from which a manifest was fetched and the
//! `origin` block declared inside that manifest, verify:
//!
//! 1. The carrier is `tor-v3` (the only carrier defined in v1.0).
//! 2. The fetched address byte-equals `origin.address`.
//! 3. The address verifies strictly (correct version + checksum).
//! 4. The pubkey embedded in the address matches `origin.origin_pubkey`.
//!
//! All four checks emit `E_BIND_ORIGIN` on failure, attached to the manifest.

use serde_json::json;

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

    Ok(())
}
