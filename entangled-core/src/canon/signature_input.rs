//! Signature-input construction for signed Entangled objects (§05).
//!
//! Every signed Entangled object combines:
//!
//! ```text
//! signature_input = context_string || 0x00 || JCS(signed_payload)
//! ```
//!
//! The null-byte separator is unambiguous because JCS canonical JSON is UTF-8
//! text and emits no `0x00` byte as a structural separator.
//!
//! Domain separation is normative. Only the three context strings below are
//! accepted; arbitrary contexts are rejected with [`CanonError::UnknownContext`].

use serde_json::Value;

use super::error::CanonError;
use super::jcs::canonicalize;

pub const MANIFEST_CONTEXT: &str = "ENTANGLED-v1 manifest";
pub const CONTENT_CONTEXT: &str = "ENTANGLED-v1 content";
pub const TRANSACTION_CONTEXT: &str = "ENTANGLED-v1 transaction";

/// Build `context || 0x00 || JCS(payload)` for one of the three normative
/// contexts. Other context strings are rejected.
pub fn build_signature_input(context: &str, payload: &Value) -> Result<Vec<u8>, CanonError> {
    if context != MANIFEST_CONTEXT && context != CONTENT_CONTEXT && context != TRANSACTION_CONTEXT {
        return Err(CanonError::UnknownContext);
    }
    let canonical = canonicalize(payload)?;
    let mut out = Vec::with_capacity(context.len() + 1 + canonical.len());
    out.extend_from_slice(context.as_bytes());
    out.push(0x00);
    out.extend_from_slice(&canonical);
    Ok(out)
}

pub fn build_manifest_signature_input(payload: &Value) -> Result<Vec<u8>, CanonError> {
    build_signature_input(MANIFEST_CONTEXT, payload)
}

pub fn build_content_signature_input(payload: &Value) -> Result<Vec<u8>, CanonError> {
    build_signature_input(CONTENT_CONTEXT, payload)
}

pub fn build_transaction_signature_input(payload: &Value) -> Result<Vec<u8>, CanonError> {
    build_signature_input(TRANSACTION_CONTEXT, payload)
}
