//! Helpers to manipulate the top-level `sig` field on a parsed `Value`.
//!
//! The §05 signed payload is the envelope object with `sig` removed. These
//! helpers do the surgery for callers — the signer adds `sig` back after
//! computing it, the verifier removes `sig` before reconstructing the
//! signature input.

use serde_json::Value;

use crate::types::keys::Signature;
use crate::validation::{Diagnostic, DiagnosticCode, DocumentKindLabel};

/// Remove and return the top-level `sig` field, expecting a base64url-no-pad
/// 64-byte Ed25519 signature.
///
/// Errors are reported with `document_kind` set by the caller via the
/// [`DocumentKindLabel`] argument so that the diagnostic carries the right
/// kind tag in pipeline contexts.
pub fn extract_sig(value: &mut Value, kind: DocumentKindLabel) -> Result<Signature, Diagnostic> {
    let map = match value {
        Value::Object(m) => m,
        _ => {
            return Err(Diagnostic::new(
                DiagnosticCode::EParseJson,
                kind,
                "envelope is not a JSON object",
            ));
        }
    };
    let sig_value = map.remove("sig").ok_or_else(|| {
        Diagnostic::new(
            DiagnosticCode::EKindMissingFields,
            kind,
            "envelope is missing required field `sig`",
        )
    })?;
    let sig_str = match sig_value {
        Value::String(s) => s,
        _ => {
            return Err(Diagnostic::new(
                DiagnosticCode::EKindMissingFields,
                kind,
                "envelope field `sig` is not a string",
            ));
        }
    };
    Signature::try_from(sig_str.as_str()).map_err(|e| {
        Diagnostic::new(
            DiagnosticCode::ESigMalformed,
            kind,
            format!("envelope field `sig` is malformed: {e}"),
        )
    })
}

/// Insert (or overwrite) the top-level `sig` field on a `Value::Object`.
///
/// Errors only when `value` is not an object — the caller is expected to have
/// constructed the value through serialization of a struct.
pub fn attach_sig(
    value: &mut Value,
    sig: &Signature,
    kind: DocumentKindLabel,
) -> Result<(), Diagnostic> {
    match value {
        Value::Object(map) => {
            map.insert("sig".to_owned(), Value::String(sig.to_string()));
            Ok(())
        }
        _ => Err(Diagnostic::new(
            DiagnosticCode::EParseJson,
            kind,
            "envelope is not a JSON object",
        )),
    }
}
