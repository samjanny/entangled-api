//! Stage 9 transaction binding helpers (§10).
//!
//! Once a transaction document has cleared Stage 6 self-verification (via
//! [`crate::document::parse_and_verify_transaction`]), the spec requires
//! three byte-exact binding checks to tie it to the originating submit:
//!
//! * `in_response_to` MUST equal the path the client posted to
//!   (`E_BIND_RESPONSE_PATH`, §11);
//! * `request_id` MUST equal the `request_id` the client placed in the
//!   submit body (`E_BIND_REQUEST_ID`, §11);
//! * `request_hash` MUST equal the SHA-256 digest of the JCS-canonical
//!   submit body the client sent (`E_BIND_REQUEST_HASH`, §11).
//!
//! Mirrors [`crate::tor::verify_origin_binding`] for manifests:
//! single entry point, byte-exact comparisons, no I/O. The diagnostics it
//! emits carry structured `details = { expected, received }` for the
//! request-id / request-hash failures (§11).

use data_encoding::BASE64URL_NOPAD;

use crate::canon::canonicalize;
use crate::crypto::sha256;
use crate::state::SubmitBody;
use crate::types::document::TransactionDocument;
use crate::types::path::EntangledPath;
use crate::validation::diagnostic::{Diagnostic, DiagnosticCode, DocumentKindLabel};

/// Verify the three Stage 9 binding fields of a transaction document
/// against the originating submit (§10).
///
/// `submit_path` is the path the client posted the submit to.
/// `submit_body` is the body the client sent — the helper canonicalizes
/// it via JCS and SHA-256-hashes those bytes to compare against
/// `tx.request_hash`. The `request_id` carried by `submit_body` is
/// compared against `tx.request_id`.
///
/// Returns `Err` on the first failing check, in §10 stage order:
/// path mismatch → `E_BIND_RESPONSE_PATH`, request-id mismatch →
/// `E_BIND_REQUEST_ID`, request-hash mismatch → `E_BIND_REQUEST_HASH`.
///
/// # Errors
///
/// `E_BIND_RESPONSE_PATH`, `E_BIND_REQUEST_ID`, or `E_BIND_REQUEST_HASH`
/// per §11 — exactly one is returned, others remain unchecked.
pub fn verify_transaction_binding(
    tx: &TransactionDocument,
    submit_path: &EntangledPath,
    submit_body: &SubmitBody,
) -> Result<(), Diagnostic> {
    if &tx.in_response_to != submit_path {
        return Err(Diagnostic::new(
            DiagnosticCode::EBindResponsePath,
            DocumentKindLabel::Transaction,
            format!(
                "transaction.in_response_to {:?} does not match submit path {:?}",
                tx.in_response_to.as_str(),
                submit_path.as_str()
            ),
        )
        .with_details(serde_json::json!({
            "expected": submit_path.as_str(),
            "received": tx.in_response_to.as_str(),
        })));
    }

    if tx.request_id != submit_body.request_id {
        return Err(Diagnostic::new(
            DiagnosticCode::EBindRequestId,
            DocumentKindLabel::Transaction,
            "transaction.request_id does not match the request_id placed in the submit body",
        )
        .with_details(serde_json::json!({
            "expected": submit_body.request_id.to_string(),
            "received": tx.request_id.to_string(),
        })));
    }

    let body_value = serde_json::to_value(submit_body).map_err(|e| {
        Diagnostic::new(
            DiagnosticCode::EBindRequestHash,
            DocumentKindLabel::Transaction,
            format!("failed to serialize submit body for hash binding: {e}"),
        )
    })?;
    let canonical = canonicalize(&body_value).map_err(|e| {
        Diagnostic::new(
            DiagnosticCode::EBindRequestHash,
            DocumentKindLabel::Transaction,
            format!("failed to JCS-canonicalize submit body for hash binding: {e}"),
        )
    })?;
    let local_hash = sha256(&canonical);

    if &local_hash != tx.request_hash.as_bytes() {
        return Err(Diagnostic::new(
            DiagnosticCode::EBindRequestHash,
            DocumentKindLabel::Transaction,
            "transaction.request_hash does not match the locally computed hash of the submit body",
        )
        .with_details(serde_json::json!({
            "expected": format!("sha-256:{}", BASE64URL_NOPAD.encode(&local_hash)),
            "received": tx.request_hash.to_string(),
        })));
    }

    Ok(())
}
