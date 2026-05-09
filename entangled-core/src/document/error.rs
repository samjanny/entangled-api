//! Error type for the `document` API.
//!
//! `DocumentError` aggregates failures from the validation pipeline, the
//! canonicalizer, the high-level signing helpers, and the Ed25519 layer. It
//! exposes [`DocumentError::into_diagnostic`] so callers that need to propagate
//! a §11 diagnostic — for example, parser entry points wrapped by the public
//! Stage 2-6 API — can map any builder failure to the closest matching code.

use thiserror::Error;

use crate::canon::CanonError;
use crate::crypto::{CryptoError, SigningError};
use crate::validation::{Diagnostic, DiagnosticCode, DocumentKindLabel};

/// Aggregated error type for the high-level `document` API.
#[derive(Debug, Error)]
pub enum DocumentError {
    /// A validation pipeline stage rejected the document.
    #[error("validation failed: {0}")]
    Validation(Diagnostic),
    /// JCS canonicalization rejected the payload.
    #[error("canonicalization failed: {0}")]
    Canon(#[from] CanonError),
    /// A high-level sign/verify helper failed (flattened into Canon/Crypto on
    /// `From`).
    #[error("signing failed: {0}")]
    Signing(SigningError),
    /// The Ed25519 layer rejected a key or a signature.
    #[error("crypto failed: {0}")]
    Crypto(#[from] CryptoError),
    /// `serde_json` serialization failed (unreachable through the public API
    /// under the closed schema).
    #[error("serialization failed: {0}")]
    Serialization(serde_json::Error),
}

impl From<Diagnostic> for DocumentError {
    fn from(d: Diagnostic) -> Self {
        Self::Validation(d)
    }
}

impl From<SigningError> for DocumentError {
    fn from(err: SigningError) -> Self {
        match err {
            SigningError::Canon(c) => Self::Canon(c),
            SigningError::Crypto(c) => Self::Crypto(c),
        }
    }
}

impl From<serde_json::Error> for DocumentError {
    fn from(err: serde_json::Error) -> Self {
        Self::Serialization(err)
    }
}

impl DocumentError {
    /// Map any document-layer error to a [`Diagnostic`] tagged with the given
    /// document kind. The mapping table:
    ///
    /// - [`DocumentError::Validation`] → the contained diagnostic, unchanged.
    /// - [`CanonError::NullNotPermitted`] → `E_SCHEMA_NULL_VALUE`.
    /// - [`CanonError::NonIntegerNumber`] / [`CanonError::NumberOutOfRange`]
    ///   → `E_SCHEMA_NON_INTEGER`.
    /// - [`CanonError::MalformedSurrogate`] → `E_SCHEMA_MALFORMED_UNICODE`.
    /// - [`CanonError::UnknownContext`] → `E_SCHEMA_FIELD_TYPE` (internal;
    ///   only triggered if the caller wires a non-normative context string,
    ///   which is impossible through the public API).
    /// - [`CryptoError::VerificationFailed`] → `E_SIG_VERIFICATION`.
    /// - [`CryptoError::InvalidPublicKey`] → `E_SIG_VERIFICATION` with
    ///   `details.reason: "public_key_rejected"`. Per §05 v1.0-rc.4, a
    ///   public key failing the strict profile (non-canonical encoding
    ///   or small-order point) causes the document being verified under
    ///   that key to be rejected as a signature failure.
    ///   `E_SIG_INVALID_KEY` is reserved for "expected verification key
    ///   not available" (e.g. no manifest from which to resolve a
    ///   runtime pubkey) and is emitted by higher-layer callers, not by
    ///   this mapping.
    /// - [`DocumentError::Serialization`] → `E_PARSE_JSON`.
    pub fn into_diagnostic(self, kind: DocumentKindLabel) -> Diagnostic {
        match self {
            Self::Validation(d) => d,
            Self::Canon(CanonError::NullNotPermitted) => Diagnostic::new(
                DiagnosticCode::ESchemaNullValue,
                kind,
                "null literal is not permitted",
            ),
            Self::Canon(CanonError::NonIntegerNumber)
            | Self::Canon(CanonError::NumberOutOfRange) => Diagnostic::new(
                DiagnosticCode::ESchemaNonInteger,
                kind,
                "non-integer numeric value",
            ),
            Self::Canon(CanonError::MalformedSurrogate) => Diagnostic::new(
                DiagnosticCode::ESchemaMalformedUnicode,
                kind,
                "malformed UTF-16 surrogate pair",
            ),
            Self::Canon(CanonError::UnknownContext) => Diagnostic::new(
                DiagnosticCode::ESchemaFieldType,
                kind,
                "unknown signature context",
            ),
            Self::Crypto(CryptoError::VerificationFailed) => Diagnostic::new(
                DiagnosticCode::ESigVerification,
                kind,
                "Ed25519 signature verification failed",
            ),
            Self::Crypto(CryptoError::InvalidPublicKey) => Diagnostic::new(
                DiagnosticCode::ESigVerification,
                kind,
                "Ed25519 public key fails the §05 strict profile (non-canonical or small-order)",
            )
            .with_details(serde_json::json!({
                "reason": "public_key_rejected",
            })),
            Self::Signing(_) => unreachable!(
                "From<SigningError> flattens into Canon/Crypto variants before reaching this point"
            ),
            Self::Serialization(err) => Diagnostic::new(
                DiagnosticCode::EParseJson,
                kind,
                format!("serialization failed: {err}"),
            ),
        }
    }
}
