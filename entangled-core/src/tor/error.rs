//! Error type for the Tor v3 onion-address subsystem.
//!
//! `TorError` covers the byte-level decoding of a `.onion` v3 address (§05
//! "Carrier origin binding") and is mapped to normative diagnostics via
//! [`TorError::into_diagnostic`].
//!
//! ## Mapping rationale
//!
//! Structural decode failures (`WrongLength`, `MissingOnionSuffix`,
//! `NotLowercase`, `InvalidBase32`) map to `E_SCHEMA_FIELD_SYNTAX` because the
//! address is rejected at the same stage where the wire syntax of the field
//! `origin.address` is checked (§10 Stage 5).
//!
//! `WrongVersion` and `BadChecksum` are mapped to `E_BIND_ORIGIN` (§10 Stage
//! 9). Although `WrongVersion` is arguably also a syntactic constraint on the
//! field, both checks operate on the cryptographic relationship between the
//! address and the embedded public key — they are part of the address↔pubkey
//! binding rather than mere field-shape checks. We mirror the §05 framing
//! ("checksum verification" sits next to "binding origin to pubkey") and emit
//! both under the binding code so callers can distinguish "the address looked
//! wrong" (Stage 5) from "the address contradicts itself" (Stage 9).

use thiserror::Error;

use crate::validation::diagnostic::{Diagnostic, DiagnosticCode, DocumentKindLabel};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TorError {
    #[error("address must be 62 characters total (56 base32 + .onion)")]
    WrongLength,
    #[error("address must end with .onion suffix")]
    MissingOnionSuffix,
    #[error("address must be lowercase base32 (RFC 4648)")]
    NotLowercase,
    #[error("address contains invalid base32 characters")]
    InvalidBase32,
    #[error("address version byte must be 0x03 (Tor v3), got {0:#04x}")]
    WrongVersion(u8),
    #[error("checksum verification failed")]
    BadChecksum,
}

impl TorError {
    /// Map a `TorError` onto the normative diagnostic catalog.
    ///
    /// See module docs for the rationale behind the Stage 5 vs Stage 9 split.
    pub fn into_diagnostic(&self, document_kind: DocumentKindLabel) -> Diagnostic {
        match self {
            TorError::WrongLength
            | TorError::MissingOnionSuffix
            | TorError::NotLowercase
            | TorError::InvalidBase32 => Diagnostic::new(
                DiagnosticCode::ESchemaFieldSyntax,
                document_kind,
                self.to_string(),
            ),
            TorError::WrongVersion(_) | TorError::BadChecksum => {
                Diagnostic::new(DiagnosticCode::EBindOrigin, document_kind, self.to_string())
            }
        }
    }
}
