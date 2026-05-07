//! Canonicalization (RFC 8785 JCS) and signature-input construction.
//!
//! See [`jcs`] for the JCS implementation and [`signature_input`] for the
//! `context || 0x00 || JCS(payload)` envelope used by all signed Entangled
//! objects.

pub mod error;
pub mod jcs;
pub mod signature_input;

pub use error::CanonError;
pub use jcs::canonicalize;
pub use signature_input::{
    build_content_signature_input, build_manifest_signature_input, build_signature_input,
    build_transaction_signature_input, CONTENT_CONTEXT, MANIFEST_CONTEXT, TRANSACTION_CONTEXT,
};
