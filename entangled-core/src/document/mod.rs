//! High-level document API: build a signed envelope from an `Unsigned*`
//! struct, or run pipeline Stages 2-6 to parse and self-verify a signed
//! envelope.
//!
//! This module is the end-to-end story that combines the validation pipeline
//! (Stages 2-5), JCS canonicalization, the per-context signature input
//! envelope, and Ed25519 strict verification.
//!
//! For manifests, [`parse_and_verify_manifest`] returns a
//! [`ManifestSigVerified`] type-state wrapper rather than a bare
//! [`crate::types::Manifest`], forcing the caller at compile time to
//! traverse Stages 8 (canary) and 9 (origin binding) explicitly via
//! [`ManifestSigVerified::verify_canary`] and
//! [`ManifestCanaryChecked::verify_origin`], or to opt out via the
//! corresponding `skip_*` methods. Stage 7 (trust state) remains the
//! caller's responsibility, applied after the chain completes.

pub mod builder;
pub mod envelope;
pub mod error;
pub mod parser;
pub mod unsigned;
pub mod verified;

pub use builder::{build_content, build_manifest, build_transaction};
pub use envelope::{attach_sig, extract_sig};
pub use error::DocumentError;
pub use parser::{
    parse_and_verify_content, parse_and_verify_manifest, parse_and_verify_transaction,
};
pub use unsigned::{UnsignedContent, UnsignedManifest, UnsignedTransaction};
pub use verified::{ManifestCanaryChecked, ManifestOriginBound, ManifestSigVerified};
