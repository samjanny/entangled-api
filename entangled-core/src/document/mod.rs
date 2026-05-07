//! High-level document API: build a signed envelope from an `Unsigned*`
//! struct, or run pipeline Stages 2-6 to parse and self-verify a signed
//! envelope.
//!
//! This module is the end-to-end story that combines the validation pipeline
//! (Stages 2-5), JCS canonicalization, the per-context signature input
//! envelope, and Ed25519 strict verification. Higher-pipeline stages (trust
//! state, canary, binding) are out of scope.

pub mod builder;
pub mod envelope;
pub mod error;
pub mod parser;
pub mod unsigned;

pub use builder::{build_content, build_manifest, build_transaction};
pub use envelope::{attach_sig, extract_sig};
pub use error::DocumentError;
pub use parser::{
    parse_and_verify_content, parse_and_verify_manifest, parse_and_verify_transaction,
};
pub use unsigned::{UnsignedContent, UnsignedManifest, UnsignedTransaction};
