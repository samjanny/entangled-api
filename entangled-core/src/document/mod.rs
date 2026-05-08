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
//! [`crate::types::Manifest`], structurally preventing extraction of the
//! bare type from incomplete-stage states. The bare `Manifest` is
//! obtainable only via complete chain (`into_parts`) or explicit
//! `skip_*` opt-out. Stage 7 (trust state) remains the
//! caller's responsibility, applied after the chain completes.
//!
//! The wrappers do not expose the bare [`crate::types::Manifest`]; only
//! field-level accessors are exposed via the [`ManifestRead`] trait
//! pre-canary, with [`crate::types::Canary`] access available
//! post-canary. To obtain a `Manifest` value, callers must complete the
//! chain via [`ManifestOriginBound::into_parts`] or explicitly opt out
//! of further stages via `skip_canary_check` / `skip_origin_check`.

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
pub use verified::{ManifestCanaryChecked, ManifestOriginBound, ManifestRead, ManifestSigVerified};
