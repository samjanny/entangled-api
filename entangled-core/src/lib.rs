//! Rust implementation of the Entangled v1.0 protocol.
//!
//! This crate covers the static API surface of the protocol: typed wire
//! formats ([`types`]), JSON canonicalization ([`canon`]), Ed25519 signing
//! and BIP-39 PIP derivation ([`crypto`]), the Stage 2-5 validation pipeline
//! plus canary, clock-skew, and state-policy checks ([`validation`]),
//! end-to-end builder/parser helpers ([`document`]), the client-side state
//! store ([`state`]), and Tor v3 onion-address handling ([`tor`]).
//!
//! Transport, the trust-state machine (Stage 7), publisher history persistence,
//! and consent UI are out of scope for this crate.
//!
//! The full protocol specification lives at
//! <https://github.com/samjanny/entangled>.
//!
//! # Quick start
//!
//! Derive a Publisher Identity Phrase (PIP) and recover the public key from it:
//!
//! ```
//! use entangled_core::crypto::{derive_pip, pip_to_pubkey, PublisherSigningKey};
//!
//! let publisher = PublisherSigningKey::from_seed(&[0x42; 32]);
//! let publisher_pubkey = publisher.verifying_key();
//!
//! let pip = derive_pip(&publisher_pubkey);
//! assert_eq!(pip.split_whitespace().count(), 24);
//!
//! let recovered = pip_to_pubkey(&pip).unwrap();
//! assert_eq!(recovered, publisher_pubkey);
//! ```
//!
//! # Forbidden unsafe
//!
//! `#![forbid(unsafe_code)]` is enforced at the crate root. Some transitive
//! dependencies (`ed25519-dalek`, `curve25519-dalek`, `sha2`, `sha3`) contain
//! `unsafe` for SIMD and field-arithmetic optimizations; they are maintained
//! by the RustCrypto and dalek-cryptography projects.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![deny(missing_docs)]

/// Upstream spec revision this crate is aligned against.
///
/// Matches the upstream corpus's `rc_target` field (no leading `v`,
/// which is reserved for the git tag form `v1.0-rc.19`). Bumped in
/// lockstep with the CI conformance-corpus pin in
/// `.github/workflows/ci.yml`. The conformance harness asserts
/// byte-equality between this constant and the corpus's `rc_target`,
/// so a corpus that drifts ahead of (or behind) the code fails CI
/// instead of silently skipping new vectors.
pub const SPEC_REVISION: &str = "1.0-rc.19";

pub mod canon;
pub mod crypto;
pub mod document;
pub mod state;
pub mod tor;
pub mod types;
pub mod validation;
