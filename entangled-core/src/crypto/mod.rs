//! Crypto layer (Phase 4): Ed25519 sign/verify, SHA-256, BIP-39 PIP derivation,
//! and high-level sign/verify helpers that combine canonicalization with the
//! Ed25519 primitive for each of the three signed-object kinds.

pub mod ed25519;
pub mod pip;
pub mod sha256;
pub mod signing;

pub use ed25519::{CryptoError, PublisherSigningKey, RuntimeSigningKey, VerifyingKey};
pub use pip::{derive_pip, pip_to_pubkey, PipError};
pub use sha256::{sha256, sha256_base64url, sha256_image, sha256_request};
pub use signing::{
    sign_content_payload, sign_manifest_payload, sign_transaction_payload, verify_content_payload,
    verify_manifest_payload, verify_transaction_payload, SigningError,
};
