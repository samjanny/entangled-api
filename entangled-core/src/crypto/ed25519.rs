//! Minimal Ed25519 wrapper around `ed25519_dalek`.
//!
//! Operates on the 32-byte/64-byte newtypes from [`crate::types`] rather than
//! raw byte arrays. Signing is infallible (RFC 8032 makes Ed25519 signing total
//! over arbitrary input). Verification reduces every internal failure to
//! [`CryptoError::VerificationFailed`] — the call site uses the strongly-typed
//! `Signature` and `*Pubkey` newtypes for syntactic validity, so any
//! cryptographic mismatch reaching this layer is by definition a verification
//! failure.

use ed25519_dalek::Signer as _;
use thiserror::Error;

use crate::types::{OriginPubkey, PublisherPubkey, RuntimePubkey, Signature};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("invalid Ed25519 public key encoding")]
    InvalidPublicKey,
    #[error("Ed25519 signature verification failed")]
    VerificationFailed,
}

pub struct SigningKey(ed25519_dalek::SigningKey);

pub struct VerifyingKey(ed25519_dalek::VerifyingKey);

impl SigningKey {
    /// Generate a fresh keypair from operating-system entropy.
    ///
    /// Test-only: gated behind `#[cfg(test)]` and the `test-utils` feature so
    /// that production code paths never accidentally generate keys this way.
    /// Uses `getrandom` for cross-platform OS RNG access (Linux `getrandom(2)`,
    /// `BCryptGenRandom` on Windows, `arc4random_buf` on the BSDs, etc.) —
    /// this is the de-facto standard for OS-level entropy in Rust.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("OS RNG unavailable");
        Self::from_seed(&seed)
    }

    /// Build a `SigningKey` from a 32-byte seed (the RFC 8032 secret key).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(seed))
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key())
    }

    /// Sign an arbitrary input. Infallible per RFC 8032.
    pub fn sign(&self, input: &[u8]) -> Signature {
        let sig: ed25519_dalek::Signature = self.0.sign(input);
        Signature::from_bytes(sig.to_bytes())
    }
}

impl VerifyingKey {
    pub fn from_publisher_pubkey(pk: &PublisherPubkey) -> Result<Self, CryptoError> {
        Self::from_pubkey_bytes(pk.as_bytes())
    }

    pub fn from_origin_pubkey(pk: &OriginPubkey) -> Result<Self, CryptoError> {
        Self::from_pubkey_bytes(pk.as_bytes())
    }

    pub fn from_runtime_pubkey(pk: &RuntimePubkey) -> Result<Self, CryptoError> {
        Self::from_pubkey_bytes(pk.as_bytes())
    }

    fn from_pubkey_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map(VerifyingKey)
            .map_err(|_| CryptoError::InvalidPublicKey)
    }

    /// Verify a signature on an arbitrary input.
    ///
    /// Uses ed25519-dalek's `verify_strict`, which rejects malleable signatures
    /// (non-canonical S scalar and small-order public keys) per RFC 8032 §5.1.7
    /// strict verification.
    pub fn verify(&self, input: &[u8], sig: &Signature) -> Result<(), CryptoError> {
        let parsed = ed25519_dalek::Signature::from_bytes(sig.as_bytes());
        self.0
            .verify_strict(input, &parsed)
            .map_err(|_| CryptoError::VerificationFailed)
    }

    pub fn to_publisher_pubkey(&self) -> PublisherPubkey {
        PublisherPubkey::from_bytes(self.0.to_bytes())
    }

    pub fn to_origin_pubkey(&self) -> OriginPubkey {
        OriginPubkey::from_bytes(self.0.to_bytes())
    }

    pub fn to_runtime_pubkey(&self) -> RuntimePubkey {
        RuntimePubkey::from_bytes(self.0.to_bytes())
    }
}
