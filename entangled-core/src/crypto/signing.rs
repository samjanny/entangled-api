//! High-level sign/verify helpers that combine `canon` (signature-input
//! construction with per-context domain separation) and `ed25519` (signing /
//! verification) into a single call.
//!
//! These functions are the building blocks Phase 5 will use to construct the
//! envelope `{ signed_payload, sig }`. They operate on the **signed payload**
//! — the document body without the `sig` field. Stripping `sig` before
//! calling these functions is the caller's responsibility (per §05): callers
//! that hold a complete envelope must remove the signature before computing
//! `signature_input`, otherwise the input includes the signature itself.

use serde_json::Value;
use thiserror::Error;

use crate::canon::{
    build_content_signature_input, build_manifest_signature_input,
    build_transaction_signature_input, CanonError,
};
use crate::types::{PublisherPubkey, RuntimePubkey, Signature};

use super::ed25519::{CryptoError, SigningKey, VerifyingKey};

/// Errors that can occur during high-level sign/verify.
#[derive(Debug, Error)]
pub enum SigningError {
    /// The signed payload could not be canonicalized.
    #[error("canonicalization failed: {0}")]
    Canon(#[from] CanonError),
    /// An Ed25519 verification or key-decoding step failed.
    #[error("crypto operation failed: {0}")]
    Crypto(#[from] CryptoError),
}

/// Sign a manifest payload (the manifest body without `sig`) under the
/// publisher key.
///
/// # Errors
///
/// Forwards any [`CanonError`] from canonicalization.
pub fn sign_manifest_payload(
    payload: &Value,
    publisher_key: &SigningKey,
) -> Result<Signature, SigningError> {
    let input = build_manifest_signature_input(payload)?;
    Ok(publisher_key.sign(&input))
}

/// Verify a manifest signature against the publisher pubkey.
///
/// # Errors
///
/// Forwards any [`CanonError`] from canonicalization, and any
/// [`CryptoError`] from key parsing or strict verification.
pub fn verify_manifest_payload(
    payload: &Value,
    sig: &Signature,
    publisher_pubkey: &PublisherPubkey,
) -> Result<(), SigningError> {
    let input = build_manifest_signature_input(payload)?;
    let vk = VerifyingKey::from_publisher_pubkey(publisher_pubkey)?;
    vk.verify(&input, sig)?;
    Ok(())
}

/// Sign a content payload (the content body without `sig`) under the runtime
/// key.
///
/// # Errors
///
/// Forwards any [`CanonError`] from canonicalization.
pub fn sign_content_payload(
    payload: &Value,
    runtime_key: &SigningKey,
) -> Result<Signature, SigningError> {
    let input = build_content_signature_input(payload)?;
    Ok(runtime_key.sign(&input))
}

/// Verify a content signature against the runtime pubkey.
///
/// # Errors
///
/// Forwards any [`CanonError`] and any [`CryptoError`].
pub fn verify_content_payload(
    payload: &Value,
    sig: &Signature,
    runtime_pubkey: &RuntimePubkey,
) -> Result<(), SigningError> {
    let input = build_content_signature_input(payload)?;
    let vk = VerifyingKey::from_runtime_pubkey(runtime_pubkey)?;
    vk.verify(&input, sig)?;
    Ok(())
}

/// Sign a transaction payload (the transaction body without `sig`) under the
/// runtime key. Per §05, transaction documents are signed by `K_runtime` —
/// the same operational key used for content — and verified against the
/// runtime pubkey authorized by the relevant publication cycle's manifest.
///
/// # Errors
///
/// Forwards any [`CanonError`] from canonicalization.
pub fn sign_transaction_payload(
    payload: &Value,
    runtime_key: &SigningKey,
) -> Result<Signature, SigningError> {
    let input = build_transaction_signature_input(payload)?;
    Ok(runtime_key.sign(&input))
}

/// Verify a transaction signature against the runtime pubkey.
///
/// # Errors
///
/// Forwards any [`CanonError`] and any [`CryptoError`].
pub fn verify_transaction_payload(
    payload: &Value,
    sig: &Signature,
    runtime_pubkey: &RuntimePubkey,
) -> Result<(), SigningError> {
    let input = build_transaction_signature_input(payload)?;
    let vk = VerifyingKey::from_runtime_pubkey(runtime_pubkey)?;
    vk.verify(&input, sig)?;
    Ok(())
}
