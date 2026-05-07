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
use crate::types::{OriginPubkey, PublisherPubkey, RuntimePubkey, Signature};

use super::ed25519::{CryptoError, SigningKey, VerifyingKey};

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("canonicalization failed: {0}")]
    Canon(#[from] CanonError),
    #[error("crypto operation failed: {0}")]
    Crypto(#[from] CryptoError),
}

pub fn sign_manifest_payload(
    payload: &Value,
    publisher_key: &SigningKey,
) -> Result<Signature, SigningError> {
    let input = build_manifest_signature_input(payload)?;
    Ok(publisher_key.sign(&input))
}

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

pub fn sign_content_payload(
    payload: &Value,
    runtime_key: &SigningKey,
) -> Result<Signature, SigningError> {
    let input = build_content_signature_input(payload)?;
    Ok(runtime_key.sign(&input))
}

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

pub fn sign_transaction_payload(
    payload: &Value,
    origin_key: &SigningKey,
) -> Result<Signature, SigningError> {
    let input = build_transaction_signature_input(payload)?;
    Ok(origin_key.sign(&input))
}

pub fn verify_transaction_payload(
    payload: &Value,
    sig: &Signature,
    origin_pubkey: &OriginPubkey,
) -> Result<(), SigningError> {
    let input = build_transaction_signature_input(payload)?;
    let vk = VerifyingKey::from_origin_pubkey(origin_pubkey)?;
    vk.verify(&input, sig)?;
    Ok(())
}
