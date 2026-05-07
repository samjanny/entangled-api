//! High-level builders that take an `Unsigned*` struct and a signing key and
//! produce the corresponding signed struct plus its serialized JSON bytes.
//!
//! The builder runs the same Stage 5 schema validation that the parser would
//! apply to the resulting document. This guarantees that:
//!
//! 1. Bytes produced by the builder always pass `parse_and_validate_*` on the
//!    receiving side (modulo trust state, which is out of scope here).
//! 2. The signature input the builder hashes is the same canonical byte
//!    stream the parser will reconstruct from the resulting envelope.
//!
//! ## Why `(Signed, Vec<u8>)` instead of just `Vec<u8>`?
//!
//! Callers usually need both: the signed struct for in-process use, the
//! bytes for transmission or storage. Returning both avoids re-deserializing
//! the bytes that we just produced.

use serde_json::Value;

use crate::crypto::{
    sign_content_payload, sign_manifest_payload, sign_transaction_payload, SigningKey,
};
use crate::types::document::{ContentDocument, TransactionDocument};
use crate::types::manifest::Manifest;
use crate::validation::schema::{
    validate_content_fields, validate_manifest_fields, validate_transaction_fields,
};

use super::error::DocumentError;
use super::unsigned::{UnsignedContent, UnsignedManifest, UnsignedTransaction};

/// Validate, sign, and serialize a manifest from an [`UnsignedManifest`].
///
/// Returns the signed [`Manifest`] alongside its JSON envelope bytes (with
/// the `kind` discriminator and `sig` already attached).
///
/// # Errors
///
/// - [`DocumentError::Validation`] if the unsigned manifest fails Stage 5
///   schema/range checks.
/// - [`DocumentError::Canon`] / [`DocumentError::Crypto`] if canonicalization
///   or Ed25519 signing fails.
/// - [`DocumentError::Serialization`] if `serde_json` cannot serialize the
///   envelope (in practice unreachable under the closed schema).
pub fn build_manifest(
    unsigned: &UnsignedManifest,
    publisher_key: &SigningKey,
) -> Result<(Manifest, Vec<u8>), DocumentError> {
    validate_manifest_fields(
        unsigned.min_refresh_interval,
        &unsigned.navigation,
        &unsigned.state_policy,
        &unsigned.canary,
    )?;

    let signed_payload = unsigned.to_signed_payload()?;
    let sig = sign_manifest_payload(&signed_payload, publisher_key)?;

    let manifest = Manifest {
        spec_version: unsigned.spec_version,
        publisher_pubkey: unsigned.publisher_pubkey,
        origin: unsigned.origin.clone(),
        canary: unsigned.canary.clone(),
        state_policy: unsigned.state_policy.clone(),
        navigation: unsigned.navigation.clone(),
        min_refresh_interval: unsigned.min_refresh_interval,
        updated: unsigned.updated,
        sig,
    };

    let bytes = serialize_manifest_envelope(&manifest, &sig.to_string())?;
    Ok((manifest, bytes))
}

/// Validate, sign, and serialize a content document from an
/// [`UnsignedContent`].
///
/// Returns the signed [`ContentDocument`] and its JSON envelope bytes.
///
/// # Errors
///
/// See [`build_manifest`] — same set of failures, applied to content.
pub fn build_content(
    unsigned: &UnsignedContent,
    runtime_key: &SigningKey,
) -> Result<(ContentDocument, Vec<u8>), DocumentError> {
    validate_content_fields(&unsigned.meta, &unsigned.blocks)?;

    let signed_payload = unsigned.to_signed_payload()?;
    let sig = sign_content_payload(&signed_payload, runtime_key)?;

    let content = ContentDocument {
        spec_version: unsigned.spec_version,
        path: unsigned.path.clone(),
        meta: unsigned.meta.clone(),
        blocks: unsigned.blocks.clone(),
        sig,
    };

    let bytes = serialize_content_envelope(&content, &sig.to_string())?;
    Ok((content, bytes))
}

/// Validate, sign, and serialize a transaction from an
/// [`UnsignedTransaction`].
///
/// Returns the signed [`TransactionDocument`] and its JSON envelope bytes.
///
/// # Errors
///
/// See [`build_manifest`] — same set of failures, applied to transactions.
pub fn build_transaction(
    unsigned: &UnsignedTransaction,
    runtime_key: &SigningKey,
) -> Result<(TransactionDocument, Vec<u8>), DocumentError> {
    validate_transaction_fields(&unsigned.blocks, &unsigned.state_updates)?;

    let signed_payload = unsigned.to_signed_payload()?;
    let sig = sign_transaction_payload(&signed_payload, runtime_key)?;

    let tx = TransactionDocument {
        spec_version: unsigned.spec_version,
        in_response_to: unsigned.in_response_to.clone(),
        state_updates: unsigned.state_updates.clone(),
        blocks: unsigned.blocks.clone(),
        sig,
    };

    let bytes = serialize_transaction_envelope(&tx, &sig.to_string())?;
    Ok((tx, bytes))
}

fn serialize_manifest_envelope(
    manifest: &Manifest,
    sig_str: &str,
) -> Result<Vec<u8>, DocumentError> {
    let mut value = serde_json::to_value(manifest)?;
    finalize_envelope(&mut value, "manifest", sig_str);
    Ok(serde_json::to_vec(&value)?)
}

fn serialize_content_envelope(
    content: &ContentDocument,
    sig_str: &str,
) -> Result<Vec<u8>, DocumentError> {
    let mut value = serde_json::to_value(content)?;
    finalize_envelope(&mut value, "content", sig_str);
    Ok(serde_json::to_vec(&value)?)
}

fn serialize_transaction_envelope(
    tx: &TransactionDocument,
    sig_str: &str,
) -> Result<Vec<u8>, DocumentError> {
    let mut value = serde_json::to_value(tx)?;
    finalize_envelope(&mut value, "transaction", sig_str);
    Ok(serde_json::to_vec(&value)?)
}

fn finalize_envelope(value: &mut Value, kind: &'static str, sig_str: &str) {
    if let Value::Object(map) = value {
        map.insert("kind".to_owned(), Value::String(kind.to_owned()));
        map.insert("sig".to_owned(), Value::String(sig_str.to_owned()));
    }
}
