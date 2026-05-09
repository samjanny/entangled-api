//! Pipeline Stages 2-6 for the three signed document kinds.
//!
//! Each entry point runs:
//!
//! - Stage 2 (input): byte cap, BOM, UTF-8 — via [`crate::validation::check_input`].
//! - Stage 3 (parsing): JSON limits — via [`crate::validation::parse_with_limits`].
//! - Stage 4 (kind discrimination): cross-kind rejection.
//! - Stage 5 (schema): closed-schema, field types, ranges, lengths, syntax.
//!   For manifests, this includes the §06 clock-skew check on
//!   `manifest.updated` (driven by the `now` parameter).
//! - Stage 6 (signature): JCS canonicalization plus Ed25519 strict
//!   verification under the document's domain-separated context.
//!
//! # Pipeline coverage and caller responsibilities
//!
//! `parse_and_verify_manifest` and the rest of the `parse_and_verify_*`
//! family cover Stages 2 through 6 of §10. The remaining stages are
//! deliberately the **caller's responsibility**:
//!
//! - **Stage 7 (trust state machine)** — TOFU pinning, externally-verified
//!   identity, mismatch resolution. Out of scope for this crate; handled by
//!   a higher-level client layer (e.g. a future `entangled-client`).
//! - **Stage 8 (canary state and structure)** — for manifests, traverse the
//!   type-state chain returned by `parse_and_verify_manifest`: call
//!   [`super::verified::ManifestSigVerified::verify_canary`], or opt out
//!   explicitly via
//!   [`super::verified::ManifestSigVerified::skip_canary_check`]. The
//!   canary `issued_at` clock-skew check lives there, not in this parse
//!   pipeline, because it is paired with the canary state machine
//!   (fresh / stale / expired) and anti-downgrade comparisons against
//!   previously seen canaries — neither of which is a closed-schema
//!   concern. Standalone helpers
//!   [`crate::validation::canary::validate_canary_structure`] and
//!   [`crate::validation::canary::compute_canary_state`] remain available
//!   for callers operating on a `Manifest` not obtained from
//!   `parse_and_verify_manifest`.
//! - **Stage 9 (binding)** — for manifests, traverse the chain via
//!   [`super::verified::ManifestCanaryChecked::verify_origin`] (or opt out
//!   via [`super::verified::ManifestCanaryChecked::skip_origin_check`]).
//!   The standalone [`crate::tor::verify_origin_binding`] helper remains
//!   available. For content and transaction documents,
//!   path/in-response-to binding is the caller's check too.
//! - **Stage 10 (rendering decisions)** — chrome and UI concerns.
//!
//! Stage 5 includes `manifest.updated` clock-skew because that field is a
//! pure schema-level range check on a single self-contained timestamp; it
//! does not depend on history or trust state. Stage 8's canary check
//! depends on both, so it is exposed as a separate helper rather than
//! folded into the parse pipeline.
//!
//! ## Manifest type-state chain
//!
//! `parse_and_verify_manifest` returns a [`super::verified::ManifestSigVerified`]
//! type-state wrapper rather than a bare [`crate::types::Manifest`]. To
//! extract a bare `Manifest`, the caller traverses the chain via
//! `verify_canary` and
//! `verify_origin`, or opts out explicitly via the corresponding `skip_*`
//! methods. The bare `Manifest` is reachable only by completing the chain
//! (`into_parts`) or by explicit `skip_canary_check` / `skip_origin_check`
//! opt-out, making Stage 8 / Stage 9 omission a deliberate choice rather
//! than an oversight.
//!
//! The `Manifest` type itself is not accessible through the wrappers;
//! only field-level accessors are exposed via the
//! [`super::verified::ManifestRead`] trait pre-canary, with
//! [`crate::types::Canary`] access available post-canary. To obtain a
//! `Manifest` value, callers must complete the chain via
//! [`super::verified::ManifestOriginBound::into_parts`] or explicitly
//! opt out of further stages via
//! [`super::verified::ManifestSigVerified::skip_canary_check`] /
//! [`super::verified::ManifestCanaryChecked::skip_origin_check`].
//!
//! Content and transaction documents return bare [`ContentDocument`] and
//! [`TransactionDocument`] because their signature verification already
//! binds them to a specific path or `in_response_to`, leaving less surface
//! for stage omission.
//!
//! The parser only proves that whoever signed the manifest knew the private
//! key matching `manifest.publisher_pubkey` — it does not prove that this
//! pubkey is the one the user expects.
//!
//! ## Stage 5 / Stage 6 boundary for `sig` shape
//!
//! Per §11 (rc.9), a `sig` field received on the wire whose length or
//! base64url alphabet is wrong is a Stage 5 schema violation reported as
//! `E_SCHEMA_FIELD_SYNTAX`. `E_SIG_MALFORMED` is reserved for the off-wire
//! case where the same decoding is attempted in a context where Stage 5
//! field-syntax validation does not apply (e.g. signatures handed to
//! [`crate::document::extract_sig`] from a non-pipeline source). The
//! pipeline already runs the schema deserializer first, so on the wire the
//! malformed-sig path is reached as Stage 5 syntax — the
//! [`crate::types::keys::Signature`] newtype's decoder errors flow through
//! [`crate::validation::schema`]'s serde-error mapper and surface as
//! `E_SCHEMA_FIELD_SYNTAX`.

use crate::canon::{
    build_content_signature_input, build_manifest_signature_input,
    build_transaction_signature_input,
};
use crate::crypto::{CryptoError, VerifyingKey};
use crate::types::document::{ContentDocument, TransactionDocument};
use crate::types::keys::RuntimePubkey;
use crate::types::timestamp::EntangledTimestamp;
use crate::validation::schema::{
    parse_and_validate_content, parse_and_validate_manifest, parse_and_validate_transaction,
};
use crate::validation::{Diagnostic, DiagnosticCode, DocumentKindLabel};

use super::envelope::extract_sig;
use super::verified::ManifestSigVerified;

/// Parse, validate, and self-verify a manifest envelope.
///
/// Returns a [`ManifestSigVerified`] type-state wrapper. To extract the
/// bare [`crate::types::Manifest`], traverse the chain via
/// [`ManifestSigVerified::verify_canary`] (Stage 8) and
/// [`super::verified::ManifestCanaryChecked::verify_origin`] (Stage 9), or
/// opt out explicitly via [`ManifestSigVerified::skip_canary_check`] /
/// [`super::verified::ManifestCanaryChecked::skip_origin_check`]. The
/// `#[must_use]` annotation on each wrapper warns when a wrapper value
/// is silently dropped without being used, catching the trivial
/// "called but ignored" omission case. It does NOT prevent a caller from
/// reading individual fields via `ManifestRead` and then dropping the
/// wrapper without completing the chain — that pattern is permitted
/// because per-field reads on incomplete states are needed for Stage 7
/// (trust state lookup, §10) which precedes Stage 8.
///
/// The verification key is `manifest.publisher_pubkey` — the parser
/// performs "Stage 6 self-verification" only. Stage 7 trust-state
/// resolution (TOFU pinning, externally verified PIP, mismatch detection)
/// remains the caller's responsibility, after the chain has been
/// completed.
///
/// `now` is the local wall-clock time used for the §06 / §10 clock-skew
/// check on `manifest.updated` (Stage 5). Pass a deterministic timestamp in
/// tests; pass `OffsetDateTime::now_utc().into()` (or equivalent) in
/// production callers — `entangled-core` deliberately does not query the
/// system clock itself.
pub fn parse_and_verify_manifest(
    raw: &[u8],
    now: &EntangledTimestamp,
) -> Result<ManifestSigVerified, Diagnostic> {
    let manifest = parse_and_validate_manifest(raw, now)?;
    let mut value = serde_json::to_value(&manifest).map_err(|e| {
        Diagnostic::new(
            DiagnosticCode::EParseJson,
            DocumentKindLabel::Manifest,
            format!("failed to re-serialize manifest for signature check: {e}"),
        )
    })?;
    if let serde_json::Value::Object(ref mut map) = value {
        map.insert(
            "kind".to_owned(),
            serde_json::Value::String("manifest".to_owned()),
        );
    }
    let sig = extract_sig(&mut value, DocumentKindLabel::Manifest)?;
    let input = build_manifest_signature_input(&value).map_err(|e| {
        Diagnostic::new(
            DiagnosticCode::ESchemaFieldType,
            DocumentKindLabel::Manifest,
            format!("canonicalization failed: {e}"),
        )
    })?;
    let vk = VerifyingKey::from_publisher_pubkey(&manifest.publisher_pubkey)
        .map_err(|e| crypto_to_diagnostic(e, DocumentKindLabel::Manifest))?;
    vk.verify(&input, &sig)
        .map_err(|e| crypto_to_diagnostic(e, DocumentKindLabel::Manifest))?;
    Ok(ManifestSigVerified::new(manifest))
}

/// Parse, validate, and verify a content document against the supplied
/// runtime pubkey.
///
/// The runtime pubkey is normally `current_manifest.canary.runtime_pubkey`
/// from a previously verified manifest. The parser does not attempt to
/// retrieve a manifest itself.
pub fn parse_and_verify_content(
    raw: &[u8],
    runtime_pubkey: &RuntimePubkey,
) -> Result<ContentDocument, Diagnostic> {
    let content = parse_and_validate_content(raw)?;
    let mut value = serde_json::to_value(&content).map_err(|e| {
        Diagnostic::new(
            DiagnosticCode::EParseJson,
            DocumentKindLabel::Content,
            format!("failed to re-serialize content for signature check: {e}"),
        )
    })?;
    if let serde_json::Value::Object(ref mut map) = value {
        map.insert(
            "kind".to_owned(),
            serde_json::Value::String("content".to_owned()),
        );
    }
    let sig = extract_sig(&mut value, DocumentKindLabel::Content)?;
    let input = build_content_signature_input(&value).map_err(|e| {
        Diagnostic::new(
            DiagnosticCode::ESchemaFieldType,
            DocumentKindLabel::Content,
            format!("canonicalization failed: {e}"),
        )
    })?;
    let vk = VerifyingKey::from_runtime_pubkey(runtime_pubkey)
        .map_err(|e| crypto_to_diagnostic(e, DocumentKindLabel::Content))?;
    vk.verify(&input, &sig)
        .map_err(|e| crypto_to_diagnostic(e, DocumentKindLabel::Content))?;
    Ok(content)
}

/// Parse, validate, and verify a transaction document against the supplied
/// runtime pubkey.
///
/// The runtime pubkey must come from a previously verified manifest's
/// `canary.runtime_pubkey`; the parser does not retrieve the manifest.
///
/// # Errors
///
/// Returns the first [`Diagnostic`] produced by Stage 2-6 validation:
/// `E_INPUT_*`, `E_PARSE_*`, `E_KIND_*`, `E_SCHEMA_*`, or
/// `E_SIG_VERIFICATION` (see [`crate::validation::DiagnosticCode`]). A
/// public key failing the §05 strict profile is rejected here as
/// `E_SIG_VERIFICATION`; `E_SIG_INVALID_KEY` is emitted only by callers
/// that detect "no verifying key is available" before reaching this stage.
pub fn parse_and_verify_transaction(
    raw: &[u8],
    runtime_pubkey: &RuntimePubkey,
) -> Result<TransactionDocument, Diagnostic> {
    let tx = parse_and_validate_transaction(raw)?;
    let mut value = serde_json::to_value(&tx).map_err(|e| {
        Diagnostic::new(
            DiagnosticCode::EParseJson,
            DocumentKindLabel::Transaction,
            format!("failed to re-serialize transaction for signature check: {e}"),
        )
    })?;
    if let serde_json::Value::Object(ref mut map) = value {
        map.insert(
            "kind".to_owned(),
            serde_json::Value::String("transaction".to_owned()),
        );
    }
    let sig = extract_sig(&mut value, DocumentKindLabel::Transaction)?;
    let input = build_transaction_signature_input(&value).map_err(|e| {
        Diagnostic::new(
            DiagnosticCode::ESchemaFieldType,
            DocumentKindLabel::Transaction,
            format!("canonicalization failed: {e}"),
        )
    })?;
    let vk = VerifyingKey::from_runtime_pubkey(runtime_pubkey)
        .map_err(|e| crypto_to_diagnostic(e, DocumentKindLabel::Transaction))?;
    vk.verify(&input, &sig)
        .map_err(|e| crypto_to_diagnostic(e, DocumentKindLabel::Transaction))?;
    Ok(tx)
}

fn crypto_to_diagnostic(err: CryptoError, kind: DocumentKindLabel) -> Diagnostic {
    match err {
        // §05 v1.0-rc.4: a public key that fails the strict profile (non-canonical
        // encoding or small-order point) causes the document being verified under
        // that key to be rejected as a signature failure, reported as
        // E_SIG_VERIFICATION (§11) — not E_SIG_INVALID_KEY, which is reserved for
        // "the expected verification key is not available".
        CryptoError::InvalidPublicKey => Diagnostic::new(
            DiagnosticCode::ESigVerification,
            kind,
            "Ed25519 public key fails the §05 strict profile (non-canonical or small-order)",
        )
        .with_details(serde_json::json!({
            "reason": "public_key_rejected",
        })),
        CryptoError::VerificationFailed => Diagnostic::new(
            DiagnosticCode::ESigVerification,
            kind,
            "Ed25519 signature verification failed",
        ),
    }
}
