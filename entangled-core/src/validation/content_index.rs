//! Content index validation (§02/§09/§10 v1.0-rc.19, N46–N49).
//!
//! The content index is a non-signed JSON resource at
//! `/content_index.json`. Its integrity is established by the
//! `content_root` hash binding in the manifest. This module provides:
//!
//! * [`ContentIndex`] — the parsed and validated content index.
//! * [`ContentIndexEntry`] — a single `(seq, hash)` pair.
//! * [`validate_content_index`] — structural validation of the raw bytes.
//! * [`verify_content_against_index`] — per-document `seq`/`hash`
//!   verification at Stage 9.
//!
//! # Caller obligations for the transport fetch
//!
//! The helpers in this module operate on the raw response body bytes of
//! `/content_index.json` and do NOT inspect HTTP response headers.
//! Three transport-layer rules from Section 09 are the fetching
//! caller's responsibility, and the spec maps each violation onto
//! `E_CONTENT_INDEX_FETCH_FAILED` rather than onto the generic Stage 1
//! transport codes that apply to Entangled signed documents:
//!
//! 1. `Content-Type` MUST be `application/json`. The content index is
//!    not an Entangled signed document, so `application/entangled+json`
//!    is not an acceptable value here.
//! 2. `Content-Length` MUST be present and exact. A response without
//!    `Content-Length` is `E_CONTENT_INDEX_FETCH_FAILED` (not
//!    `E_TRANSPORT_CONTENT_LENGTH`).
//! 3. `Content-Encoding` and `Transfer-Encoding` MUST be absent. The
//!    `content_root` hash binding is over the exact response body
//!    bytes, so any transfer-layer transformation invalidates the hash.
//!    A response carrying either header is
//!    `E_CONTENT_INDEX_FETCH_FAILED` (not
//!    `E_TRANSPORT_CONTENT_ENCODING` or
//!    `E_TRANSPORT_TRANSFER_ENCODING`).
//!
//! A non-`200` response is also `E_CONTENT_INDEX_FETCH_FAILED`. When
//! the manifest declares `content_root` and the content index cannot
//! be obtained for any of the above reasons, the client MUST NOT
//! render content documents from the site under that manifest: the
//! spec treats failure to honor a signed `content_root` commitment as
//! indistinguishable from server compromise (Section 09:116).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::types::keys::{ContentHash, ContentRoot};
use crate::validation::diagnostic::{Diagnostic, DiagnosticCode, DocumentKindLabel};
use crate::validation::limits::CONTENT_INDEX_MAX_BYTES;
use crate::validation::parse::parse_with_limits;

/// A validated content index.
///
/// Parsed from the exact bytes of `/content_index.json` after hash
/// verification against the manifest's `content_root`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentIndex {
    entries: HashMap<String, ContentIndexEntry>,
}

/// One entry in the content index: a `(seq, hash)` pair for a path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentIndexEntry {
    /// Sequence number (≥ 1, monotonic per path).
    pub seq: u64,
    /// SHA-256 digest of the content document's exact response body bytes.
    pub hash: ContentHash,
}

/// Raw wire representation for deserialization.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContentIndexWire {
    entries: HashMap<String, ContentIndexEntry>,
}

impl ContentIndex {
    /// Look up an entry by content path.
    pub fn get(&self, path: &str) -> Option<&ContentIndexEntry> {
        self.entries.get(path)
    }

    /// Iterate over all entries.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &ContentIndexEntry)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Number of indexed paths.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Validate content index bytes and verify against `content_root`.
///
/// Runs in order:
/// 1. Size check (≤ 1 MiB).
/// 2. Hash verification against `content_root`.
/// 3. Input discipline (strict UTF-8, no BOM).
/// 4. Strict JSON parse (no duplicate keys; integer grammar per §04;
///    Stage 3 JSON nesting / array / object-key / string-length caps).
/// 5. Closed-schema deserialization.
/// 6. Per-entry path syntax + seq lower bound.
///
/// Per §02:208 the content index is hash-bound to a `K_publisher`-signed
/// commitment and therefore MUST be parsed under the same input
/// restrictions that apply to Entangled documents — including strict
/// duplicate-key rejection (not last-wins) and lexical integer grammar.
/// Steps 3-4 are routed through [`parse_with_limits`] for that reason;
/// any deviation between two conforming parsers on the same bytes would
/// defeat the content_root binding model.
///
/// Returns the validated [`ContentIndex`] on success.
///
/// # Errors
///
/// * `E_CONTENT_INDEX_HASH_MISMATCH` — hash does not match `content_root`.
/// * `E_CONTENT_INDEX_INVALID` — any other failure (size cap, UTF-8, BOM,
///   parse error, schema violation, path syntax, seq lower bound).
///
/// Transport-layer failures (missing `Content-Length`, wrong
/// `Content-Type`, presence of `Content-Encoding` /
/// `Transfer-Encoding`, non-`200` status) are the fetching caller's
/// responsibility and map to `E_CONTENT_INDEX_FETCH_FAILED` rather than
/// to the generic Stage 1 transport codes. See the module-level docs
/// for the full caller checklist.
pub fn validate_content_index(
    bytes: &[u8],
    content_root: &ContentRoot,
) -> Result<ContentIndex, Diagnostic> {
    if bytes.len() > CONTENT_INDEX_MAX_BYTES {
        return Err(Diagnostic::new(
            DiagnosticCode::EContentIndexInvalid,
            DocumentKindLabel::ContentIndex,
            format!(
                "content index response body of {} bytes exceeds cap of {CONTENT_INDEX_MAX_BYTES}",
                bytes.len()
            ),
        ));
    }

    let computed = crate::crypto::sha256(bytes);
    if computed != *content_root.as_bytes() {
        return Err(Diagnostic::new(
            DiagnosticCode::EContentIndexHashMismatch,
            DocumentKindLabel::ContentIndex,
            "SHA-256 of content index bytes does not match manifest content_root",
        )
        .with_details(serde_json::json!({
            "expected": content_root.to_string(),
            "received": format!(
                "sha-256:{}",
                data_encoding::BASE64URL_NOPAD.encode(&computed)
            ),
        })));
    }

    let s = std::str::from_utf8(bytes).map_err(|_| {
        Diagnostic::new(
            DiagnosticCode::EContentIndexInvalid,
            DocumentKindLabel::ContentIndex,
            "content index is not valid UTF-8",
        )
    })?;

    if s.starts_with('\u{FEFF}') {
        return Err(Diagnostic::new(
            DiagnosticCode::EContentIndexInvalid,
            DocumentKindLabel::ContentIndex,
            "content index must not begin with a BOM",
        ));
    }

    // §02:208: parse under the same input restrictions as Entangled
    // documents (no duplicate JSON keys, integer grammar, parser limits).
    // Map any parse diagnostic onto the single content-index code per
    // §11 — the content index does not surface stage-3 codes directly.
    let value = parse_with_limits(s).map_err(|d| {
        Diagnostic::new(
            DiagnosticCode::EContentIndexInvalid,
            DocumentKindLabel::ContentIndex,
            format!("content index parse failure: {}", d.message),
        )
    })?;

    let wire: ContentIndexWire = serde_json::from_value(value).map_err(|e| {
        Diagnostic::new(
            DiagnosticCode::EContentIndexInvalid,
            DocumentKindLabel::ContentIndex,
            format!("content index structural validation failed: {e}"),
        )
    })?;

    for (path, entry) in &wire.entries {
        validate_index_path(path)?;
        if entry.seq < 1 {
            return Err(Diagnostic::new(
                DiagnosticCode::EContentIndexInvalid,
                DocumentKindLabel::ContentIndex,
                format!("content index entry for {path}: seq must be at least 1"),
            ));
        }
    }

    Ok(ContentIndex {
        entries: wire.entries,
    })
}

/// Validate a path key in the content index.
///
/// Must satisfy the same syntax as `EntangledPath` and must not be a
/// reserved path.
fn validate_index_path(path: &str) -> Result<(), Diagnostic> {
    use crate::types::path::EntangledPath;
    EntangledPath::try_from(path).map_err(|e| {
        Diagnostic::new(
            DiagnosticCode::EContentIndexInvalid,
            DocumentKindLabel::ContentIndex,
            format!("content index path {path:?}: {e}"),
        )
    })?;
    Ok(())
}

/// Verify a content document against the content index at Stage 9.
///
/// `doc_path` is the document's `path` field, `doc_seq` is its `seq`
/// field, and `doc_body_hash` is the SHA-256 of the exact response body
/// bytes formatted as `sha-256:<base64url>`.
///
/// # Errors
///
/// * `E_CONTENT_SEQ_MISSING` — index has an entry but document omits `seq`.
/// * `E_CONTENT_SEQ_ROLLBACK` — `doc_seq < idx_seq`.
/// * `E_CONTENT_SEQ_UNCOMMITTED` — `doc_seq > idx_seq`.
/// * `E_CONTENT_HASH_MISMATCH` — `doc_seq == idx_seq` but hash differs.
pub fn verify_content_against_index(
    index: &ContentIndex,
    doc_path: &str,
    doc_seq: Option<u64>,
    doc_body_hash: &ContentHash,
) -> Result<(), Diagnostic> {
    let Some(idx_entry) = index.get(doc_path) else {
        return Ok(());
    };

    let Some(seq) = doc_seq else {
        return Err(Diagnostic::new(
            DiagnosticCode::EContentSeqMissing,
            DocumentKindLabel::Content,
            format!("content index has entry for {doc_path} but document omits seq"),
        ));
    };

    if seq < idx_entry.seq {
        return Err(Diagnostic::new(
            DiagnosticCode::EContentSeqRollback,
            DocumentKindLabel::Content,
            format!(
                "content seq {seq} < index seq {} for {doc_path}",
                idx_entry.seq
            ),
        ));
    }

    if seq > idx_entry.seq {
        return Err(Diagnostic::new(
            DiagnosticCode::EContentSeqUncommitted,
            DocumentKindLabel::Content,
            format!(
                "content seq {seq} > index seq {} for {doc_path}",
                idx_entry.seq
            ),
        ));
    }

    if *doc_body_hash != idx_entry.hash {
        return Err(Diagnostic::new(
            DiagnosticCode::EContentHashMismatch,
            DocumentKindLabel::Content,
            format!("content hash mismatch at seq {seq} for {doc_path}"),
        )
        .with_details(serde_json::json!({
            "expected": idx_entry.hash.to_string(),
            "received": doc_body_hash.to_string(),
        })));
    }

    Ok(())
}
