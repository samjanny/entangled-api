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

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::types::keys::{ContentHash, ContentRoot};
use crate::validation::diagnostic::{Diagnostic, DiagnosticCode, DocumentKindLabel};
use crate::validation::limits::CONTENT_INDEX_MAX_BYTES;

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
/// 3. Structural validation (JSON parse, closed schema, path/entry checks).
///
/// Returns the validated [`ContentIndex`] on success.
///
/// # Errors
///
/// * `E_CONTENT_INDEX_HASH_MISMATCH` — hash does not match `content_root`.
/// * `E_CONTENT_INDEX_INVALID` — structural validation failure or size cap exceeded.
pub fn validate_content_index(
    bytes: &[u8],
    content_root: &ContentRoot,
) -> Result<ContentIndex, Diagnostic> {
    if bytes.len() > CONTENT_INDEX_MAX_BYTES {
        return Err(Diagnostic::new(
            DiagnosticCode::EContentIndexInvalid,
            DocumentKindLabel::Manifest,
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
            DocumentKindLabel::Manifest,
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
            DocumentKindLabel::Manifest,
            "content index is not valid UTF-8",
        )
    })?;

    if s.starts_with('\u{FEFF}') {
        return Err(Diagnostic::new(
            DiagnosticCode::EContentIndexInvalid,
            DocumentKindLabel::Manifest,
            "content index must not begin with a BOM",
        ));
    }

    let wire: ContentIndexWire = serde_json::from_str(s).map_err(|e| {
        Diagnostic::new(
            DiagnosticCode::EContentIndexInvalid,
            DocumentKindLabel::Manifest,
            format!("content index structural validation failed: {e}"),
        )
    })?;

    for (path, entry) in &wire.entries {
        validate_index_path(path)?;
        if entry.seq < 1 {
            return Err(Diagnostic::new(
                DiagnosticCode::EContentIndexInvalid,
                DocumentKindLabel::Manifest,
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
            DocumentKindLabel::Manifest,
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
