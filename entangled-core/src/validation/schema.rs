//! Stage 5 dispatch — top-level validators and end-to-end pipelines for
//! manifest, content, and transaction documents.
//!
//! The serde error message format used by `map_serde_err` is not part of
//! serde's public API. If serde changes the wording, the mapping may need
//! adjustment. Tests in `tests/validation/` cover the current behavior of
//! serde_json 1.0.149.

use serde_json::Value;

use crate::types::document::{ContentDocument, Document, TransactionDocument};
use crate::types::manifest::Manifest;

use super::blocks::validate_blocks;
use super::diagnostic::{Diagnostic, DiagnosticCode, DocumentKindLabel};
use super::input::{check_input, InputKind};
use super::kind::{discriminate_kind, DocumentKind};
use super::limits::{
    CANARY_FRESHNESS_PROOF_MAX_BYTES, CANARY_STATEMENT_MAX_BYTES, MAX_BLOCKS_CONTENT,
    MAX_BLOCKS_TRANSACTION, MAX_NAVIGATION_ENTRIES, META_TITLE_MAX_BYTES,
    MIN_REFRESH_INTERVAL_RANGE, NAVIGATION_LABEL_MAX_BYTES,
};
use super::parse::parse_with_limits;
use super::state::{validate_state_policy, validate_state_updates_standalone};
use super::strings::no_control_chars;

// -----------------------------------------------------------------------------
// Public top-level pipelines (Stages 2–5)
// -----------------------------------------------------------------------------

pub fn parse_and_validate_manifest(bytes: &[u8]) -> Result<Manifest, Diagnostic> {
    let s = check_input(bytes, InputKind::Manifest)?;
    let value = parse_with_limits(s).map_err(|d| set_kind(d, DocumentKindLabel::Manifest))?;
    let kind = discriminate_kind(&value)?;
    if kind != DocumentKind::Manifest {
        return Err(Diagnostic::new(
            DiagnosticCode::EKindUnknown,
            DocumentKindLabel::None,
            format!("expected manifest, got {kind:?}"),
        ));
    }
    schema_prepass(&value, DocumentKindLabel::Manifest)?;
    let doc: Document =
        serde_json::from_value(value).map_err(|e| map_serde_err(e, DocumentKindLabel::Manifest))?;
    let manifest = match doc {
        Document::Manifest(m) => m,
        _ => unreachable!("Stage 4 already discriminated as manifest"),
    };
    validate_manifest(&manifest)?;
    Ok(manifest)
}

pub fn parse_and_validate_content(bytes: &[u8]) -> Result<ContentDocument, Diagnostic> {
    let s = check_input(bytes, InputKind::ContentDocument)?;
    let value = parse_with_limits(s).map_err(|d| set_kind(d, DocumentKindLabel::Content))?;
    let kind = discriminate_kind(&value)?;
    if kind != DocumentKind::Content {
        return Err(Diagnostic::new(
            DiagnosticCode::EKindUnknown,
            DocumentKindLabel::None,
            format!("expected content, got {kind:?}"),
        ));
    }
    schema_prepass(&value, DocumentKindLabel::Content)?;
    let doc: Document =
        serde_json::from_value(value).map_err(|e| map_serde_err(e, DocumentKindLabel::Content))?;
    let content = match doc {
        Document::Content(c) => c,
        _ => unreachable!("Stage 4 already discriminated as content"),
    };
    validate_content(&content)?;
    Ok(content)
}

pub fn parse_and_validate_transaction(bytes: &[u8]) -> Result<TransactionDocument, Diagnostic> {
    let s = check_input(bytes, InputKind::TransactionDocument)?;
    let value = parse_with_limits(s).map_err(|d| set_kind(d, DocumentKindLabel::Transaction))?;
    let kind = discriminate_kind(&value)?;
    if kind != DocumentKind::Transaction {
        return Err(Diagnostic::new(
            DiagnosticCode::EKindUnknown,
            DocumentKindLabel::None,
            format!("expected transaction, got {kind:?}"),
        ));
    }
    schema_prepass(&value, DocumentKindLabel::Transaction)?;
    let doc: Document = serde_json::from_value(value)
        .map_err(|e| map_serde_err(e, DocumentKindLabel::Transaction))?;
    let tx = match doc {
        Document::Transaction(t) => t,
        _ => unreachable!("Stage 4 already discriminated as transaction"),
    };
    validate_transaction(&tx)?;
    Ok(tx)
}

// -----------------------------------------------------------------------------
// Public per-kind validators (post-deserialize)
// -----------------------------------------------------------------------------

pub fn validate_manifest(manifest: &Manifest) -> Result<(), Diagnostic> {
    if !MIN_REFRESH_INTERVAL_RANGE.contains(&manifest.min_refresh_interval) {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldRange,
            DocumentKindLabel::Manifest,
            format!(
                "min_refresh_interval {} out of range {}..={}",
                manifest.min_refresh_interval,
                MIN_REFRESH_INTERVAL_RANGE.start(),
                MIN_REFRESH_INTERVAL_RANGE.end()
            ),
        ));
    }

    if manifest.navigation.len() > MAX_NAVIGATION_ENTRIES {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldLength,
            DocumentKindLabel::Manifest,
            format!(
                "navigation has {} entries, max is {MAX_NAVIGATION_ENTRIES}",
                manifest.navigation.len()
            ),
        ));
    }
    for nav in &manifest.navigation {
        if nav.label.len() > NAVIGATION_LABEL_MAX_BYTES {
            return Err(Diagnostic::new(
                DiagnosticCode::ESchemaFieldLength,
                DocumentKindLabel::Manifest,
                format!(
                    "navigation label of {} bytes exceeds cap of {NAVIGATION_LABEL_MAX_BYTES}",
                    nav.label.len()
                ),
            ));
        }
        if !no_control_chars(&nav.label, false) {
            return Err(Diagnostic::new(
                DiagnosticCode::ESchemaFieldSyntax,
                DocumentKindLabel::Manifest,
                "navigation label contains control characters",
            ));
        }
    }

    validate_state_policy(&manifest.state_policy)?;

    // Canary structural string limits. Interval bounds and `issued_at` future
    // checks are Stage 8 (later phase).
    let canary = &manifest.canary;
    if canary.statement.len() > CANARY_STATEMENT_MAX_BYTES {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldLength,
            DocumentKindLabel::Manifest,
            format!(
                "canary.statement of {} bytes exceeds cap of {CANARY_STATEMENT_MAX_BYTES}",
                canary.statement.len()
            ),
        ));
    }
    // §08: statement permits LF; other control chars rejected.
    if !no_control_chars(&canary.statement, true) {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldSyntax,
            DocumentKindLabel::Manifest,
            "canary.statement contains control characters other than line feed",
        ));
    }
    if let Some(fp) = &canary.freshness_proof {
        if fp.len() > CANARY_FRESHNESS_PROOF_MAX_BYTES {
            return Err(Diagnostic::new(
                DiagnosticCode::ESchemaFieldLength,
                DocumentKindLabel::Manifest,
                format!(
                    "canary.freshness_proof of {} bytes exceeds cap of {CANARY_FRESHNESS_PROOF_MAX_BYTES}",
                    fp.len()
                ),
            ));
        }
        // §08: freshness_proof MUST NOT contain control characters.
        if !no_control_chars(fp, false) {
            return Err(Diagnostic::new(
                DiagnosticCode::ESchemaFieldSyntax,
                DocumentKindLabel::Manifest,
                "canary.freshness_proof contains control characters",
            ));
        }
    }

    Ok(())
}

pub fn validate_content(doc: &ContentDocument) -> Result<(), Diagnostic> {
    if doc.meta.title.len() > META_TITLE_MAX_BYTES {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldLength,
            DocumentKindLabel::Content,
            format!(
                "meta.title of {} bytes exceeds cap of {META_TITLE_MAX_BYTES}",
                doc.meta.title.len()
            ),
        ));
    }
    if !no_control_chars(&doc.meta.title, false) {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldSyntax,
            DocumentKindLabel::Content,
            "meta.title contains control characters",
        ));
    }

    if doc.blocks.len() > MAX_BLOCKS_CONTENT {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldLength,
            DocumentKindLabel::Content,
            format!(
                "content blocks has {} entries, max is {MAX_BLOCKS_CONTENT}",
                doc.blocks.len()
            ),
        ));
    }

    validate_blocks(&doc.blocks, DocumentKind::Content)
}

pub fn validate_transaction(doc: &TransactionDocument) -> Result<(), Diagnostic> {
    if doc.blocks.is_empty() {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaRequiredField,
            DocumentKindLabel::Transaction,
            "transaction must contain at least one block",
        ));
    }
    if doc.blocks.len() > MAX_BLOCKS_TRANSACTION {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldLength,
            DocumentKindLabel::Transaction,
            format!(
                "transaction blocks has {} entries, max is {MAX_BLOCKS_TRANSACTION}",
                doc.blocks.len()
            ),
        ));
    }

    validate_blocks(&doc.blocks, DocumentKind::Transaction)?;
    validate_state_updates_standalone(&doc.state_updates)?;
    Ok(())
}

// -----------------------------------------------------------------------------
// Pre-pass over the parsed Value
// -----------------------------------------------------------------------------

/// Detects `null` literals and non-integer numbers anywhere in the document.
/// §0.10: null and float values are forbidden in Entangled wire form.
fn schema_prepass(root: &Value, kind: DocumentKindLabel) -> Result<(), Diagnostic> {
    let mut stack: Vec<&Value> = vec![root];
    while let Some(node) = stack.pop() {
        match node {
            Value::Null => {
                return Err(Diagnostic::new(
                    DiagnosticCode::ESchemaNullValue,
                    kind,
                    "null literal is not permitted",
                ));
            }
            Value::Number(n) => {
                if n.is_f64() {
                    return Err(Diagnostic::new(
                        DiagnosticCode::ESchemaNonInteger,
                        kind,
                        format!("non-integer numeric value: {n}"),
                    ));
                }
            }
            Value::Array(arr) => {
                for v in arr {
                    stack.push(v);
                }
            }
            Value::Object(map) => {
                for v in map.values() {
                    stack.push(v);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

fn set_kind(mut d: Diagnostic, kind: DocumentKindLabel) -> Diagnostic {
    d.document_kind = kind;
    d
}

/// Maps a `serde_json::Error` produced while deserializing a validated
/// `Value` into a Stage 5 `Diagnostic`. Distinguishes the canonical
/// "missing field", "unknown field", and "invalid type" forms; classifies
/// custom errors emitted by Phase 1 newtypes by phrase matching.
fn map_serde_err(err: serde_json::Error, kind: DocumentKindLabel) -> Diagnostic {
    let msg = err.to_string();

    let code = if msg.contains("missing field") {
        DiagnosticCode::ESchemaRequiredField
    } else if msg.contains("unknown field") {
        DiagnosticCode::ESchemaUnknownField
    } else if msg.contains("invalid type") {
        DiagnosticCode::ESchemaFieldType
    } else if is_range_message(&msg) {
        DiagnosticCode::ESchemaFieldRange
    } else if is_length_message(&msg) {
        DiagnosticCode::ESchemaFieldLength
    } else if is_syntax_message(&msg) {
        DiagnosticCode::ESchemaFieldSyntax
    } else {
        DiagnosticCode::ESchemaFieldType
    };

    Diagnostic::new(code, kind, msg.clone())
        .with_details(serde_json::json!({ "serde_message": msg }))
}

fn is_range_message(msg: &str) -> bool {
    msg.contains("must be in")
        || msg.contains("out of range")
        || msg.contains("out-of-range")
        || msg.contains("between")
}

fn is_length_message(msg: &str) -> bool {
    msg.contains("exceeds maximum length")
        || msg.contains("expected ")
            && (msg.contains("base64url characters") || msg.contains("ASCII characters"))
}

fn is_syntax_message(msg: &str) -> bool {
    // Phase 1 newtype error messages.
    msg.contains("slug")
        || msg.contains("path")
        || msg.contains("timestamp")
        || msg.contains("base64url")
        || msg.contains("onion")
        || msg.contains("spec_version")
}
