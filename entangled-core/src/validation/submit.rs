//! Submit body validation (§09).
//!
//! `validate_submit_body` checks the schema of an already-deserialized
//! `SubmitBody`: pair count, slug syntax of every `fields` key, and value
//! byte caps. `validate_submit_body_bytes` runs the same Stage 2/3
//! pipeline used elsewhere (byte cap, BOM, UTF-8, JSON limits, null/float
//! pre-pass), then deserializes into a closed-schema `SubmitBody` before
//! handing off to `validate_submit_body`.

use std::collections::HashSet;

use serde_json::Value;

use crate::state::submit::SubmitBody;
use crate::types::slug::Slug;

use super::diagnostic::{Diagnostic, DiagnosticCode, DocumentKindLabel};
use super::input::{check_input, InputKind};
use super::limits::{
    STATE_VALUE_MAX_BYTES, SUBMIT_FIELDS_MAX_PAIRS, SUBMIT_FIELD_VALUE_MAX_BYTES,
    SUBMIT_REQUEST_STATE_MAX_ENTRIES,
};
use super::parse::parse_with_limits;

/// Check a deserialized `SubmitBody` against §09 caps and slug syntax.
pub fn validate_submit_body(body: &SubmitBody) -> Result<(), Diagnostic> {
    if body.fields.len() > SUBMIT_FIELDS_MAX_PAIRS {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldLength,
            DocumentKindLabel::None,
            format!(
                "submit body fields has {} pairs, max is {SUBMIT_FIELDS_MAX_PAIRS}",
                body.fields.len()
            ),
        ));
    }
    for (k, v) in &body.fields {
        // Slug syntax: same rule as state namespace/key. The Slug newtype
        // is the single source of truth for that syntax.
        if Slug::try_from(k.as_str()).is_err() {
            return Err(Diagnostic::new(
                DiagnosticCode::ESchemaFieldSyntax,
                DocumentKindLabel::None,
                format!("submit body fields key {k:?} is not a valid slug"),
            ));
        }
        if v.len() > SUBMIT_FIELD_VALUE_MAX_BYTES {
            return Err(Diagnostic::new(
                DiagnosticCode::ESchemaFieldLength,
                DocumentKindLabel::None,
                format!(
                    "submit body field {k:?} value of {} bytes exceeds cap of {SUBMIT_FIELD_VALUE_MAX_BYTES}",
                    v.len()
                ),
            ));
        }
    }
    if body.request_state.len() > SUBMIT_REQUEST_STATE_MAX_ENTRIES {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldLength,
            DocumentKindLabel::None,
            format!(
                "submit body request_state has {} entries, max is {SUBMIT_REQUEST_STATE_MAX_ENTRIES}",
                body.request_state.len()
            ),
        ));
    }
    // RequestStateItem.namespace / key are already `Slug` (validated at
    // deserialize). §09 (rc.10) places a 4096-byte schema cap on each
    // `value` — the protocol's absolute state-value ceiling restated for the
    // submit body. Per-policy `max_size` (≤ 4096) was enforced at `set`
    // time; this cap is the wire-side defence-in-depth check.
    for entry in &body.request_state {
        if entry.value.len() > STATE_VALUE_MAX_BYTES {
            return Err(Diagnostic::new(
                DiagnosticCode::ESchemaFieldLength,
                DocumentKindLabel::None,
                format!(
                    "submit body request_state value of {} bytes exceeds cap of {STATE_VALUE_MAX_BYTES}",
                    entry.value.len()
                ),
            ));
        }
    }

    // §09: each (namespace, key) pair appears at most once. Publishers MUST
    // reject submit bodies containing duplicate request_state entries
    // (`E_STATE_DUPLICATE`, §11). A conformant client never emits one;
    // running the check here protects publisher-side parsers that share
    // this validator.
    let mut seen: HashSet<(&Slug, &Slug)> = HashSet::with_capacity(body.request_state.len());
    for entry in &body.request_state {
        if !seen.insert((&entry.namespace, &entry.key)) {
            return Err(Diagnostic::new(
                DiagnosticCode::EStateDuplicate,
                DocumentKindLabel::Transaction,
                format!(
                    "duplicate request_state entry for ({}, {})",
                    entry.namespace.as_str(),
                    entry.key.as_str()
                ),
            )
            .with_details(serde_json::json!({
                "duplicate_namespace": entry.namespace.as_str(),
                "duplicate_key": entry.key.as_str(),
            })));
        }
    }
    Ok(())
}

/// Full pipeline: bytes → SubmitBody, with Stage 2/3 checks, the §0.10
/// null/float pre-pass, deserialization with `deny_unknown_fields`, and
/// finally `validate_submit_body`.
pub fn validate_submit_body_bytes(raw: &[u8]) -> Result<SubmitBody, Diagnostic> {
    let s = check_input(raw, InputKind::SubmitBody)?;
    let value = parse_with_limits(s).map_err(|d| set_kind(d, DocumentKindLabel::None))?;
    null_and_float_prepass(&value)?;
    let body: SubmitBody = serde_json::from_value(value).map_err(map_serde_err)?;
    validate_submit_body(&body)?;
    Ok(body)
}

fn set_kind(mut d: Diagnostic, kind: DocumentKindLabel) -> Diagnostic {
    d.document_kind = kind;
    d
}

fn null_and_float_prepass(root: &Value) -> Result<(), Diagnostic> {
    let mut stack: Vec<&Value> = vec![root];
    while let Some(node) = stack.pop() {
        match node {
            Value::Null => {
                return Err(Diagnostic::new(
                    DiagnosticCode::ESchemaNullValue,
                    DocumentKindLabel::None,
                    "null literal is not permitted",
                ));
            }
            Value::Number(n) if n.is_f64() => {
                return Err(Diagnostic::new(
                    DiagnosticCode::ESchemaNonInteger,
                    DocumentKindLabel::None,
                    format!("non-integer numeric value: {n}"),
                ));
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

fn map_serde_err(err: serde_json::Error) -> Diagnostic {
    let msg = err.to_string();
    let code = if msg.contains("missing field") {
        DiagnosticCode::ESchemaRequiredField
    } else if msg.contains("unknown field") {
        DiagnosticCode::ESchemaUnknownField
    } else if msg.contains("invalid type") {
        DiagnosticCode::ESchemaFieldType
    } else if msg.contains("slug") {
        DiagnosticCode::ESchemaFieldSyntax
    } else {
        DiagnosticCode::ESchemaFieldType
    };
    Diagnostic::new(code, DocumentKindLabel::None, msg.clone())
        .with_details(serde_json::json!({ "serde_message": msg }))
}
