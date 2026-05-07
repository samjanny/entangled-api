//! Stage 3 — JSON parsing with parser-enforced limits. §10.
//!
//! Note: `serde_json` parses the entire input before this walker runs.
//! Stage 2's byte cap (≤ 1 MiB) bounds the worst-case allocation. A future
//! optimization could use `serde_json::StreamDeserializer` or a custom
//! `Visitor` to enforce limits during parse, eliminating the post-parse
//! walk.

use serde_json::Value;

use super::diagnostic::{Diagnostic, DiagnosticCode, DocumentKindLabel};
use super::limits::{
    MAX_JSON_ARRAY_ELEMENTS, MAX_JSON_NESTING_DEPTH, MAX_JSON_OBJECT_KEYS, MAX_JSON_STRING_BYTES,
};

/// Stage 3 entry: parse and apply parser limits. The diagnostic
/// `document_kind` is `None` because the kind is not yet known at this
/// stage; callers may reassign it after Stage 4.
pub fn parse_with_limits(s: &str) -> Result<Value, Diagnostic> {
    let value: Value = serde_json::from_str(s).map_err(|e| {
        Diagnostic::new(
            DiagnosticCode::EParseJson,
            DocumentKindLabel::None,
            format!("body is not parseable as JSON: {e}"),
        )
    })?;
    walk_limits(&value)?;
    Ok(value)
}

fn walk_limits(root: &Value) -> Result<(), Diagnostic> {
    // Iterative walker. `depth` is the nesting depth of the current node;
    // the root is at depth 1.
    let mut stack: Vec<(&Value, usize)> = Vec::with_capacity(16);
    stack.push((root, 1));

    while let Some((node, depth)) = stack.pop() {
        // Depth applies to compound nodes only. A leaf (string/number/bool)
        // is "at" its parent's depth and doesn't itself consume nesting.
        match node {
            Value::String(s) if s.len() > MAX_JSON_STRING_BYTES => {
                return Err(Diagnostic::new(
                    DiagnosticCode::EParseStringLength,
                    DocumentKindLabel::None,
                    format!(
                        "JSON string of {} bytes exceeds limit of {MAX_JSON_STRING_BYTES}",
                        s.len()
                    ),
                ));
            }
            Value::Array(arr) => {
                if depth > MAX_JSON_NESTING_DEPTH {
                    return Err(Diagnostic::new(
                        DiagnosticCode::EParseNestingDepth,
                        DocumentKindLabel::None,
                        format!(
                            "JSON nesting depth {depth} exceeds limit of {MAX_JSON_NESTING_DEPTH}"
                        ),
                    ));
                }
                if arr.len() > MAX_JSON_ARRAY_ELEMENTS {
                    return Err(Diagnostic::new(
                        DiagnosticCode::EParseArrayLength,
                        DocumentKindLabel::None,
                        format!(
                            "JSON array of {} elements exceeds limit of {MAX_JSON_ARRAY_ELEMENTS}",
                            arr.len()
                        ),
                    ));
                }
                for child in arr {
                    stack.push((child, depth + 1));
                }
            }
            Value::Object(map) => {
                if depth > MAX_JSON_NESTING_DEPTH {
                    return Err(Diagnostic::new(
                        DiagnosticCode::EParseNestingDepth,
                        DocumentKindLabel::None,
                        format!(
                            "JSON nesting depth {depth} exceeds limit of {MAX_JSON_NESTING_DEPTH}"
                        ),
                    ));
                }
                if map.len() > MAX_JSON_OBJECT_KEYS {
                    return Err(Diagnostic::new(
                        DiagnosticCode::EParseObjectKeys,
                        DocumentKindLabel::None,
                        format!(
                            "JSON object of {} keys exceeds limit of {MAX_JSON_OBJECT_KEYS}",
                            map.len()
                        ),
                    ));
                }
                for (k, v) in map {
                    if k.len() > MAX_JSON_STRING_BYTES {
                        return Err(Diagnostic::new(
                            DiagnosticCode::EParseStringLength,
                            DocumentKindLabel::None,
                            format!(
                                "JSON object key of {} bytes exceeds limit of {MAX_JSON_STRING_BYTES}",
                                k.len()
                            ),
                        ));
                    }
                    stack.push((v, depth + 1));
                }
            }
            // Bool, Number, Null are leaves.
            _ => {}
        }
    }
    Ok(())
}
