//! Stage 3 — JSON parsing with parser-enforced limits. §10.
//!
//! Deserialization goes through a custom `serde::Visitor` that produces a
//! `serde_json::Value` while rejecting **duplicate object keys** at parse
//! time. Without this, `serde_json::from_str` silently last-write-wins and
//! a hostile producer could hide a payload under the surviving key.
//!
//! Errors raised by `serde_json` are then post-classified: messages whose
//! text identifies a malformed `\uXXXX` surrogate pair are mapped to
//! `E_SCHEMA_MALFORMED_UNICODE` per §11; everything else is `E_PARSE_JSON`.
//! The `walk_limits` post-pass still enforces depth/length caps; it remains
//! O(n) over the same input bounded by Stage 2's 1 MiB cap.

use std::fmt;

use serde::de::{Deserialize, Deserializer, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

use super::diagnostic::{Diagnostic, DiagnosticCode, DocumentKindLabel};
use super::limits::{
    MAX_JSON_ARRAY_ELEMENTS, MAX_JSON_NESTING_DEPTH, MAX_JSON_OBJECT_KEYS, MAX_JSON_STRING_BYTES,
};

/// Stage 3 entry: parse and apply parser limits. The diagnostic
/// `document_kind` is `None` because the kind is not yet known at this
/// stage; callers may reassign it after Stage 4.
pub fn parse_with_limits(s: &str) -> Result<Value, Diagnostic> {
    let value: Value = serde_json::from_str::<DedupedValue>(s)
        .map(|d| d.0)
        .map_err(classify_serde_error)?;
    walk_limits(&value)?;
    Ok(value)
}

/// Map a `serde_json` deserialization error to a Stage 3 diagnostic.
///
/// Surrogate-pair complaints (`\uXXXX` escapes that don't form a valid code
/// point) are routed to `E_SCHEMA_MALFORMED_UNICODE` because §11 reserves
/// that code for "malformed Unicode escape sequences or isolated
/// surrogates". Every other parse failure — including the duplicate-key
/// rejection emitted by `DedupedMapVisitor` — falls under `E_PARSE_JSON`.
fn classify_serde_error(e: serde_json::Error) -> Diagnostic {
    let msg = e.to_string();
    if is_surrogate_error(&msg) {
        return Diagnostic::new(
            DiagnosticCode::ESchemaMalformedUnicode,
            DocumentKindLabel::None,
            format!("malformed Unicode escape: {msg}"),
        );
    }
    Diagnostic::new(
        DiagnosticCode::EParseJson,
        DocumentKindLabel::None,
        format!("body is not parseable as JSON: {msg}"),
    )
}

fn is_surrogate_error(msg: &str) -> bool {
    // serde_json reports `\uXXXX` failures with a small fixed set of phrases:
    // "lone leading surrogate in hex escape", "unexpected end of hex escape",
    // and "invalid unicode code point". Each of these is exactly the
    // §11 condition for `E_SCHEMA_MALFORMED_UNICODE` ("malformed Unicode
    // escape sequences or isolated surrogates"). Generic "invalid escape"
    // errors (e.g. `\q`) are *not* matched here and remain `E_PARSE_JSON`.
    let lower = msg.to_ascii_lowercase();
    lower.contains("surrogate") || lower.contains("hex escape") || lower.contains("invalid unicode")
}

/// Wrapper around `serde_json::Value` whose `Deserialize` impl rejects
/// duplicate object keys.
struct DedupedValue(Value);

impl<'de> Deserialize<'de> for DedupedValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(DedupedValueVisitor).map(DedupedValue)
    }
}

struct DedupedValueVisitor;

impl<'de> Visitor<'de> for DedupedValueVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any valid JSON value")
    }

    fn visit_bool<E: DeError>(self, v: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E: DeError>(self, v: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_u64<E: DeError>(self, v: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_f64<E: DeError>(self, v: f64) -> Result<Self::Value, E> {
        Ok(serde_json::Number::from_f64(v)
            .map(Value::Number)
            .unwrap_or(Value::Null))
    }
    fn visit_str<E: DeError>(self, v: &str) -> Result<Self::Value, E> {
        Ok(Value::String(v.to_owned()))
    }
    fn visit_string<E: DeError>(self, v: String) -> Result<Self::Value, E> {
        Ok(Value::String(v))
    }
    fn visit_unit<E: DeError>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E: DeError>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }
    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        Deserialize::deserialize(d).map(|DedupedValue(v)| v)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));
        while let Some(DedupedValue(v)) = seq.next_element()? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut out = serde_json::Map::with_capacity(map.size_hint().unwrap_or(0));
        while let Some(key) = map.next_key::<String>()? {
            let DedupedValue(value) = map.next_value()?;
            if out.contains_key(&key) {
                return Err(A::Error::custom(format!("duplicate object key {key:?}")));
            }
            out.insert(key, value);
        }
        Ok(Value::Object(out))
    }
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
