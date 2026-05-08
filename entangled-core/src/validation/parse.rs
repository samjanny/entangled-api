//! Stage 3 — JSON parsing with parser-enforced limits. §10.
//!
//! Deserialization goes through a custom `serde::Visitor` that produces a
//! `serde_json::Value` while rejecting **duplicate object keys** at parse
//! time (§04, §10 Stage 3). Without this, `serde_json::from_str` silently
//! last-write-wins and a hostile producer could hide a payload under the
//! surviving key.
//!
//! Errors raised by `serde_json` are then post-classified: a duplicate-key
//! rejection is reported as `E_PARSE_DUPLICATE_KEY` (§11) with structured
//! `details` carrying the duplicated member name and a JSON-pointer
//! `object_path` to the offending object; messages identifying a malformed
//! `\uXXXX` surrogate pair are mapped to `E_SCHEMA_MALFORMED_UNICODE`;
//! everything else is `E_PARSE_JSON`. The `walk_limits` post-pass still
//! enforces depth/length caps; it remains O(n) over the same input
//! bounded by Stage 2's 1 MiB cap.

use std::cell::RefCell;
use std::fmt;

use serde::de::{Deserialize, Deserializer, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

use super::diagnostic::{Diagnostic, DiagnosticCode, DocumentKindLabel};
use super::limits::{
    MAX_JSON_ARRAY_ELEMENTS, MAX_JSON_NESTING_DEPTH, MAX_JSON_OBJECT_KEYS, MAX_JSON_STRING_BYTES,
};

thread_local! {
    /// Path of object keys currently being descended into. Pushed before
    /// recursing into a child value, popped after. Captured into
    /// `DEDUP_INFO` if a duplicate key is hit at the deepest object.
    static DEDUP_PATH: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    /// Set when the duplicate-key visitor rejects a map. Read by
    /// `classify_serde_error` to attach structured details.
    static DEDUP_INFO: RefCell<Option<DuplicateInfo>> = const { RefCell::new(None) };
}

/// Captured at the visitor when a duplicate object key is detected; consumed
/// by `classify_serde_error` to emit `E_PARSE_DUPLICATE_KEY` details.
struct DuplicateInfo {
    duplicate_key: String,
    object_path: String,
}

/// Stage 3 entry: parse and apply parser limits. The diagnostic
/// `document_kind` is `None` because the kind is not yet known at this
/// stage; callers may reassign it after Stage 4.
pub fn parse_with_limits(s: &str) -> Result<Value, Diagnostic> {
    DEDUP_INFO.with(|i| {
        i.borrow_mut().take();
    });
    DEDUP_PATH.with(|p| {
        p.borrow_mut().clear();
    });
    let value: Value = serde_json::from_str::<DedupedValue>(s)
        .map(|d| d.0)
        .map_err(classify_serde_error)?;
    enforce_integer_grammar(s)?;
    walk_limits(&value)?;
    Ok(value)
}

/// Lexically enforce the §04 integer grammar
/// (`integer = "0" / non-zero-digit *digit`) by scanning the raw input
/// bytes outside of JSON strings.
///
/// `serde_json` already rejects JSON syntax errors (so leading-zero forms
/// like `01` never reach this step) and `schema_prepass` rejects `f64`
/// numbers in parsed `Value`s. This pass closes the remaining gaps that
/// neither catches:
///
/// * `-0` — silently parsed as `0` by typical JSON readers, which would
///   conflate negative zero with positive zero.
/// * any negative integer — Entangled has no signed integer fields; a
///   value like `-1` outside a typed deserializer would slip through.
/// * any integer whose decimal value exceeds `2^63 − 1` — fits in
///   `serde_json::Number::PosInt(u64)` but is out of the protocol-wide
///   range.
/// * float-shaped tokens (`1.0`, `1e0`, `1E1`) as a defence-in-depth
///   layer; `schema_prepass` reaches the same verdict on the parsed
///   `Value`, but catching them here keeps the lexical contract explicit.
///
/// The scanner is a tiny state machine: it skips JSON string contents
/// (handling backslash escapes) and treats every numeric run starting
/// with `-` or an ASCII digit as a token to validate.
fn enforce_integer_grammar(input: &str) -> Result<(), Diagnostic> {
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'"' => {
                i += 1;
                while i < bytes.len() {
                    match bytes[i] {
                        b'\\' if i + 1 < bytes.len() => i += 2,
                        b'"' => {
                            i += 1;
                            break;
                        }
                        _ => i += 1,
                    }
                }
            }
            b'-' | b'0'..=b'9' => {
                let start = i;
                i += 1;
                while i < bytes.len()
                    && matches!(
                        bytes[i],
                        b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-'
                    )
                {
                    i += 1;
                }
                check_integer_token(&input[start..i])?;
            }
            _ => i += 1,
        }
    }
    Ok(())
}

/// Validate a single numeric token against §04's integer grammar.
fn check_integer_token(token: &str) -> Result<(), Diagnostic> {
    if token
        .bytes()
        .any(|b| matches!(b, b'.' | b'e' | b'E' | b'+'))
    {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaNonInteger,
            DocumentKindLabel::None,
            format!("non-integer numeric token {token:?}"),
        ));
    }
    if let Some(rest) = token.strip_prefix('-') {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldRange,
            DocumentKindLabel::None,
            if rest == "0" {
                format!("negative-zero numeric token {token:?} is not in the integer grammar")
            } else {
                format!(
                    "negative integer {token:?} is not in the protocol range [0, 2^63 - 1]"
                )
            },
        ));
    }
    let value: u64 = token.parse().map_err(|_| {
        Diagnostic::new(
            DiagnosticCode::ESchemaFieldRange,
            DocumentKindLabel::None,
            format!("integer token {token:?} exceeds the protocol range [0, 2^63 - 1]"),
        )
    })?;
    if value > i64::MAX as u64 {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldRange,
            DocumentKindLabel::None,
            format!("integer {value} exceeds the protocol range [0, 2^63 - 1]"),
        ));
    }
    Ok(())
}

/// Map a `serde_json` deserialization error to a Stage 3 diagnostic.
///
/// A duplicate-key rejection (signalled via the `DEDUP_INFO` thread-local
/// captured by the visitor) is reported as `E_PARSE_DUPLICATE_KEY` (§04,
/// §11) with structured details `{ duplicate_key, object_path }`.
/// Surrogate-pair complaints (`\uXXXX` escapes that don't form a valid code
/// point) are routed to `E_SCHEMA_MALFORMED_UNICODE` because §11 reserves
/// that code for "malformed Unicode escape sequences or isolated
/// surrogates". Every other parse failure falls under `E_PARSE_JSON`.
fn classify_serde_error(e: serde_json::Error) -> Diagnostic {
    let dup = DEDUP_INFO.with(|i| i.borrow_mut().take());
    if let Some(info) = dup {
        return Diagnostic::new(
            DiagnosticCode::EParseDuplicateKey,
            DocumentKindLabel::None,
            format!(
                "duplicate object member name {:?} at {}",
                info.duplicate_key, info.object_path
            ),
        )
        .with_details(serde_json::json!({
            "duplicate_key": info.duplicate_key,
            "object_path": info.object_path,
        }));
    }
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
            if out.contains_key(&key) {
                let object_path = DEDUP_PATH.with(|p| {
                    let parts = p.borrow();
                    if parts.is_empty() {
                        "/".to_owned()
                    } else {
                        let mut s = String::new();
                        for part in parts.iter() {
                            s.push('/');
                            s.push_str(&escape_json_pointer(part));
                        }
                        s
                    }
                });
                DEDUP_INFO.with(|i| {
                    *i.borrow_mut() = Some(DuplicateInfo {
                        duplicate_key: key.clone(),
                        object_path,
                    });
                });
                return Err(A::Error::custom(format!(
                    "duplicate object member name {key:?}"
                )));
            }
            DEDUP_PATH.with(|p| p.borrow_mut().push(key.clone()));
            let result = map.next_value::<DedupedValue>();
            DEDUP_PATH.with(|p| {
                p.borrow_mut().pop();
            });
            let DedupedValue(value) = result?;
            out.insert(key, value);
        }
        Ok(Value::Object(out))
    }
}

/// Escape a member name for use as a single segment of an RFC 6901 JSON
/// pointer: `~` becomes `~0`, `/` becomes `~1`. Other characters are
/// emitted as-is.
fn escape_json_pointer(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '~' => out.push_str("~0"),
            '/' => out.push_str("~1"),
            _ => out.push(c),
        }
    }
    out
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
