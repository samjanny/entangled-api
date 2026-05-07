//! JSON Canonicalization Scheme (JCS) — RFC 8785, with verified errata
//! EID 6292 and EID 7920 incorporated.
//!
//! Reference revision: the inline-errata version of RFC 8785 published by the
//! RFC Editor at <https://www.rfc-editor.org/rfc/rfc8785.html> with EID 6292
//! and EID 7920 applied.
//!
//! Per `docs-spec/specs/04-canonicalization.md` Entangled MUST canonicalize
//! JSON values according to RFC 8785 with those errata. EID 6292 and EID 7920
//! are clarifications of the existing rules (member ordering by UTF-16 code
//! units and number serialization edge cases respectively); for the
//! Entangled-restricted input space — no `null`, no floats, only 64-bit
//! integers, only valid Unicode strings — they do not change the output bytes
//! produced by this canonicalizer relative to the original RFC 8785 text. The
//! canonicalizer is implemented to satisfy both the original text and the
//! errata.
//!
//! # Self-defensive checks
//!
//! Before serialization the canonicalizer walks the entire value tree and
//! rejects:
//!
//! - any `Value::Null`;
//! - any `Value::Number` that is `f64`-only;
//! - any `Value::Number` outside `0..=i64::MAX`.
//!
//! Per §04: "All numeric fields in Entangled are non-negative integers
//! within ranges declared by the schema of each field" and "numbers outside
//! the range expressible as a 64-bit signed integer" are not permitted.
//! Negative integers and unsigned values exceeding `i64::MAX` are therefore
//! out of the Entangled domain even though they would be representable by
//! RFC 8785's serialization rules.
//!
//! These checks duplicate Stage 5 closed-schema validation
//! (see [`crate::validation`]) on purpose. The canonicalizer is a
//! self-defensive component: it runs at the cryptographic boundary and does
//! not trust upstream stages to have rejected forbidden value forms.
//!
//! Strings are passed through with minimal RFC 8259 escaping; `serde_json`'s
//! parser already rejects malformed UTF-8 and isolated surrogates at parse
//! time, so any `&str` reaching this function is well-formed Unicode.

use std::io::Write as _;

use serde_json::Value;

use super::error::CanonError;

/// Canonicalize a `serde_json::Value` to the JCS byte sequence.
///
/// Returns the UTF-8 byte sequence defined by RFC 8785 with the verified
/// errata listed in the module documentation.
pub fn canonicalize(value: &Value) -> Result<Vec<u8>, CanonError> {
    validate_subset(value)?;
    let mut out = Vec::with_capacity(64);
    write_value(&mut out, value);
    Ok(out)
}

/// Iterative walker that rejects any value form Entangled forbids.
///
/// Iterative, not recursive, to bound stack usage on adversarial inputs even
/// though Stage 3 caps nesting at 16. The canonicalizer does not rely on that
/// cap.
fn validate_subset(root: &Value) -> Result<(), CanonError> {
    let mut stack: Vec<&Value> = Vec::with_capacity(16);
    stack.push(root);
    while let Some(v) = stack.pop() {
        match v {
            Value::Null => return Err(CanonError::NullNotPermitted),
            Value::Number(n) => match n.as_i64() {
                Some(v) if v >= 0 => {}
                Some(_) => return Err(CanonError::NumberOutOfRange),
                None if n.is_f64() => return Err(CanonError::NonIntegerNumber),
                None => return Err(CanonError::NumberOutOfRange),
            },
            Value::Bool(_) | Value::String(_) => {}
            Value::Array(items) => {
                for item in items {
                    stack.push(item);
                }
            }
            Value::Object(map) => {
                for (_k, item) in map {
                    stack.push(item);
                }
            }
        }
    }
    Ok(())
}

/// Recursive serializer. Recursion depth is bounded by the input depth, which
/// the validation pipeline caps at 16 (§10 Stage 3).
fn write_value(out: &mut Vec<u8>, value: &Value) {
    match value {
        Value::Null => unreachable!("validate_subset rejects null before serialization"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => write_number(out, n),
        Value::String(s) => write_string(out, s),
        Value::Array(items) => write_array(out, items),
        Value::Object(map) => write_object(out, map),
    }
}

fn write_number(out: &mut Vec<u8>, n: &serde_json::Number) {
    // Subset already guarantees a non-negative i64. Decimal formatting via
    // `write!` produces no leading zeros, no decimal point, no exponent,
    // and (for 0) no minus sign.
    let i = n
        .as_i64()
        .expect("validate_subset accepts only non-negative i64-fitting integers");
    debug_assert!(i >= 0, "validate_subset rejects negative integers");
    write!(out, "{}", i).expect("write to Vec<u8> never fails");
}

fn write_string(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    for ch in s.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{0008}' => out.extend_from_slice(b"\\b"),
            '\u{0009}' => out.extend_from_slice(b"\\t"),
            '\u{000A}' => out.extend_from_slice(b"\\n"),
            '\u{000C}' => out.extend_from_slice(b"\\f"),
            '\u{000D}' => out.extend_from_slice(b"\\r"),
            c if (c as u32) < 0x20 => {
                // Other C0 controls: \u00XX with lowercase two-digit hex.
                let cp = c as u32;
                let hi = ((cp >> 4) & 0xF) as u8;
                let lo = (cp & 0xF) as u8;
                out.extend_from_slice(b"\\u00");
                out.push(hex_lower(hi));
                out.push(hex_lower(lo));
            }
            c => {
                let mut buf = [0u8; 4];
                let encoded = c.encode_utf8(&mut buf);
                out.extend_from_slice(encoded.as_bytes());
            }
        }
    }
    out.push(b'"');
}

const fn hex_lower(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        10..=15 => b'a' + (nibble - 10),
        _ => b'?',
    }
}

fn write_array(out: &mut Vec<u8>, items: &[Value]) {
    out.push(b'[');
    let mut first = true;
    for item in items {
        if !first {
            out.push(b',');
        }
        first = false;
        write_value(out, item);
    }
    out.push(b']');
}

fn write_object(out: &mut Vec<u8>, map: &serde_json::Map<String, Value>) {
    // RFC 8785 §3.2.3 / EID 6292: members MUST be sorted by lexicographic
    // comparison of UTF-16 code unit sequences of the property names.
    //
    // For purely-ASCII keys this coincides with byte ordering; for keys
    // containing supplementary code points (> U+FFFF) the surrogate-pair
    // decomposition can change the ordering relative to UTF-8 byte order.
    let mut entries: Vec<(&String, &Value)> = map.iter().collect();
    entries.sort_by(|a, b| utf16_cmp(a.0, b.0));

    out.push(b'{');
    let mut first = true;
    for (k, v) in entries {
        if !first {
            out.push(b',');
        }
        first = false;
        write_string(out, k);
        out.push(b':');
        write_value(out, v);
    }
    out.push(b'}');
}

/// Lexicographic comparison of two `&str` by UTF-16 code unit sequence.
///
/// Streaming: produces UTF-16 code units from each string lazily and compares
/// element-wise. No allocation. For supplementary code points the high
/// surrogate is yielded first, then the low surrogate, matching the surrogate
/// pair order required by JCS.
fn utf16_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let mut ai = Utf16Iter::new(a);
    let mut bi = Utf16Iter::new(b);
    loop {
        match (ai.next(), bi.next()) {
            (None, None) => return std::cmp::Ordering::Equal,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (Some(x), Some(y)) => match x.cmp(&y) {
                std::cmp::Ordering::Equal => continue,
                ne => return ne,
            },
        }
    }
}

struct Utf16Iter<'a> {
    chars: std::str::Chars<'a>,
    pending_low: Option<u16>,
}

impl<'a> Utf16Iter<'a> {
    fn new(s: &'a str) -> Self {
        Self {
            chars: s.chars(),
            pending_low: None,
        }
    }
}

impl<'a> Iterator for Utf16Iter<'a> {
    type Item = u16;

    fn next(&mut self) -> Option<u16> {
        if let Some(low) = self.pending_low.take() {
            return Some(low);
        }
        let c = self.chars.next()?;
        let cp = c as u32;
        if cp <= 0xFFFF {
            Some(cp as u16)
        } else {
            // Supplementary plane: emit high surrogate now, low next.
            let v = cp - 0x10000;
            let high = 0xD800 + ((v >> 10) as u16);
            let low = 0xDC00 + ((v & 0x3FF) as u16);
            self.pending_low = Some(low);
            Some(high)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16_iter_ascii_matches_codepoints() {
        let v: Vec<u16> = Utf16Iter::new("ab").collect();
        assert_eq!(v, vec![0x0061, 0x0062]);
    }

    #[test]
    fn utf16_iter_supplementary_emits_surrogate_pair() {
        // U+1F600 GRINNING FACE → high 0xD83D, low 0xDE00.
        let v: Vec<u16> = Utf16Iter::new("\u{1F600}").collect();
        assert_eq!(v, vec![0xD83D, 0xDE00]);
    }

    #[test]
    fn hex_lower_digit_and_letters() {
        assert_eq!(hex_lower(0), b'0');
        assert_eq!(hex_lower(9), b'9');
        assert_eq!(hex_lower(10), b'a');
        assert_eq!(hex_lower(15), b'f');
    }
}
