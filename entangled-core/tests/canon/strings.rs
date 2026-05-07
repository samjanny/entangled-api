//! String escaping per RFC 8259 minimal-escape rules used by JCS.

use entangled_core::canon::canonicalize;
use serde_json::{json, Value};

fn canon_str(v: &Value) -> String {
    String::from_utf8(canonicalize(v).unwrap()).unwrap()
}

#[test]
fn ascii_string_is_quoted_unchanged() {
    assert_eq!(canon_str(&json!("hello")), "\"hello\"");
}

#[test]
fn backslash_is_escaped_as_backslash_backslash() {
    assert_eq!(canon_str(&json!("a\\b")), r#""a\\b""#);
}

#[test]
fn double_quote_is_escaped() {
    assert_eq!(canon_str(&json!("a\"b")), r#""a\"b""#);
}

#[test]
fn tab_is_escaped_as_t() {
    assert_eq!(canon_str(&json!("a\tb")), r#""a\tb""#);
}

#[test]
fn line_feed_is_escaped_as_n() {
    assert_eq!(canon_str(&json!("a\nb")), r#""a\nb""#);
}

#[test]
fn backspace_is_escaped_as_b() {
    assert_eq!(canon_str(&json!("a\u{0008}b")), r#""a\bb""#);
}

#[test]
fn carriage_return_is_escaped_as_r() {
    assert_eq!(canon_str(&json!("a\rb")), r#""a\rb""#);
}

#[test]
fn form_feed_is_escaped_as_f() {
    assert_eq!(canon_str(&json!("a\u{000C}b")), r#""a\fb""#);
}

#[test]
fn other_c0_control_uses_lowercase_hex_u_escape() {
    // U+0001 has no shorthand: it must be emitted as a six-character
    // \u00xx sequence with lowercase hex digits.
    let got = canon_str(&json!("a\u{0001}b"));
    let expected = String::from("\"a\\u0001b\"");
    assert_eq!(got, expected);
}

#[test]
fn delete_byte_0x7f_is_passed_through_unescaped() {
    // 0x7F is not in the C0 range; RFC 8259 minimal escaping leaves it bare.
    assert_eq!(canon_str(&json!("a\u{007F}b")), "\"a\u{007F}b\"");
}

#[test]
fn accented_latin_passes_through_as_utf8_bytes() {
    let bytes = canonicalize(&json!("caffè")).unwrap();
    let expected = "\"caffè\"";
    assert_eq!(bytes, expected.as_bytes());
}

#[test]
fn supplementary_emoji_passes_through_as_utf8_bytes() {
    let bytes = canonicalize(&json!("\u{1F600}")).unwrap();
    let expected = "\"\u{1F600}\"";
    assert_eq!(bytes, expected.as_bytes());
}
