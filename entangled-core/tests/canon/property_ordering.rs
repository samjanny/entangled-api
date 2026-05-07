//! JCS property ordering: lexicographic comparison of UTF-16 code units of
//! property names.

use entangled_core::canon::canonicalize;
use serde_json::json;

fn canon_str(v: &serde_json::Value) -> String {
    let bytes = canonicalize(v).unwrap();
    String::from_utf8(bytes).unwrap()
}

#[test]
fn two_keys_swap_into_lexicographic_order() {
    let v = json!({"b": 1, "a": 2});
    assert_eq!(canon_str(&v), r#"{"a":2,"b":1}"#);
}

#[test]
fn three_keys_out_of_order() {
    let v = json!({"c": 1, "a": 2, "b": 3});
    assert_eq!(canon_str(&v), r#"{"a":2,"b":3,"c":1}"#);
}

#[test]
fn nested_objects_each_get_their_own_ordering() {
    let v = json!({"z": {"y": 1, "x": 2}, "a": 1});
    assert_eq!(canon_str(&v), r#"{"a":1,"z":{"x":2,"y":1}}"#);
}

#[test]
fn keys_differing_only_in_last_character() {
    let v = json!({"abc": 1, "abd": 2});
    assert_eq!(canon_str(&v), r#"{"abc":1,"abd":2}"#);
}

#[test]
fn supplementary_codepoint_key_sorts_after_ascii_tilde_under_utf16_ordering() {
    // U+1F600 GRINNING FACE: UTF-16 code unit sequence is [0xD83D, 0xDE00].
    // U+007E TILDE: [0x007E].
    // UTF-16 lexical comparison: 0x007E < 0xD83D, so "~" sorts before "😀".
    let v = json!({"\u{1F600}": 1, "~": 2});
    let canonical = canon_str(&v);
    assert_eq!(canonical, "{\"~\":2,\"\u{1F600}\":1}");

    // Verify positions explicitly so a regression to byte ordering would
    // still surface even if the assertion above were edited carelessly.
    let pos_tilde = canonical.find('~').expect("~ must be in canonical form");
    let pos_emoji = canonical
        .find('\u{1F600}')
        .expect("emoji must be in canonical form");
    assert!(
        pos_tilde < pos_emoji,
        "UTF-16 ordering: ~ must precede emoji in canonical output"
    );
}
