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
fn utf16_distinguishing_supplementary_vs_pua() {
    // This case rigorously distinguishes UTF-8 byte ordering from
    // UTF-16-code-unit ordering — the previous test (~ vs 😀) sorts the same
    // way under both, so it could not catch a regression to byte ordering.
    //
    // 😀 (U+1F600): UTF-8 starts with 0xF0; UTF-16 high surrogate 0xD83D.
    // \u{E000}    : UTF-8 starts with 0xEE; UTF-16 code unit 0xE000.
    //
    // Byte order:  \u{E000} (0xEE) < 😀 (0xF0)  → PUA before emoji.
    // UTF-16 code unit order: 😀 (0xD83D) < \u{E000} (0xE000) → emoji before PUA.
    //
    // JCS mandates UTF-16 code unit order, so emoji must appear first.
    let v = json!({"\u{E000}": 1, "\u{1F600}": 2});
    let bytes = canonicalize(&v).unwrap();

    // 😀 encodes to F0 9F 98 80 in UTF-8.
    let emoji_bytes: &[u8] = &[0xF0, 0x9F, 0x98, 0x80];
    // \u{E000} encodes to EE 80 80 in UTF-8.
    let pua_bytes: &[u8] = &[0xEE, 0x80, 0x80];

    let pos_emoji = bytes
        .windows(emoji_bytes.len())
        .position(|w| w == emoji_bytes)
        .expect("emoji bytes must be in canonical output");
    let pos_pua = bytes
        .windows(pua_bytes.len())
        .position(|w| w == pua_bytes)
        .expect("PUA bytes must be in canonical output");

    assert!(
        pos_emoji < pos_pua,
        "UTF-16 code unit ordering required: 😀 (0xD83D) must precede \\u{{E000}} (0xE000); \
         pos_emoji={pos_emoji} pos_pua={pos_pua} canonical={canonical:?}",
        canonical = String::from_utf8_lossy(&bytes)
    );
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
