//! Reproduces the §04 normative test vector exactly: 74 bytes, ASCII string
//! match, and dump-hex match.

use entangled_core::canon::canonicalize;
use serde_json::json;

const EXPECTED_ASCII: &str =
    "{\"count\":42,\"kind\":\"content\",\"spec_version\":\"1.0\",\"value\":\"hello world\"}";

const EXPECTED_HEX: &[u8] = &[
    0x7B, 0x22, 0x63, 0x6F, 0x75, 0x6E, 0x74, 0x22, 0x3A, 0x34, 0x32, 0x2C, 0x22, 0x6B, 0x69, 0x6E,
    0x64, 0x22, 0x3A, 0x22, 0x63, 0x6F, 0x6E, 0x74, 0x65, 0x6E, 0x74, 0x22, 0x2C, 0x22, 0x73, 0x70,
    0x65, 0x63, 0x5F, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x22, 0x3A, 0x22, 0x31, 0x2E, 0x30,
    0x22, 0x2C, 0x22, 0x76, 0x61, 0x6C, 0x75, 0x65, 0x22, 0x3A, 0x22, 0x68, 0x65, 0x6C, 0x6C, 0x6F,
    0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x22, 0x7D,
];

#[test]
fn spec_section_04_test_vector_canonicalizes_byte_for_byte() {
    let input = json!({
        "kind": "content",
        "spec_version": "1.0",
        "value": "hello world",
        "count": 42
    });
    let bytes = canonicalize(&input).expect("canonicalize must succeed on the §04 vector");

    // §04 prose claims "74 bytes" but the hex dump and ASCII string it
    // publishes both contain exactly 72 bytes. The hex dump is normative
    // byte-by-byte; the prose number is a known typo. We assert against
    // the hex dump (and ASCII) which match each other at 72 bytes.
    assert_eq!(EXPECTED_ASCII.len(), 72);
    assert_eq!(EXPECTED_HEX.len(), 72);

    assert_eq!(bytes.len(), 72, "byte length must match the §04 hex dump");
    assert_eq!(
        bytes.as_slice(),
        EXPECTED_ASCII.as_bytes(),
        "ASCII byte sequence must equal §04 expected canonical form"
    );
    assert_eq!(
        bytes.as_slice(),
        EXPECTED_HEX,
        "hex dump must equal §04 expected hex sequence"
    );
}
