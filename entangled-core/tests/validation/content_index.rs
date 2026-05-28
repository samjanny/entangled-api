//! Content index parser hardening (§02:208, rc.19 N46-N49).
//!
//! The content index is hash-bound to a `K_publisher`-signed
//! commitment in the manifest's `content_root`. §02:208 normatively
//! requires that two conforming parsers produce identical interpretations
//! of the same content index bytes; this implies the same input
//! disciplines as Entangled documents — strict UTF-8, no BOM, no
//! duplicate JSON keys (rejection on duplicate, not first-wins or
//! last-wins), §04 integer grammar, and the Stage 3 JSON limits.
//!
//! These tests pin those disciplines on the public
//! [`validate_content_index`] entry point.

use entangled_core::crypto::sha256;
use entangled_core::types::keys::ContentRoot;
use entangled_core::validation::{validate_content_index, DiagnosticCode};

/// Build a content_root that matches `bytes`, so the validator gets past
/// the hash check and exercises the parse disciplines that follow.
fn matching_root(bytes: &[u8]) -> ContentRoot {
    ContentRoot::from_bytes(sha256(bytes))
}

#[test]
fn well_formed_minimal_index_accepted() {
    let bytes = br#"{"entries":{}}"#.to_vec();
    let root = matching_root(&bytes);
    let idx = validate_content_index(&bytes, &root).expect("valid empty index");
    assert!(idx.is_empty());
}

#[test]
fn duplicate_entries_key_rejected_per_section_02_208() {
    // Two distinct values for the same path key. serde_json's default
    // behaviour is last-wins, which silently collapses the duplicate to
    // {seq:99, hash:H2}; under §02:208 the same bytes interpreted by
    // another conforming parser might yield {seq:1, hash:H1}, breaking
    // the hash-binding invariant ("two parsers, same bytes, same
    // commitment"). The parser MUST reject on duplicate.
    let bytes = br#"{"entries":{"/x":{"seq":1,"hash":"sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},"/x":{"seq":99,"hash":"sha-256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}}}"#.to_vec();
    let root = matching_root(&bytes);
    let err = validate_content_index(&bytes, &root)
        .expect_err("duplicate key MUST be rejected per §02:208");
    assert_eq!(err.code, DiagnosticCode::EContentIndexInvalid);
}

#[test]
fn duplicate_top_level_key_rejected() {
    // Duplicate at the top level: `entries` appears twice. Same rule.
    let bytes = br#"{"entries":{},"entries":{}}"#.to_vec();
    let root = matching_root(&bytes);
    let err = validate_content_index(&bytes, &root)
        .expect_err("duplicate top-level key MUST be rejected");
    assert_eq!(err.code, DiagnosticCode::EContentIndexInvalid);
}

#[test]
fn float_seq_rejected_by_integer_grammar() {
    // §04 integer grammar: no floats. A `seq` literal of `1.0` is a
    // lexical violation of the grammar even though it would deserialize
    // to u64 = 1 under a tolerant parser. parse_with_limits rejects.
    let bytes = br#"{"entries":{"/x":{"seq":1.0,"hash":"sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}}"#.to_vec();
    let root = matching_root(&bytes);
    let err = validate_content_index(&bytes, &root)
        .expect_err("float seq MUST be rejected per §04 integer grammar");
    assert_eq!(err.code, DiagnosticCode::EContentIndexInvalid);
}

#[test]
fn exponent_seq_rejected_by_integer_grammar() {
    // §04: no exponents. `1e0` is rejected even though it equals 1.
    let bytes = br#"{"entries":{"/x":{"seq":1e0,"hash":"sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}}"#.to_vec();
    let root = matching_root(&bytes);
    let err = validate_content_index(&bytes, &root)
        .expect_err("exponent seq MUST be rejected per §04 integer grammar");
    assert_eq!(err.code, DiagnosticCode::EContentIndexInvalid);
}

#[test]
fn leading_zero_seq_rejected_by_integer_grammar() {
    // §04: no leading zeros on multi-digit integers.
    let bytes = br#"{"entries":{"/x":{"seq":01,"hash":"sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}}"#.to_vec();
    let root = matching_root(&bytes);
    let err = validate_content_index(&bytes, &root)
        .expect_err("leading-zero seq MUST be rejected per §04 integer grammar");
    assert_eq!(err.code, DiagnosticCode::EContentIndexInvalid);
}

#[test]
fn bom_rejected() {
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(br#"{"entries":{}}"#);
    let root = matching_root(&bytes);
    let err = validate_content_index(&bytes, &root).expect_err("BOM MUST be rejected");
    assert_eq!(err.code, DiagnosticCode::EContentIndexInvalid);
}

#[test]
fn invalid_utf8_rejected() {
    let bytes = vec![b'{', 0xFF, 0xFE, b'}'];
    let root = matching_root(&bytes);
    let err = validate_content_index(&bytes, &root).expect_err("invalid UTF-8 MUST be rejected");
    assert_eq!(err.code, DiagnosticCode::EContentIndexInvalid);
}

#[test]
fn hash_mismatch_rejected_before_parse() {
    // A content_root that does NOT match the bytes' SHA-256 surfaces
    // E_CONTENT_INDEX_HASH_MISMATCH; the bytes themselves can be
    // structurally valid — the hash check fires first.
    let bytes = br#"{"entries":{}}"#.to_vec();
    let wrong = ContentRoot::from_bytes([0u8; 32]);
    let err = validate_content_index(&bytes, &wrong).expect_err("hash mismatch MUST be rejected");
    assert_eq!(err.code, DiagnosticCode::EContentIndexHashMismatch);
}

#[test]
fn size_cap_rejected_before_hash() {
    // 1 MiB + 1 byte body. The size cap fires before hash so the bogus
    // root never needs to match.
    let bytes = vec![b' '; 1024 * 1024 + 1];
    let any = ContentRoot::from_bytes([0u8; 32]);
    let err = validate_content_index(&bytes, &any).expect_err("oversize body MUST be rejected");
    assert_eq!(err.code, DiagnosticCode::EContentIndexInvalid);
}

#[test]
fn unknown_top_level_field_rejected() {
    // Closed schema: only `entries` is permitted.
    let bytes = br#"{"entries":{},"extra":1}"#.to_vec();
    let root = matching_root(&bytes);
    let err = validate_content_index(&bytes, &root).expect_err("unknown field MUST be rejected");
    assert_eq!(err.code, DiagnosticCode::EContentIndexInvalid);
}

#[test]
fn unknown_entry_field_rejected() {
    // Closed schema on each entry: only {seq, hash}.
    let bytes = br#"{"entries":{"/x":{"seq":1,"hash":"sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","extra":true}}}"#.to_vec();
    let root = matching_root(&bytes);
    let err =
        validate_content_index(&bytes, &root).expect_err("unknown entry field MUST be rejected");
    assert_eq!(err.code, DiagnosticCode::EContentIndexInvalid);
}

#[test]
fn reserved_path_rejected() {
    // /manifest.json is reserved as a content path.
    let bytes = br#"{"entries":{"/manifest.json":{"seq":1,"hash":"sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}}"#.to_vec();
    let root = matching_root(&bytes);
    let err = validate_content_index(&bytes, &root).expect_err("reserved path MUST be rejected");
    assert_eq!(err.code, DiagnosticCode::EContentIndexInvalid);
}
