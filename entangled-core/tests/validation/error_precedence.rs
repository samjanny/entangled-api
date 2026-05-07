use entangled_core::validation::{
    parse_and_validate_content, parse_and_validate_manifest, DiagnosticCode,
};
use serde_json::json;

use crate::common::fixed_now;

#[test]
fn byte_cap_takes_precedence_over_json_parse_error() {
    // Body that is both oversized and malformed JSON. Stage 2 must fire
    // before Stage 3.
    let mut bytes = vec![b'x'; 1024 * 1024 + 1];
    bytes[0] = b'{'; // start of malformed JSON
    let err = parse_and_validate_content(&bytes).unwrap_err();
    assert_eq!(
        err.code,
        DiagnosticCode::EInputByteCap,
        "Stage 2 (input byte cap) must precede Stage 3 (JSON parse)"
    );
}

#[test]
fn kind_error_takes_precedence_over_schema_error() {
    // spec_version is wrong (Stage 4) AND a required field is missing
    // (would-be Stage 5). Stage 4 must fire first.
    let bad = json!({
        "spec_version": "1.1",
        "kind": "manifest",
        "sig": "x"
        // No publisher_pubkey, no origin, etc. — Stage 5 would also fail.
    });
    let err =
        parse_and_validate_manifest(&serde_json::to_vec(&bad).unwrap(), &fixed_now()).unwrap_err();
    assert_eq!(
        err.code,
        DiagnosticCode::EKindSpecVersion,
        "Stage 4 (kind) must precede Stage 5 (schema)"
    );
}
