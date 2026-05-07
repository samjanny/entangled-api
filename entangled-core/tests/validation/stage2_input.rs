use entangled_core::validation::{check_input, DiagnosticCode, InputKind};

#[test]
fn manifest_64_kib_plus_one_rejected_with_byte_cap() {
    let bytes = vec![b'x'; 64 * 1024 + 1];
    let err = check_input(&bytes, InputKind::Manifest).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::EInputByteCap);
}

#[test]
fn content_doc_1_mib_plus_one_rejected_with_byte_cap() {
    let bytes = vec![b'x'; 1024 * 1024 + 1];
    let err = check_input(&bytes, InputKind::ContentDocument).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::EInputByteCap);
}

#[test]
fn body_with_initial_bom_rejected() {
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(b"{}");
    let err = check_input(&bytes, InputKind::ContentDocument).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::EInputBom);
}

#[test]
fn body_with_invalid_utf8_rejected() {
    let bytes: Vec<u8> = vec![b'{', 0xFF, b'}'];
    let err = check_input(&bytes, InputKind::ContentDocument).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::EInputUtf8);
}

#[test]
fn isolated_surrogate_escape_passes_stage2() {
    // The literal characters `\uD800` are valid ASCII bytes; Stage 2 only
    // validates byte-level UTF-8. The isolated surrogate is detected later
    // (serde_json rejects it at parse time).
    let body = b"{\"x\":\"\\uD800\"}";
    let s = check_input(body, InputKind::ContentDocument).expect("Stage 2 must accept");
    assert!(s.contains("\\uD800"));
}
