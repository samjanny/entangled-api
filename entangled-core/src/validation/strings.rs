//! String predicates used by Stage 5 validators.

use unicode_normalization::{is_nfc_quick, IsNormalized, UnicodeNormalization};

use crate::validation::diagnostic::{Diagnostic, DiagnosticCode, DocumentKindLabel};

/// Returns `false` if the string contains any control character in
/// U+0000..=U+001F or U+007F. When `allow_lf` is `true`, U+000A is permitted
/// (used by `code_block.content` and `canary.statement`).
pub fn no_control_chars(s: &str, allow_lf: bool) -> bool {
    for ch in s.chars() {
        let cp = ch as u32;
        let is_c0 = cp <= 0x1F;
        let is_del = cp == 0x7F;
        if is_c0 || is_del {
            if allow_lf && cp == 0x0A {
                continue;
            }
            return false;
        }
    }
    true
}

/// Returns `true` iff `s.len() <= max` (UTF-8 byte length).
pub fn check_byte_len(s: &str, max: usize) -> bool {
    s.len() <= max
}

/// §04 v1.0-rc.13 NFC requirement for user-visible strings.
///
/// Returns `Ok(())` if `s` is in Unicode Normalization Form C, otherwise
/// returns `E_SCHEMA_FIELD_SYNTAX` with structured `details` carrying
/// `field_path` and `reason: "non_nfc_string"`.
///
/// `is_nfc_quick` returns one of `Yes` (definitely NFC), `No` (definitely
/// not NFC), or `Maybe` (the cheap predicate is inconclusive). On `Maybe`
/// we fall back to the canonical comparison: a string is NFC iff it equals
/// its own NFC form. Implementations MUST NOT silently re-normalize: §04
/// is explicit that re-normalization would alter the JCS canonical bytes
/// and break the publisher's signature.
pub fn check_nfc(
    s: &str,
    field_path: &'static str,
    document_kind: DocumentKindLabel,
) -> Result<(), Diagnostic> {
    let is_nfc = match is_nfc_quick(s.chars()) {
        IsNormalized::Yes => true,
        IsNormalized::No => false,
        IsNormalized::Maybe => s.chars().eq(s.nfc()),
    };
    if is_nfc {
        return Ok(());
    }
    Err(Diagnostic::new(
        DiagnosticCode::ESchemaFieldSyntax,
        document_kind,
        format!("{field_path} is not in Unicode Normalization Form C (NFC)"),
    )
    .with_details(serde_json::json!({
        "field_path": field_path,
        "reason": "non_nfc_string",
    })))
}
