//! Stage 2 — input checks (byte cap, BOM, strict UTF-8). §10.

use super::diagnostic::{Diagnostic, DiagnosticCode, DocumentKindLabel};
use super::limits::{
    CONTENT_DOC_MAX_BYTES, MANIFEST_MAX_BYTES, SUBMIT_BODY_MAX_BYTES, TRANSACTION_DOC_MAX_BYTES,
};

const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputKind {
    Manifest,
    ContentDocument,
    TransactionDocument,
    SubmitBody,
}

impl InputKind {
    fn byte_cap(self) -> usize {
        match self {
            InputKind::Manifest => MANIFEST_MAX_BYTES,
            InputKind::ContentDocument => CONTENT_DOC_MAX_BYTES,
            InputKind::TransactionDocument => TRANSACTION_DOC_MAX_BYTES,
            InputKind::SubmitBody => SUBMIT_BODY_MAX_BYTES,
        }
    }

    fn document_kind_label(self) -> DocumentKindLabel {
        match self {
            InputKind::Manifest => DocumentKindLabel::Manifest,
            InputKind::ContentDocument => DocumentKindLabel::Content,
            InputKind::TransactionDocument => DocumentKindLabel::Transaction,
            InputKind::SubmitBody => DocumentKindLabel::None,
        }
    }
}

/// Stage 2 input check. Order: byte cap → BOM → strict UTF-8. Fail-fast.
///
/// On success returns the validated `&str` over the input bytes, ready for
/// Stage 3.
pub fn check_input(bytes: &[u8], kind: InputKind) -> Result<&str, Diagnostic> {
    let kind_label = kind.document_kind_label();
    let cap = kind.byte_cap();
    if bytes.len() > cap {
        return Err(Diagnostic::new(
            DiagnosticCode::EInputByteCap,
            kind_label,
            format!("body of {} bytes exceeds cap of {} bytes", bytes.len(), cap),
        ));
    }
    if bytes.len() >= 3 && bytes[..3] == UTF8_BOM {
        return Err(Diagnostic::new(
            DiagnosticCode::EInputBom,
            kind_label,
            "body begins with a UTF-8 BOM",
        ));
    }
    match std::str::from_utf8(bytes) {
        Ok(s) => Ok(s),
        Err(_) => Err(Diagnostic::new(
            DiagnosticCode::EInputUtf8,
            kind_label,
            "body is not strict UTF-8",
        )),
    }
}
