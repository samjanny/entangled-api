//! Stage 4 — document kind discrimination. §02, §10.

use serde_json::Value;

use super::diagnostic::{Diagnostic, DiagnosticCode, DocumentKindLabel};

/// Pipeline-internal document kind (distinct from `DocumentKindLabel` which
/// is the on-the-wire diagnostic field).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DocumentKind {
    /// `kind: "manifest"`.
    Manifest,
    /// `kind: "content"`.
    Content,
    /// `kind: "transaction"`.
    Transaction,
}

const SPEC_VERSION_LITERAL: &str = "1.0";

/// Validates the presence and primitive type of `spec_version`, `kind`, and
/// `sig`, then dispatches to a `DocumentKind`. §02 lists exactly these three
/// fields as the discriminator inputs.
pub fn discriminate_kind(value: &Value) -> Result<DocumentKind, Diagnostic> {
    let map = match value {
        Value::Object(m) => m,
        _ => {
            return Err(Diagnostic::new(
                DiagnosticCode::EKindMissingFields,
                DocumentKindLabel::None,
                "document is not a JSON object",
            ));
        }
    };

    let spec_version = match map.get("spec_version") {
        Some(Value::String(s)) => s.as_str(),
        Some(_) => {
            return Err(Diagnostic::new(
                DiagnosticCode::EKindMissingFields,
                DocumentKindLabel::None,
                "spec_version must be a string",
            ));
        }
        None => {
            return Err(Diagnostic::new(
                DiagnosticCode::EKindMissingFields,
                DocumentKindLabel::None,
                "spec_version is missing",
            ));
        }
    };

    let kind = match map.get("kind") {
        Some(Value::String(s)) => s.as_str(),
        Some(_) => {
            return Err(Diagnostic::new(
                DiagnosticCode::EKindMissingFields,
                DocumentKindLabel::None,
                "kind must be a string",
            ));
        }
        None => {
            return Err(Diagnostic::new(
                DiagnosticCode::EKindMissingFields,
                DocumentKindLabel::None,
                "kind is missing",
            ));
        }
    };

    match map.get("sig") {
        Some(Value::String(_)) => {}
        Some(_) => {
            return Err(Diagnostic::new(
                DiagnosticCode::EKindMissingFields,
                DocumentKindLabel::None,
                "sig must be a string",
            ));
        }
        None => {
            return Err(Diagnostic::new(
                DiagnosticCode::EKindMissingFields,
                DocumentKindLabel::None,
                "sig is missing",
            ));
        }
    }

    if spec_version != SPEC_VERSION_LITERAL {
        return Err(Diagnostic::new(
            DiagnosticCode::EKindSpecVersion,
            DocumentKindLabel::None,
            format!("spec_version must be exactly \"1.0\", got {spec_version:?}"),
        ));
    }

    match kind {
        "manifest" => Ok(DocumentKind::Manifest),
        "content" => Ok(DocumentKind::Content),
        "transaction" => Ok(DocumentKind::Transaction),
        other => Err(Diagnostic::new(
            DiagnosticCode::EKindUnknown,
            DocumentKindLabel::None,
            format!("kind must be one of manifest|content|transaction, got {other:?}"),
        )),
    }
}
