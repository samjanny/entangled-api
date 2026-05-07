use entangled_core::validation::{discriminate_kind, DiagnosticCode};
use serde_json::json;

#[test]
fn missing_kind_field_rejected() {
    let v = json!({"spec_version": "1.0", "sig": "x"});
    let err = discriminate_kind(&v).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::EKindMissingFields);
}

#[test]
fn missing_spec_version_rejected() {
    let v = json!({"kind": "manifest", "sig": "x"});
    let err = discriminate_kind(&v).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::EKindMissingFields);
}

#[test]
fn missing_sig_rejected() {
    let v = json!({"spec_version": "1.0", "kind": "manifest"});
    let err = discriminate_kind(&v).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::EKindMissingFields);
}

#[test]
fn numeric_kind_field_rejected_as_missing_fields() {
    let v = json!({"spec_version": "1.0", "kind": 42, "sig": "x"});
    let err = discriminate_kind(&v).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::EKindMissingFields);
}

#[test]
fn spec_version_mismatch_rejected() {
    let v = json!({"spec_version": "1.1", "kind": "manifest", "sig": "x"});
    let err = discriminate_kind(&v).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::EKindSpecVersion);
}

#[test]
fn unknown_kind_rejected() {
    let v = json!({"spec_version": "1.0", "kind": "manifesto", "sig": "x"});
    let err = discriminate_kind(&v).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::EKindUnknown);
}
