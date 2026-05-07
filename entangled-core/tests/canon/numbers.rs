//! Integer serialization and rejection of non-integer numeric forms.

use entangled_core::canon::{canonicalize, CanonError};
use serde_json::{json, Value};

fn canon_str(v: &Value) -> String {
    String::from_utf8(canonicalize(v).unwrap()).unwrap()
}

#[test]
fn zero_serializes_as_zero() {
    assert_eq!(canon_str(&json!(0)), "0");
}

#[test]
fn small_positive_integer() {
    assert_eq!(canon_str(&json!(42)), "42");
}

#[test]
fn one_million() {
    assert_eq!(canon_str(&json!(1_000_000)), "1000000");
}

#[test]
fn u64_max_boundary() {
    let v: Value = serde_json::from_str("18446744073709551615").unwrap();
    assert_eq!(canon_str(&v), "18446744073709551615");
}

#[test]
fn float_value_is_rejected() {
    let v: Value = serde_json::from_str("42.5").unwrap();
    assert_eq!(canonicalize(&v), Err(CanonError::NonIntegerNumber));
}

#[test]
fn float_zero_is_rejected() {
    let v: Value = serde_json::from_str("0.0").unwrap();
    assert_eq!(canonicalize(&v), Err(CanonError::NonIntegerNumber));
}

#[test]
fn exponent_form_is_rejected() {
    // serde_json parses "1e5" as a float, so the canonicalizer must reject it
    // even though the mathematical value is integer.
    let v: Value = serde_json::from_str("1e5").unwrap();
    assert_eq!(canonicalize(&v), Err(CanonError::NonIntegerNumber));
}

#[test]
fn nested_float_in_array_is_rejected() {
    let v: Value = serde_json::from_str("[1, 2.5, 3]").unwrap();
    assert_eq!(canonicalize(&v), Err(CanonError::NonIntegerNumber));
}
