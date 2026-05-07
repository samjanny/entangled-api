//! `null` is rejected at every nesting depth.

use entangled_core::canon::{canonicalize, CanonError};
use serde_json::{json, Value};

#[test]
fn top_level_null_is_rejected() {
    assert_eq!(
        canonicalize(&Value::Null),
        Err(CanonError::NullNotPermitted)
    );
}

#[test]
fn null_in_array_is_rejected() {
    assert_eq!(
        canonicalize(&json!([1, null, 2])),
        Err(CanonError::NullNotPermitted)
    );
}

#[test]
fn null_object_value_is_rejected() {
    assert_eq!(
        canonicalize(&json!({"a": null})),
        Err(CanonError::NullNotPermitted)
    );
}

#[test]
fn null_nested_in_object_is_rejected() {
    assert_eq!(
        canonicalize(&json!({"a": {"b": null}})),
        Err(CanonError::NullNotPermitted)
    );
}
