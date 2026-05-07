//! Structural cases: empty containers, nested mixes, whitespace elimination.

use entangled_core::canon::canonicalize;
use serde_json::{json, Value};

fn canon_str(v: &Value) -> String {
    String::from_utf8(canonicalize(v).unwrap()).unwrap()
}

#[test]
fn empty_object() {
    assert_eq!(canon_str(&json!({})), "{}");
}

#[test]
fn empty_array() {
    assert_eq!(canon_str(&json!([])), "[]");
}

#[test]
fn nested_mix_preserves_array_order_and_sorts_object_keys() {
    let v = json!({"a": [1, {"b": 2}], "c": []});
    assert_eq!(canon_str(&v), r#"{"a":[1,{"b":2}],"c":[]}"#);
}

#[test]
fn whitespace_in_input_is_eliminated_in_output() {
    let raw = "{\n  \"a\" : 1 ,\n  \"b\" : [ 2 , 3 ]\n}";
    let v: Value = serde_json::from_str(raw).unwrap();
    assert_eq!(canon_str(&v), r#"{"a":1,"b":[2,3]}"#);
}

#[test]
fn array_of_two_objects_each_individually_sorted() {
    let v = json!([{"b": 1, "a": 2}, {"d": 3, "c": 4}]);
    assert_eq!(canon_str(&v), r#"[{"a":2,"b":1},{"c":4,"d":3}]"#);
}
