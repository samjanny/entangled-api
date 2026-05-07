use entangled_core::validation::{parse_with_limits, DiagnosticCode};

#[test]
fn nesting_depth_17_rejected() {
    // 17 nested arrays — the innermost element is at depth 17.
    let mut s = String::new();
    for _ in 0..17 {
        s.push('[');
    }
    s.push('1');
    for _ in 0..17 {
        s.push(']');
    }
    let err = parse_with_limits(&s).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::EParseNestingDepth);
}

#[test]
fn nesting_depth_16_accepted() {
    // 16 nested arrays — innermost element at depth 16, allowed.
    let mut s = String::new();
    for _ in 0..16 {
        s.push('[');
    }
    s.push('1');
    for _ in 0..16 {
        s.push(']');
    }
    parse_with_limits(&s).expect("depth 16 must be accepted");
}

#[test]
fn array_with_10001_elements_rejected() {
    let mut s = String::from("[");
    for i in 0..10_001 {
        if i > 0 {
            s.push(',');
        }
        s.push('1');
    }
    s.push(']');
    let err = parse_with_limits(&s).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::EParseArrayLength);
}

#[test]
fn string_over_100_kib_rejected() {
    let big = "x".repeat(100 * 1024 + 1);
    let s = format!("{{\"v\":\"{big}\"}}");
    let err = parse_with_limits(&s).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::EParseStringLength);
}

#[test]
fn object_with_257_keys_rejected() {
    let mut s = String::from("{");
    for i in 0..257 {
        if i > 0 {
            s.push(',');
        }
        // Distinct keys k0..k256.
        s.push_str(&format!("\"k{i}\":1"));
    }
    s.push('}');
    let err = parse_with_limits(&s).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::EParseObjectKeys);
}

#[test]
fn malformed_json_unbalanced_brace_rejected() {
    let s = r#"{"a": 1"#;
    let err = parse_with_limits(s).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::EParseJson);
}
