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

#[test]
fn duplicate_object_key_rejected() {
    // serde_json silently overwrites duplicates by default; the custom
    // visitor in `parse_with_limits` must reject them so a hostile producer
    // cannot smuggle a payload past the surviving key. §04 / §11 require
    // the dedicated `E_PARSE_DUPLICATE_KEY` code with structured details
    // identifying the duplicate member name and the containing object.
    let s = r#"{"a": 1, "a": 2}"#;
    let err = parse_with_limits(s).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::EParseDuplicateKey);
    let details = err.details.as_ref().expect("details payload");
    assert_eq!(details["duplicate_key"].as_str(), Some("a"));
    assert_eq!(details["object_path"].as_str(), Some("/"));
}

#[test]
fn duplicate_object_key_nested_rejected() {
    let s = r#"{"outer": {"a": 1, "a": 2}}"#;
    let err = parse_with_limits(s).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::EParseDuplicateKey);
    let details = err.details.as_ref().expect("details payload");
    assert_eq!(details["duplicate_key"].as_str(), Some("a"));
    assert_eq!(details["object_path"].as_str(), Some("/outer"));
}

// -- §04 integer grammar (v1.0-rc.5) -----------------------------------------

#[test]
fn negative_zero_token_rejected() {
    // §04 v1.0-rc.5: `-0` is not in the grammar `"0" / non-zero-digit *digit`
    // and conflates with positive zero in many JSON readers. Reject lexically.
    let err = parse_with_limits(r#"{"v": -0}"#).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaFieldRange);
}

#[test]
fn negative_integer_token_rejected() {
    // No Entangled wire-format field accepts negative integers; the grammar
    // pins the value range to [0, 2^63 - 1].
    let err = parse_with_limits(r#"{"v": -42}"#).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaFieldRange);
}

#[test]
fn integer_above_i64_max_rejected() {
    // 2^63 fits in u64 but exceeds the protocol range [0, 2^63 - 1].
    let err = parse_with_limits(r#"{"v": 9223372036854775808}"#).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaFieldRange);
}

#[test]
fn integer_at_i64_max_accepted() {
    // 2^63 - 1 is the inclusive upper bound.
    parse_with_limits(r#"{"v": 9223372036854775807}"#).expect("i64::MAX must be accepted");
}

#[test]
fn large_integer_above_2_to_53_accepted_without_precision_loss() {
    // 2^53 + 1 is the smallest integer that loses precision when parsed
    // through IEEE 754 binary64. Conforming parsers must keep it exact.
    parse_with_limits(r#"{"v": 9007199254740993}"#)
        .expect("2^53 + 1 must round-trip without precision loss");
}

#[test]
fn float_token_rejected_lexically() {
    // §04 v1.0-rc.5: tokens like `1.0` or `1e0` aren't integers. The
    // parse-time pre-pass rejects them with E_SCHEMA_NON_INTEGER, even
    // before the schema-level f64 walk would.
    let err = parse_with_limits(r#"{"v": 1.0}"#).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaNonInteger);

    let err = parse_with_limits(r#"{"v": 1e0}"#).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaNonInteger);
}

#[test]
fn negative_lookalike_inside_string_value_accepted() {
    // The lexical scan must skip JSON string contents — a `-0` inside a
    // string value is just text, not a numeric token.
    parse_with_limits(r#"{"v": "-0"}"#).expect("strings are not numeric tokens");
}

#[test]
fn lone_leading_surrogate_classified_as_malformed_unicode() {
    // §11: `E_SCHEMA_MALFORMED_UNICODE` covers isolated surrogates and
    // malformed `\uXXXX` escape sequences. serde_json reports these as
    // syntax errors; the parse layer reclassifies them to the spec code.
    let s = r#"{"v": "\uD800"}"#;
    let err = parse_with_limits(s).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaMalformedUnicode);
}
