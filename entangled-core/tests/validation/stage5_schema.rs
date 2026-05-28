use entangled_core::validation::{
    parse_and_validate_content, parse_and_validate_manifest, parse_and_validate_transaction,
    DiagnosticCode,
};
use serde_json::{json, Value};

use crate::common::{
    fixed_now, minimal_canary, minimal_content_doc, minimal_manifest, REQUEST_ID_ZEROS,
    SHA256_PREFIXED_ZEROS, SIG_ZEROS,
};

fn manifest_value() -> Value {
    let mut v = serde_json::to_value(minimal_manifest()).unwrap();
    v.as_object_mut()
        .unwrap()
        .insert("kind".to_owned(), json!("manifest"));
    v
}

fn content_value() -> Value {
    let mut v = serde_json::to_value(minimal_content_doc()).unwrap();
    v.as_object_mut()
        .unwrap()
        .insert("kind".to_owned(), json!("content"));
    v
}

fn manifest_bytes(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}

#[test]
fn t01_content_doc_with_extra_top_field_rejected() {
    let mut v = content_value();
    v.as_object_mut()
        .unwrap()
        .insert("extra_top_field".to_owned(), json!("evil"));
    let err = parse_and_validate_content(&manifest_bytes(&v)).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaUnknownField);
}

#[test]
fn t02_manifest_without_canary_rejected() {
    let mut v = manifest_value();
    v.as_object_mut().unwrap().remove("canary");
    let err = parse_and_validate_manifest(&manifest_bytes(&v), &fixed_now()).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaRequiredField);
}

#[test]
fn t03_heading_level_7_rejected_with_field_range() {
    let mut v = content_value();
    let blocks = v.as_object_mut().unwrap().get_mut("blocks").unwrap();
    *blocks = json!([
        {
            "kind": "heading",
            "level": 7,
            "content": [
                { "kind": "text", "value": "x", "marks": [] }
            ]
        }
    ]);
    let err = parse_and_validate_content(&manifest_bytes(&v)).unwrap_err();
    assert_eq!(
        err.code,
        DiagnosticCode::ESchemaFieldRange,
        "expected E_SCHEMA_FIELD_RANGE, got {:?}: {}",
        err.code,
        err.message
    );
}

#[test]
fn t04_min_refresh_interval_100_rejected_with_field_range() {
    let mut v = manifest_value();
    v.as_object_mut()
        .unwrap()
        .insert("min_refresh_interval".to_owned(), json!(100));
    let err = parse_and_validate_manifest(&manifest_bytes(&v), &fixed_now()).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaFieldRange);
}

#[test]
fn t05_state_policy_duplicate_namespace_key_rejected() {
    let mut v = manifest_value();
    let entry = json!({
        "namespace": "session",
        "key": "auth",
        "mode": "request",
        "max_size": 512,
        "max_lifetime": 86_400,
        "purpose": "Auth."
    });
    v.as_object_mut()
        .unwrap()
        .insert("state_policy".to_owned(), json!([entry, entry]));
    let err = parse_and_validate_manifest(&manifest_bytes(&v), &fixed_now()).unwrap_err();
    // §11 (rc.10): within-array uniqueness violations report
    // E_SCHEMA_DUPLICATE_ENTRY, not E_SCHEMA_FIELD_SYNTAX.
    assert_eq!(err.code, DiagnosticCode::ESchemaDuplicateEntry);
    let details = err.details.as_ref().expect("details payload");
    assert_eq!(details["field_path"].as_str(), Some("state_policy"));
    assert_eq!(details["duplicate_namespace"].as_str(), Some("session"));
    assert_eq!(details["duplicate_key"].as_str(), Some("auth"));
}

#[test]
fn t06_form_with_duplicate_field_name_rejected() {
    let mut v = content_value();
    let blocks = v.as_object_mut().unwrap().get_mut("blocks").unwrap();
    *blocks = json!([
        {
            "kind": "submit_form",
            "label": [{ "kind": "text", "value": "lbl", "marks": [] }],
            "submit_to": "/submit",
            "fields": [
                { "kind": "text", "name": "x", "label": "A", "required": true, "max_length": 10 },
                { "kind": "text", "name": "x", "label": "B", "required": false, "max_length": 10 }
            ],
            "submit_label": "Send"
        }
    ]);
    let err = parse_and_validate_content(&manifest_bytes(&v)).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaDuplicateEntry);
}

#[test]
fn t07_select_with_duplicate_option_value_rejected() {
    let mut v = content_value();
    let blocks = v.as_object_mut().unwrap().get_mut("blocks").unwrap();
    *blocks = json!([
        {
            "kind": "submit_form",
            "label": [{ "kind": "text", "value": "lbl", "marks": [] }],
            "submit_to": "/submit",
            "fields": [
                {
                    "kind": "select",
                    "name": "category",
                    "label": "Cat",
                    "required": true,
                    "options": [
                        { "value": "a", "label": "A" },
                        { "value": "a", "label": "Aprime" }
                    ]
                }
            ],
            "submit_label": "Send"
        }
    ]);
    let err = parse_and_validate_content(&manifest_bytes(&v)).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaDuplicateEntry);
}

#[test]
fn t08_inline_marks_with_duplicate_bold_rejected() {
    let mut v = content_value();
    let blocks = v.as_object_mut().unwrap().get_mut("blocks").unwrap();
    *blocks = json!([
        {
            "kind": "paragraph",
            "content": [
                { "kind": "text", "value": "x", "marks": ["bold", "bold"] }
            ]
        }
    ]);
    let err = parse_and_validate_content(&manifest_bytes(&v)).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaDuplicateEntry);
}

#[test]
fn t09_inline_value_with_line_feed_rejected() {
    let mut v = content_value();
    let blocks = v.as_object_mut().unwrap().get_mut("blocks").unwrap();
    *blocks = json!([
        {
            "kind": "paragraph",
            "content": [
                { "kind": "text", "value": "a\nb", "marks": [] }
            ]
        }
    ]);
    let err = parse_and_validate_content(&manifest_bytes(&v)).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaFieldSyntax);
}

#[test]
fn t10_code_block_content_with_line_feed_accepted() {
    let mut v = content_value();
    let blocks = v.as_object_mut().unwrap().get_mut("blocks").unwrap();
    *blocks = json!([
        {
            "kind": "code_block",
            "language": "rust",
            "content": "fn main() {\n    println!(\"hi\");\n}"
        }
    ]);
    parse_and_validate_content(&manifest_bytes(&v))
        .expect("LF in code_block content must be accepted");
}

#[test]
fn t11_code_block_content_with_tab_rejected() {
    let mut v = content_value();
    let blocks = v.as_object_mut().unwrap().get_mut("blocks").unwrap();
    *blocks = json!([
        {
            "kind": "code_block",
            "language": "rust",
            "content": "fn main() {\tprintln!(\"hi\");}"
        }
    ]);
    let err = parse_and_validate_content(&manifest_bytes(&v)).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaFieldSyntax);
}

#[test]
fn t12_canary_statement_with_line_feed_accepted() {
    let mut canary = serde_json::to_value(minimal_canary()).unwrap();
    canary
        .as_object_mut()
        .unwrap()
        .insert("statement".to_owned(), json!("Line one.\nLine two."));
    let mut v = manifest_value();
    v.as_object_mut()
        .unwrap()
        .insert("canary".to_owned(), canary);
    parse_and_validate_manifest(&manifest_bytes(&v), &fixed_now())
        .expect("LF in canary.statement must be accepted");
}

#[test]
fn t13_state_policy_purpose_with_line_feed_rejected() {
    let mut v = manifest_value();
    v.as_object_mut().unwrap().insert(
        "state_policy".to_owned(),
        json!([{
            "namespace": "n",
            "key": "k",
            "mode": "client_only",
            "max_size": 100,
            "max_lifetime": 600,
            "purpose": "line one\nline two"
        }]),
    );
    let err = parse_and_validate_manifest(&manifest_bytes(&v), &fixed_now()).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaFieldSyntax);
}

#[test]
fn t14_navigation_label_101_bytes_rejected() {
    let label = "x".repeat(101);
    let mut v = manifest_value();
    v.as_object_mut().unwrap().insert(
        "navigation".to_owned(),
        json!([{ "label": label, "path": "/" }]),
    );
    let err = parse_and_validate_manifest(&manifest_bytes(&v), &fixed_now()).unwrap_err();
    assert_eq!(
        err.code,
        DiagnosticCode::ESchemaFieldLength,
        "navigation 101-byte label must trigger E_SCHEMA_FIELD_LENGTH"
    );
}

#[test]
fn t15_navigation_label_200_bytes_rejected_too() {
    // The cap is 100, not 200 — this test catches an implementation that
    // accidentally used the generic 200 cap.
    let label = "x".repeat(200);
    let mut v = manifest_value();
    v.as_object_mut().unwrap().insert(
        "navigation".to_owned(),
        json!([{ "label": label, "path": "/" }]),
    );
    let err = parse_and_validate_manifest(&manifest_bytes(&v), &fixed_now()).unwrap_err();
    assert_eq!(
        err.code,
        DiagnosticCode::ESchemaFieldLength,
        "200-byte navigation label must be rejected (cap is 100, not 200)"
    );
}

#[test]
fn t16_transaction_with_submit_form_block_rejected() {
    let v = json!({
        "spec_version": "1.0",
        "kind": "transaction",
        "in_response_to": "/contact",
        "request_id": REQUEST_ID_ZEROS,
        "request_hash": SHA256_PREFIXED_ZEROS,
        "state_updates": [],
        "blocks": [
            {
                "kind": "submit_form",
                "label": [{ "kind": "text", "value": "lbl", "marks": [] }],
                "submit_to": "/contact",
                "fields": [
                    { "kind": "text", "name": "x", "label": "A", "required": true, "max_length": 10 }
                ],
                "submit_label": "Send"
            }
        ],
        "sig": SIG_ZEROS
    });
    let err = parse_and_validate_transaction(&serde_json::to_vec(&v).unwrap()).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaBlockNotPermitted);
}

#[test]
fn t17_null_anywhere_rejected_with_null_value() {
    let mut v = content_value();
    // Inject null on an optional field.
    let blocks = v.as_object_mut().unwrap().get_mut("blocks").unwrap();
    *blocks = json!([
        {
            "kind": "image",
            "src": "/a.png",
            "sha256": SHA256_PREFIXED_ZEROS,
            "media_type": "image/png",
            "width": 800,
            "height": 600,
            "alt": "diagram",
            "caption": null
        }
    ]);
    let err = parse_and_validate_content(&manifest_bytes(&v)).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaNullValue);
}

#[test]
fn t18_non_integer_number_rejected() {
    let mut v = manifest_value();
    v.as_object_mut()
        .unwrap()
        .insert("min_refresh_interval".to_owned(), json!(42.5));
    let err = parse_and_validate_manifest(&manifest_bytes(&v), &fixed_now()).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaNonInteger);
}

#[test]
fn t19_list_with_65_items_rejected() {
    let mut items = Vec::with_capacity(65);
    for _ in 0..65 {
        items.push(json!([{ "kind": "text", "value": "x", "marks": [] }]));
    }
    let mut v = content_value();
    let blocks = v.as_object_mut().unwrap().get_mut("blocks").unwrap();
    *blocks = json!([{ "kind": "list", "ordered": false, "items": items }]);
    let err = parse_and_validate_content(&manifest_bytes(&v)).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaFieldLength);
}

#[test]
fn t20a_citation_url_with_http_scheme_rejected() {
    // §03 / Tranche 2 fix #5: clearnet citations are restricted to https://;
    // plain http:// is not permitted in v1.
    let mut v = content_value();
    let blocks = v.as_object_mut().unwrap().get_mut("blocks").unwrap();
    *blocks = json!([
        {
            "kind": "link",
            "label": [{ "kind": "text", "value": "src", "marks": [] }],
            "target": { "kind": "citation", "url": "http://example.org/x" }
        }
    ]);
    let err = parse_and_validate_content(&manifest_bytes(&v)).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaFieldSyntax);
}

#[test]
fn t20_citation_url_with_ftp_scheme_rejected() {
    let mut v = content_value();
    let blocks = v.as_object_mut().unwrap().get_mut("blocks").unwrap();
    *blocks = json!([
        {
            "kind": "link",
            "label": [{ "kind": "text", "value": "src", "marks": [] }],
            "target": { "kind": "citation", "url": "ftp://x" }
        }
    ]);
    let err = parse_and_validate_content(&manifest_bytes(&v)).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaFieldSyntax);
}

// -- §03 carrier link target -------------------------------------------------

const CARRIER_ONION: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";

#[test]
fn t27_carrier_link_with_valid_onion_url_accepted() {
    // §03: kind:"carrier" routes a non-Entangled service (e.g. a foreign
    // onion site) over an already-supported carrier. Plain http:// over
    // a 62-char onion host is the canonical valid form.
    let mut v = content_value();
    let blocks = v.as_object_mut().unwrap().get_mut("blocks").unwrap();
    *blocks = json!([
        {
            "kind": "link",
            "label": [{ "kind": "text", "value": "src", "marks": [] }],
            "target": {
                "kind": "carrier",
                "carrier": "tor-v3",
                "url": format!("http://{CARRIER_ONION}/wiki")
            }
        }
    ]);
    parse_and_validate_content(&manifest_bytes(&v))
        .expect("valid carrier link target must pass Stage 5");
}

#[test]
fn t27a_carrier_link_with_https_scheme_rejected() {
    // §03: carrier links are http-only. The carrier (Tor v3 here) provides
    // the rendezvous-layer crypto; a TLS layer on top is unnecessary and
    // currently disallowed for v1 conformance.
    let mut v = content_value();
    let blocks = v.as_object_mut().unwrap().get_mut("blocks").unwrap();
    *blocks = json!([
        {
            "kind": "link",
            "label": [{ "kind": "text", "value": "src", "marks": [] }],
            "target": {
                "kind": "carrier",
                "carrier": "tor-v3",
                "url": format!("https://{CARRIER_ONION}/wiki")
            }
        }
    ]);
    let err = parse_and_validate_content(&manifest_bytes(&v)).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaFieldSyntax);
}

#[test]
fn t27b_carrier_link_with_clearnet_host_rejected() {
    // §03: a tor-v3 carrier link MUST point at a 62-char onion host.
    // A clearnet host fails the host-validation step.
    let mut v = content_value();
    let blocks = v.as_object_mut().unwrap().get_mut("blocks").unwrap();
    *blocks = json!([
        {
            "kind": "link",
            "label": [{ "kind": "text", "value": "src", "marks": [] }],
            "target": {
                "kind": "carrier",
                "carrier": "tor-v3",
                "url": "http://example.org/x"
            }
        }
    ]);
    let err = parse_and_validate_content(&manifest_bytes(&v)).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaFieldSyntax);
}

#[test]
fn t27c_carrier_link_with_unknown_carrier_rejected() {
    // The Carrier enum is closed (only "tor-v3" in v1); an unknown carrier
    // value is rejected at deserialize time.
    let mut v = content_value();
    let blocks = v.as_object_mut().unwrap().get_mut("blocks").unwrap();
    *blocks = json!([
        {
            "kind": "link",
            "label": [{ "kind": "text", "value": "src", "marks": [] }],
            "target": {
                "kind": "carrier",
                "carrier": "i2p",
                "url": format!("http://{CARRIER_ONION}/x")
            }
        }
    ]);
    parse_and_validate_content(&manifest_bytes(&v)).expect_err("unknown carrier must reject");
}

#[test]
fn t27d_carrier_link_with_expected_publisher_pubkey_field_rejected() {
    // §03: the carrier kind is for non-Entangled destinations and does
    // NOT carry expected_publisher_pubkey. deny_unknown_fields catches a
    // stray Entangled-style key on the carrier target.
    let mut v = content_value();
    let blocks = v.as_object_mut().unwrap().get_mut("blocks").unwrap();
    *blocks = json!([
        {
            "kind": "link",
            "label": [{ "kind": "text", "value": "src", "marks": [] }],
            "target": {
                "kind": "carrier",
                "carrier": "tor-v3",
                "url": format!("http://{CARRIER_ONION}/x"),
                "expected_publisher_pubkey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            }
        }
    ]);
    let err = parse_and_validate_content(&manifest_bytes(&v)).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaUnknownField);
}

#[test]
fn t27e_carrier_link_url_with_control_char_rejected() {
    let mut v = content_value();
    let blocks = v.as_object_mut().unwrap().get_mut("blocks").unwrap();
    *blocks = json!([
        {
            "kind": "link",
            "label": [{ "kind": "text", "value": "src", "marks": [] }],
            "target": {
                "kind": "carrier",
                "carrier": "tor-v3",
                "url": format!("http://{CARRIER_ONION}/path\u{0001}with-ctrl")
            }
        }
    ]);
    let err = parse_and_validate_content(&manifest_bytes(&v)).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaFieldSyntax);
}

#[test]
fn t22_content_with_empty_blocks_array_rejected() {
    // §02: content `blocks` MUST contain at least one block.
    let mut v = content_value();
    let blocks = v.as_object_mut().unwrap().get_mut("blocks").unwrap();
    *blocks = json!([]);
    let err = parse_and_validate_content(&manifest_bytes(&v)).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaRequiredField);
}

#[test]
fn t22a_image_alt_empty_string_accepted() {
    // §03 (rc.10): `alt` MAY be the empty string for purely decorative
    // images, in contrast to `caption` where the empty string is forbidden.
    // Pinning the asymmetry against an over-eager future refactor that
    // would add `is_empty()` and break conformance.
    let mut v = content_value();
    let blocks = v.as_object_mut().unwrap().get_mut("blocks").unwrap();
    *blocks = json!([
        {
            "kind": "image",
            "src": "/a.png",
            "sha256": SHA256_PREFIXED_ZEROS,
            "media_type": "image/png",
            "width": 800,
            "height": 600,
            "alt": ""
        }
    ]);
    parse_and_validate_content(&manifest_bytes(&v))
        .expect("decorative image with empty alt must validate");
}

#[test]
fn t23_image_caption_empty_string_rejected() {
    // §03: when `caption` is present it MUST NOT be an empty string.
    let mut v = content_value();
    let blocks = v.as_object_mut().unwrap().get_mut("blocks").unwrap();
    *blocks = json!([
        {
            "kind": "image",
            "src": "/a.png",
            "sha256": SHA256_PREFIXED_ZEROS,
            "media_type": "image/png",
            "width": 800,
            "height": 600,
            "alt": "diagram",
            "caption": ""
        }
    ]);
    let err = parse_and_validate_content(&manifest_bytes(&v)).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaFieldSyntax);
}

#[test]
fn t24_note_title_empty_string_rejected() {
    // §03: when `title` is present on a note block it MUST NOT be empty.
    let mut v = content_value();
    let blocks = v.as_object_mut().unwrap().get_mut("blocks").unwrap();
    *blocks = json!([
        {
            "kind": "note",
            "variant": "info",
            "title": "",
            "content": [{ "kind": "text", "value": "body", "marks": [] }]
        }
    ]);
    let err = parse_and_validate_content(&manifest_bytes(&v)).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaFieldSyntax);
}

#[test]
fn t25_canary_freshness_proof_empty_string_rejected() {
    // §08: when `freshness_proof` is present it MUST NOT be empty.
    let mut v = manifest_value();
    let canary = v.as_object_mut().unwrap().get_mut("canary").unwrap();
    canary
        .as_object_mut()
        .unwrap()
        .insert("freshness_proof".to_owned(), json!(""));
    let err = parse_and_validate_manifest(&manifest_bytes(&v), &fixed_now()).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaFieldSyntax);
}

#[test]
fn t26_citation_url_with_brace_rejected_as_field_syntax() {
    // §03 / RFC 3986: braces are not in the unreserved/reserved URI set.
    let mut v = content_value();
    let blocks = v.as_object_mut().unwrap().get_mut("blocks").unwrap();
    *blocks = json!([
        {
            "kind": "link",
            "label": [{ "kind": "text", "value": "src", "marks": [] }],
            "target": { "kind": "citation", "url": "https://example.org/{template}" }
        }
    ]);
    let err = parse_and_validate_content(&manifest_bytes(&v)).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaFieldSyntax);
}

#[test]
fn t26a_citation_url_with_invalid_percent_triplet_rejected() {
    // §03 / RFC 3986: `%` MUST introduce a complete `%HH` triplet of HEXDIGs.
    for bad in [
        "https://example.org/%zz",
        "https://example.org/%2",
        "https://example.org/%",
    ] {
        let mut v = content_value();
        let blocks = v.as_object_mut().unwrap().get_mut("blocks").unwrap();
        *blocks = json!([
            {
                "kind": "link",
                "label": [{ "kind": "text", "value": "src", "marks": [] }],
                "target": { "kind": "citation", "url": bad }
            }
        ]);
        let err = parse_and_validate_content(&manifest_bytes(&v))
            .err()
            .unwrap_or_else(|| panic!("expected rejection for {bad}"));
        assert_eq!(err.code, DiagnosticCode::ESchemaFieldSyntax, "url={bad}");
    }
}

#[test]
fn t26b_citation_url_with_valid_percent_triplet_accepted() {
    // §03 / RFC 3986: well-formed `%HH` triplets are permitted.
    let mut v = content_value();
    let blocks = v.as_object_mut().unwrap().get_mut("blocks").unwrap();
    *blocks = json!([
        {
            "kind": "link",
            "label": [{ "kind": "text", "value": "src", "marks": [] }],
            "target": { "kind": "citation", "url": "https://example.org/a%20b/%2F%fF" }
        }
    ]);
    parse_and_validate_content(&manifest_bytes(&v)).expect("valid pct-encoded url accepted");
}

// -----------------------------------------------------------------------------
// §04 v1.0-rc.13 NFC normalization. User-visible strings MUST be in NFC.
// Non-NFC values rejected at schema time with E_SCHEMA_FIELD_SYNTAX +
// details.reason "non_nfc_string". Implementations MUST NOT silently
// re-normalize: re-normalization would alter the JCS canonical bytes and
// break the publisher's signature.
// -----------------------------------------------------------------------------

#[test]
fn nfc_canary_statement_in_nfd_rejected() {
    // "Café" in NFD: 'C' 'a' 'f' 'e' + U+0301 (combining acute accent).
    let nfd_statement = "Cafe\u{0301}";
    let mut v = manifest_value();
    let canary = v.as_object_mut().unwrap().get_mut("canary").unwrap();
    canary
        .as_object_mut()
        .unwrap()
        .insert("statement".to_owned(), json!(nfd_statement));
    let err = parse_and_validate_manifest(&manifest_bytes(&v), &fixed_now())
        .expect_err("NFD statement must reject");
    assert_eq!(err.code, DiagnosticCode::ESchemaFieldSyntax);
    let details = err.details.as_ref().expect("details payload");
    assert_eq!(details["field_path"].as_str(), Some("canary.statement"));
    assert_eq!(details["reason"].as_str(), Some("non_nfc_string"));
}

#[test]
fn nfc_meta_title_in_nfc_accepted() {
    // Precomposed "Café": all single codepoints, trivially NFC.
    let mut v = content_value();
    let meta = v.as_object_mut().unwrap().get_mut("meta").unwrap();
    meta.as_object_mut()
        .unwrap()
        .insert("title".to_owned(), json!("Caf\u{00E9}"));
    parse_and_validate_content(&manifest_bytes(&v)).expect("NFC title accepted");
}

#[test]
fn nfc_meta_title_in_nfd_rejected() {
    let mut v = content_value();
    let meta = v.as_object_mut().unwrap().get_mut("meta").unwrap();
    meta.as_object_mut()
        .unwrap()
        .insert("title".to_owned(), json!("Cafe\u{0301}"));
    let err =
        parse_and_validate_content(&manifest_bytes(&v)).expect_err("NFD meta.title must reject");
    assert_eq!(err.code, DiagnosticCode::ESchemaFieldSyntax);
    let details = err.details.as_ref().expect("details payload");
    assert_eq!(details["field_path"].as_str(), Some("meta.title"));
    assert_eq!(details["reason"].as_str(), Some("non_nfc_string"));
}

// -----------------------------------------------------------------------------
// §06 v1.0-rc.13 migration_pointer schema validation. Stage 5 rejects
// structurally invalid announcements with E_MIGRATION_INVALID before
// signature verification. The publisher-identity continuity check across
// announcing and successor manifests (E_MIGRATION_MISMATCH) is exercised
// separately in tests/validation/migration.rs.
// -----------------------------------------------------------------------------

fn manifest_value_with_migration_pointer(mp: serde_json::Value) -> Value {
    let mut v = manifest_value();
    v.as_object_mut()
        .unwrap()
        .insert("migration_pointer".to_owned(), mp);
    v
}

#[test]
fn migration_pointer_self_pointing_address_rejected() {
    // successor_origin.address equal to the announcing origin.address.
    let same_origin = json!({
        "carrier": "tor-v3",
        "address": "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion",
        "origin_pubkey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    });
    let mp = json!({
        "successor_origin": same_origin,
        "announced_at": "2026-05-07T00:00:00Z",
    });
    let v = manifest_value_with_migration_pointer(mp);
    let err = parse_and_validate_manifest(&manifest_bytes(&v), &fixed_now())
        .expect_err("self-pointing migration must reject");
    assert_eq!(err.code, DiagnosticCode::EMigrationInvalid);
    let details = err.details.as_ref().expect("details payload");
    // rc.19 N57: renamed from `self_pointing_migration` to `self_pointer`.
    assert_eq!(details["reason"].as_str(), Some("self_pointer"));
    assert!(details["announcing_origin_address"].is_string());
    assert!(details["successor_origin_address"].is_string());
}

#[test]
fn migration_pointer_announced_after_updated_rejected() {
    // announced_at strictly later than updated.
    let mp = json!({
        "successor_origin": {
            "carrier": "tor-v3",
            "address": "ssssssssssssssssssssssssssssssssssssssssssssssssssssssss.onion",
            "origin_pubkey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        },
        "announced_at": "2026-06-01T00:00:00Z",
    });
    let v = manifest_value_with_migration_pointer(mp);
    let err = parse_and_validate_manifest(&manifest_bytes(&v), &fixed_now())
        .expect_err("announced_at after updated must reject");
    assert_eq!(err.code, DiagnosticCode::EMigrationInvalid);
    let details = err.details.as_ref().expect("details payload");
    // rc.19 N57: renamed from `announced_after_updated` to match §11
    // vocabulary.
    assert_eq!(
        details["reason"].as_str(),
        Some("announced_at_after_updated")
    );
    assert!(details["announcing_origin_address"].is_string());
    assert!(details["successor_origin_address"].is_string());
}

#[test]
fn migration_pointer_omitted_field_accepted() {
    // The default fixture has no migration_pointer; verify it still validates.
    let v = manifest_value();
    parse_and_validate_manifest(&manifest_bytes(&v), &fixed_now())
        .expect("manifest without migration_pointer accepted");
}

#[test]
fn migration_pointer_null_rejected_by_prepass() {
    // §04 no-`null` discipline: absent is encoded by omission, never by null.
    // Without the schema-prepass null sweep, `Option<MigrationPointer>::deserialize`
    // would accept `null` as `None` and the subsequent round-trip
    // (`to_value(&manifest)` with `skip_serializing_if = "Option::is_none"`)
    // would omit the field, producing JCS bytes different from the wire input
    // — a signature-input asymmetry. The prepass closes this gap at Stage 5
    // before deserialization, so any future refactor that reorders the prepass
    // breaks this test rather than the signature invariant.
    let mut v = manifest_value();
    v.as_object_mut()
        .unwrap()
        .insert("migration_pointer".to_owned(), json!(null));
    let err = parse_and_validate_manifest(&manifest_bytes(&v), &fixed_now())
        .expect_err("null migration_pointer must reject under no-null discipline");
    assert_eq!(err.code, DiagnosticCode::ESchemaNullValue);
}

#[test]
fn migration_pointer_well_formed_accepted_at_schema_level() {
    let mp = json!({
        "successor_origin": {
            "carrier": "tor-v3",
            "address": "ssssssssssssssssssssssssssssssssssssssssssssssssssssssss.onion",
            "origin_pubkey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        },
        "announced_at": "2026-05-06T12:00:00Z",
    });
    let v = manifest_value_with_migration_pointer(mp);
    parse_and_validate_manifest(&manifest_bytes(&v), &fixed_now())
        .expect("well-formed migration_pointer must pass schema validation");
}

#[test]
fn migration_pointer_successor_origin_with_not_after_rejected() {
    // §06:373 (v1.0-rc.14): the successor_origin schema is fixed at three
    // fields; `not_after` belongs to the successor's own manifest, not to
    // the pointer announcing it. Reported as `E_SCHEMA_UNKNOWN_FIELD`
    // because the §11 N57 closed-enum `details.reason` vocabulary for
    // `E_MIGRATION_INVALID` does not cover this case (the four members
    // are self_pointer / announced_at_after_updated / carrier_mismatch /
    // chain_cycle); a stray field on the successor pointer is a
    // closed-schema violation, not a migration-semantic failure.
    let mp = json!({
        "successor_origin": {
            "carrier": "tor-v3",
            "address": "ssssssssssssssssssssssssssssssssssssssssssssssssssssssss.onion",
            "origin_pubkey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "not_after": "2027-05-07T00:00:00Z",
        },
        "announced_at": "2026-05-06T12:00:00Z",
    });
    let v = manifest_value_with_migration_pointer(mp);
    let err = parse_and_validate_manifest(&manifest_bytes(&v), &fixed_now())
        .expect_err("successor_origin.not_after must reject");
    assert_eq!(err.code, DiagnosticCode::ESchemaUnknownField);
    let details = err.details.as_ref().expect("details payload");
    assert_eq!(
        details["field_path"].as_str(),
        Some("migration_pointer.successor_origin.not_after")
    );
}

// -----------------------------------------------------------------------------
// §06 v1.0-rc.14 origin.not_after schema validation. Stage 5 enforces the
// two MUSTs from §06 (strictly after canary.issued_at; within a 5-year
// horizon) and reports them as E_ORIGIN_INVALID with details.reason in the
// §11 vocabulary. The Stage 9 expiry check (E_ORIGIN_EXPIRED) lives in
// tests/validation/origin_not_after.rs.
// -----------------------------------------------------------------------------

fn manifest_value_with_not_after(not_after: &str) -> Value {
    let mut v = manifest_value();
    let origin = v.as_object_mut().unwrap().get_mut("origin").unwrap();
    origin
        .as_object_mut()
        .unwrap()
        .insert("not_after".to_owned(), json!(not_after));
    v
}

#[test]
fn origin_not_after_omitted_accepted() {
    // The minimal manifest fixture does not declare not_after; rc.14 keeps
    // that path valid byte-for-byte.
    let v = manifest_value();
    parse_and_validate_manifest(&manifest_bytes(&v), &fixed_now())
        .expect("manifest without origin.not_after accepted");
}

#[test]
fn origin_not_after_well_formed_accepted() {
    // canary.issued_at = 2026-05-07T00:00:00Z; not_after one year later is
    // well within the 5-year horizon and strictly later than issued_at.
    let v = manifest_value_with_not_after("2027-05-07T00:00:00Z");
    parse_and_validate_manifest(&manifest_bytes(&v), &fixed_now())
        .expect("well-formed origin.not_after accepted");
}

#[test]
fn origin_not_after_at_or_before_issued_at_rejected() {
    // not_after == canary.issued_at violates the strict-later constraint.
    let v = manifest_value_with_not_after("2026-05-07T00:00:00Z");
    let err = parse_and_validate_manifest(&manifest_bytes(&v), &fixed_now())
        .expect_err("not_after at issued_at must reject");
    assert_eq!(err.code, DiagnosticCode::EOriginInvalid);
    let details = err.details.as_ref().expect("details payload");
    assert_eq!(details["field_path"].as_str(), Some("origin.not_after"));
    assert_eq!(
        details["reason"].as_str(),
        Some("not_after_not_later_than_issued_at")
    );

    // And the strictly-before case.
    let v = manifest_value_with_not_after("2026-05-06T23:59:59Z");
    let err = parse_and_validate_manifest(&manifest_bytes(&v), &fixed_now())
        .expect_err("not_after before issued_at must reject");
    assert_eq!(err.code, DiagnosticCode::EOriginInvalid);
    assert_eq!(
        err.details.as_ref().unwrap()["reason"].as_str(),
        Some("not_after_not_later_than_issued_at")
    );
}

#[test]
fn origin_not_after_beyond_5y_rejected() {
    // canary.issued_at = 2026-05-07T00:00:00Z; 5 * 365 * 86_400s = exactly
    // 2031-05-06T00:00:00Z. A `not_after` one day later breaches the
    // horizon.
    let v = manifest_value_with_not_after("2031-05-07T00:00:00Z");
    let err = parse_and_validate_manifest(&manifest_bytes(&v), &fixed_now())
        .expect_err("not_after beyond 5y horizon must reject");
    assert_eq!(err.code, DiagnosticCode::EOriginInvalid);
    let details = err.details.as_ref().expect("details payload");
    assert_eq!(details["reason"].as_str(), Some("not_after_beyond_5y"));
}

#[test]
fn origin_not_after_at_5y_boundary_accepted() {
    // The horizon is inclusive: exactly canary.issued_at + 5 * 365 * 86_400s
    // is permitted; only strictly greater is rejected.
    let v = manifest_value_with_not_after("2031-05-06T00:00:00Z");
    parse_and_validate_manifest(&manifest_bytes(&v), &fixed_now())
        .expect("not_after at exact 5y boundary accepted");
}

#[test]
fn origin_not_after_details_use_issued_at_key_per_spec() {
    // M-1 regression: Section 11 vocabulary for E_ORIGIN_INVALID details
    // uses `issued_at` (the declared `canary.issued_at` value), not
    // `canary_issued_at`. The implementation previously emitted the
    // latter; this test pins the canonical key for both reason variants.

    // not_after_not_later_than_issued_at branch.
    let v = manifest_value_with_not_after("2026-05-07T00:00:00Z");
    let err = parse_and_validate_manifest(&manifest_bytes(&v), &fixed_now())
        .expect_err("not_after at issued_at must reject");
    let details = err.details.as_ref().expect("details payload");
    assert_eq!(
        details["issued_at"].as_str(),
        Some("2026-05-07T00:00:00Z"),
        "Section 11 vocabulary requires key `issued_at`"
    );
    assert!(
        details.get("canary_issued_at").is_none(),
        "non-canonical `canary_issued_at` key must not be emitted"
    );

    // not_after_beyond_5y branch.
    let v = manifest_value_with_not_after("2031-05-07T00:00:00Z");
    let err = parse_and_validate_manifest(&manifest_bytes(&v), &fixed_now())
        .expect_err("not_after beyond 5y must reject");
    let details = err.details.as_ref().expect("details payload");
    assert_eq!(details["issued_at"].as_str(), Some("2026-05-07T00:00:00Z"));
    assert!(
        details.get("canary_issued_at").is_none(),
        "non-canonical `canary_issued_at` key must not be emitted"
    );
}

#[test]
fn origin_not_after_null_rejected_by_prepass() {
    // §04 no-`null` discipline: absent is encoded by omission, never by
    // null. The schema-prepass null sweep fires before serde reaches the
    // Option<EntangledTimestamp> field.
    let mut v = manifest_value();
    v.as_object_mut()
        .unwrap()
        .get_mut("origin")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("not_after".to_owned(), json!(null));
    let err = parse_and_validate_manifest(&manifest_bytes(&v), &fixed_now())
        .expect_err("null not_after must reject under no-null discipline");
    assert_eq!(err.code, DiagnosticCode::ESchemaNullValue);
}

#[test]
fn t21_inline_link_nested_inside_link_label_rejected() {
    let mut v = content_value();
    let blocks = v.as_object_mut().unwrap().get_mut("blocks").unwrap();
    *blocks = json!([
        {
            "kind": "link",
            "label": [
                {
                    "kind": "link",
                    "value": "inner",
                    "marks": [],
                    "target": { "kind": "same_site", "path": "/" }
                }
            ],
            "target": { "kind": "same_site", "path": "/" }
        }
    ]);
    let err = parse_and_validate_content(&manifest_bytes(&v)).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::ESchemaBlockNotPermitted);
}
