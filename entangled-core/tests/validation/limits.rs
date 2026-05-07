//! Documentation tests verifying that the public limit constants encode the
//! exact normative values from the spec.

use entangled_core::validation::limits::*;

#[test]
fn document_size_caps() {
    assert_eq!(CONTENT_DOC_MAX_BYTES, 1024 * 1024);
    assert_eq!(TRANSACTION_DOC_MAX_BYTES, 1024 * 1024);
    assert_eq!(MANIFEST_MAX_BYTES, 64 * 1024);
    assert_eq!(SUBMIT_BODY_MAX_BYTES, 64 * 1024);
}

#[test]
fn json_parser_limits() {
    assert_eq!(MAX_JSON_NESTING_DEPTH, 16);
    assert_eq!(MAX_JSON_STRING_BYTES, 100 * 1024);
    assert_eq!(MAX_JSON_ARRAY_ELEMENTS, 10_000);
    assert_eq!(MAX_JSON_OBJECT_KEYS, 256);
}

#[test]
fn block_array_caps() {
    assert_eq!(MAX_BLOCKS_CONTENT, 1024);
    assert_eq!(MAX_BLOCKS_TRANSACTION, 256);
    assert_eq!(MAX_IMAGE_BLOCKS_PER_DOC, 16);
    assert_eq!(MAX_IMAGE_RESPONSE_BYTES, 2 * 1024 * 1024);
}

#[test]
fn manifest_sub_array_caps() {
    assert_eq!(MAX_NAVIGATION_ENTRIES, 32);
    assert_eq!(MAX_STATE_POLICY_ENTRIES, 32);
    assert_eq!(MAX_STATE_UPDATES, 32);
}

#[test]
fn string_byte_caps() {
    assert_eq!(META_TITLE_MAX_BYTES, 200);
    assert_eq!(HEADING_CONTENT_MAX_BYTES, 200);
    assert_eq!(PARAGRAPH_CONTENT_MAX_BYTES, 8 * 1024);
    assert_eq!(CODE_BLOCK_CONTENT_MAX_BYTES, 32 * 1024);
    assert_eq!(QUOTE_CONTENT_MAX_BYTES, 4 * 1024);
    assert_eq!(QUOTE_ATTRIBUTION_MAX_BYTES, 200);
    assert_eq!(LIST_TOTAL_MAX_BYTES, 8 * 1024);
    assert_eq!(LIST_ITEMS_MAX, 64);
    assert_eq!(IMAGE_ALT_MAX_BYTES, 1024);
    assert_eq!(IMAGE_CAPTION_MAX_BYTES, 500);
    assert_eq!(LINK_LABEL_MAX_BYTES, 200);
    assert_eq!(LINK_TARGET_MAX_BYTES, 1024);
    assert_eq!(FORM_FIELD_LABEL_MAX_BYTES, 200);
    assert_eq!(SUBMIT_LABEL_MAX_BYTES, 100);
    assert_eq!(FORM_FIELDS_MAX, 16);
    assert_eq!(SELECT_OPTIONS_MAX, 32);
    assert_eq!(FEEDBACK_CONTENT_MAX_BYTES, 2 * 1024);
    assert_eq!(NOTE_TITLE_MAX_BYTES, 200);
    assert_eq!(NOTE_CONTENT_MAX_BYTES, 4 * 1024);
    assert_eq!(CITATION_URL_MAX_BYTES, 1024);
}

#[test]
fn navigation_label_is_100_not_200() {
    assert_eq!(NAVIGATION_LABEL_MAX_BYTES, 100);
    assert_ne!(NAVIGATION_LABEL_MAX_BYTES, 200);
}

#[test]
fn canary_string_caps() {
    assert_eq!(CANARY_STATEMENT_MAX_BYTES, 2048);
    assert_eq!(CANARY_FRESHNESS_PROOF_MAX_BYTES, 200);
}

#[test]
fn state_caps() {
    assert_eq!(STATE_PURPOSE_MAX_BYTES, 200);
    assert_eq!(STATE_VALUE_MAX_BYTES, 4096);
}

#[test]
fn inline_caps() {
    assert_eq!(INLINE_ARRAY_MAX_ELEMENTS, 256);
    assert_eq!(INLINE_VALUE_MAX_BYTES, 2048);
}

#[test]
fn submit_body_caps() {
    assert_eq!(SUBMIT_FIELDS_MAX_PAIRS, 32);
    assert_eq!(SUBMIT_FIELD_VALUE_MAX_BYTES, 8 * 1024);
    assert_eq!(SUBMIT_REQUEST_STATE_MAX_ENTRIES, 32);
}

#[test]
fn numeric_ranges() {
    assert_eq!(*FORM_FIELD_MAX_LENGTH_RANGE.start(), 1);
    assert_eq!(*FORM_FIELD_MAX_LENGTH_RANGE.end(), 8192);
    assert_eq!(*IMAGE_DIMENSION_RANGE.start(), 1);
    assert_eq!(*IMAGE_DIMENSION_RANGE.end(), 4096);
    assert_eq!(*HEADING_LEVEL_RANGE.start(), 1);
    assert_eq!(*HEADING_LEVEL_RANGE.end(), 6);
    assert_eq!(*MIN_REFRESH_INTERVAL_RANGE.start(), 300);
    assert_eq!(*MIN_REFRESH_INTERVAL_RANGE.end(), 604_800);
    assert_eq!(*STATE_MAX_SIZE_RANGE.start(), 1);
    assert_eq!(*STATE_MAX_SIZE_RANGE.end(), 4096);
    assert_eq!(*STATE_MAX_LIFETIME_RANGE.start(), 300);
    assert_eq!(*STATE_MAX_LIFETIME_RANGE.end(), 7_776_000);
    assert_eq!(*STATE_TTL_HARD_RANGE.start(), 300);
    assert_eq!(*STATE_TTL_HARD_RANGE.end(), 7_776_000);
}

#[test]
fn canary_interval_and_clock_skew() {
    assert_eq!(CANARY_INTERVAL_MIN_SECS, 7 * 86_400);
    assert_eq!(CANARY_INTERVAL_MAX_SECS, 90 * 86_400);
    assert_eq!(CLOCK_SKEW_TOLERANCE_SECS, 300);
}
