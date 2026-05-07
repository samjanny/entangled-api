//! Normative limits referenced by the Entangled v1.0 specification.
//!
//! Each constant cites the spec section that establishes it. These values are
//! protocol-level requirements; clients that accept larger values are
//! non-conformant (§10).

use std::ops::RangeInclusive;

// -----------------------------------------------------------------------------
// Document size caps (§02, §06, §09)
// -----------------------------------------------------------------------------

/// Total content document envelope on the wire (§02).
pub const CONTENT_DOC_MAX_BYTES: usize = 1024 * 1024; // 1 MiB

/// Total transaction document envelope on the wire (§02).
pub const TRANSACTION_DOC_MAX_BYTES: usize = 1024 * 1024; // 1 MiB

/// Total manifest envelope on the wire (§06).
pub const MANIFEST_MAX_BYTES: usize = 64 * 1024; // 64 KiB

/// Total submit body on the wire (§09).
pub const SUBMIT_BODY_MAX_BYTES: usize = 64 * 1024; // 64 KiB

// -----------------------------------------------------------------------------
// JSON parser limits (§10 Stage 3)
// -----------------------------------------------------------------------------

/// Max JSON nesting depth permitted by Stage 3 parsing (§10).
pub const MAX_JSON_NESTING_DEPTH: usize = 16;

/// Max JSON string byte length (§10). Stricter field-specific caps may apply.
pub const MAX_JSON_STRING_BYTES: usize = 100 * 1024; // 100 KiB

/// Max JSON array length (§10). Stricter array-specific caps may apply.
pub const MAX_JSON_ARRAY_ELEMENTS: usize = 10_000;

/// Max distinct keys permitted in any single JSON object (§10).
pub const MAX_JSON_OBJECT_KEYS: usize = 256;

// -----------------------------------------------------------------------------
// Block array caps (§02, §03)
// -----------------------------------------------------------------------------

/// Max number of blocks in a content document (§02).
pub const MAX_BLOCKS_CONTENT: usize = 1024;

/// Max number of blocks in a transaction document (§02).
pub const MAX_BLOCKS_TRANSACTION: usize = 256;

/// Max number of `image` blocks per containing document (§03).
pub const MAX_IMAGE_BLOCKS_PER_DOC: usize = 16;

/// Max byte length of an image resource response body (§03).
pub const MAX_IMAGE_RESPONSE_BYTES: usize = 2 * 1024 * 1024; // 2 MiB

// -----------------------------------------------------------------------------
// Manifest sub-arrays (§06)
// -----------------------------------------------------------------------------

/// Max manifest navigation entries (§06).
pub const MAX_NAVIGATION_ENTRIES: usize = 32;

/// Max manifest state_policy entries (§06, §07).
pub const MAX_STATE_POLICY_ENTRIES: usize = 32;

/// Max state_updates entries in a transaction (§02, §07).
pub const MAX_STATE_UPDATES: usize = 32;

// -----------------------------------------------------------------------------
// String byte caps per field
// -----------------------------------------------------------------------------

/// `meta.title` max bytes (§02).
pub const META_TITLE_MAX_BYTES: usize = 200;

/// `heading.content` total inline value bytes (§03).
pub const HEADING_CONTENT_MAX_BYTES: usize = 200;

/// `paragraph.content` total inline value bytes (§03).
pub const PARAGRAPH_CONTENT_MAX_BYTES: usize = 8 * 1024;

/// `code_block.content` byte cap (§03).
pub const CODE_BLOCK_CONTENT_MAX_BYTES: usize = 32 * 1024;

/// `quote.content` total inline value bytes (§03).
pub const QUOTE_CONTENT_MAX_BYTES: usize = 4 * 1024;

/// `quote.attribution` total inline value bytes (§03).
pub const QUOTE_ATTRIBUTION_MAX_BYTES: usize = 200;

/// `list.items` aggregate inline value bytes (§03).
pub const LIST_TOTAL_MAX_BYTES: usize = 8 * 1024;

/// Max number of list items (§03).
pub const LIST_ITEMS_MAX: usize = 64;

/// `image.alt` byte cap (§03).
pub const IMAGE_ALT_MAX_BYTES: usize = 1024;

/// `image.caption` byte cap (§03).
pub const IMAGE_CAPTION_MAX_BYTES: usize = 500;

/// `link.label` total inline value bytes (§03).
pub const LINK_LABEL_MAX_BYTES: usize = 200;

/// Serialized link target byte cap (§03).
pub const LINK_TARGET_MAX_BYTES: usize = 1024;

/// Form field `label` byte cap (§03).
pub const FORM_FIELD_LABEL_MAX_BYTES: usize = 200;

/// `submit_form.submit_label` byte cap (§03).
pub const SUBMIT_LABEL_MAX_BYTES: usize = 100;

/// Max form fields per `submit_form` (§03).
pub const FORM_FIELDS_MAX: usize = 16;

/// Max select options per `select` field (§03).
pub const SELECT_OPTIONS_MAX: usize = 32;

/// `feedback.content` total inline value bytes (§03).
pub const FEEDBACK_CONTENT_MAX_BYTES: usize = 2 * 1024;

/// `note.title` byte cap (§03).
pub const NOTE_TITLE_MAX_BYTES: usize = 200;

/// `note.content` total inline value bytes (§03).
pub const NOTE_CONTENT_MAX_BYTES: usize = 4 * 1024;

/// Citation URL byte cap (§03).
pub const CITATION_URL_MAX_BYTES: usize = 1024;

// -----------------------------------------------------------------------------
// Navigation (§06)
// -----------------------------------------------------------------------------

/// Navigation entry `label` byte cap (§06). Note: 100 not 200.
pub const NAVIGATION_LABEL_MAX_BYTES: usize = 100;

// -----------------------------------------------------------------------------
// Canary (§08)
// -----------------------------------------------------------------------------

/// `canary.statement` byte cap (§08).
pub const CANARY_STATEMENT_MAX_BYTES: usize = 2048;

/// `canary.freshness_proof` byte cap (§08).
pub const CANARY_FRESHNESS_PROOF_MAX_BYTES: usize = 200;

// -----------------------------------------------------------------------------
// State (§07)
// -----------------------------------------------------------------------------

/// `state_policy[].purpose` byte cap (§07).
pub const STATE_PURPOSE_MAX_BYTES: usize = 200;

/// State value byte cap (§07).
pub const STATE_VALUE_MAX_BYTES: usize = 4096;

// -----------------------------------------------------------------------------
// Inline (§03)
// -----------------------------------------------------------------------------

/// Max elements in an inline content array (§03).
pub const INLINE_ARRAY_MAX_ELEMENTS: usize = 256;

/// Max bytes of any single inline `value` string (§03).
pub const INLINE_VALUE_MAX_BYTES: usize = 2048;

// -----------------------------------------------------------------------------
// Submit body (§09)
// -----------------------------------------------------------------------------

/// Max key/value pairs in submit body `fields` (§09).
pub const SUBMIT_FIELDS_MAX_PAIRS: usize = 32;

/// Max byte length of any single submit body `fields` value (§09).
pub const SUBMIT_FIELD_VALUE_MAX_BYTES: usize = 8 * 1024;

/// Max entries in submit body `request_state` (§09).
pub const SUBMIT_REQUEST_STATE_MAX_ENTRIES: usize = 32;

// -----------------------------------------------------------------------------
// Numeric ranges (use as inclusive ranges)
// -----------------------------------------------------------------------------

/// `text` / `textarea` `max_length` permitted range (§03).
pub const FORM_FIELD_MAX_LENGTH_RANGE: RangeInclusive<u32> = 1..=8192;

/// `image.width` and `image.height` permitted range (§03).
pub const IMAGE_DIMENSION_RANGE: RangeInclusive<u32> = 1..=4096;

/// `heading.level` permitted range (§03).
pub const HEADING_LEVEL_RANGE: RangeInclusive<u8> = 1..=6;

/// `manifest.min_refresh_interval` permitted range, seconds (§06).
pub const MIN_REFRESH_INTERVAL_RANGE: RangeInclusive<u32> = 300..=604_800;

/// `state_policy[].max_size` permitted range, bytes (§07).
pub const STATE_MAX_SIZE_RANGE: RangeInclusive<u32> = 1..=4096;

/// `state_policy[].max_lifetime` permitted range, seconds (§07).
pub const STATE_MAX_LIFETIME_RANGE: RangeInclusive<u32> = 300..=7_776_000;

/// State set `ttl` hard ceiling range, seconds (§07).
///
/// The check vs the manifest-declared `max_lifetime` is separate and requires
/// the current manifest at evaluation time.
pub const STATE_TTL_HARD_RANGE: RangeInclusive<u32> = 300..=7_776_000;

// -----------------------------------------------------------------------------
// Canary interval (§08; included here for coherence with later phases)
// -----------------------------------------------------------------------------

/// Min canary interval `next_expected - issued_at` in seconds (§08).
pub const CANARY_INTERVAL_MIN_SECS: i64 = 7 * 86_400;

/// Max canary interval `next_expected - issued_at` in seconds (§08).
pub const CANARY_INTERVAL_MAX_SECS: i64 = 90 * 86_400;

/// Clock-skew tolerance for future timestamps in seconds (§10).
pub const CLOCK_SKEW_TOLERANCE_SECS: i64 = 300;
