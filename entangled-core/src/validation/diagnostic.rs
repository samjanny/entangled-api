//! Diagnostic codes, severities, and the structured `Diagnostic` payload.
//!
//! The catalog mirrors the §11 normative table. Severity and pipeline stage
//! are protocol-level properties: implementations MUST NOT reclassify a code
//! when reporting it (§11).

use std::fmt;

use serde::{Deserialize, Serialize};

/// Diagnostic severity per §11.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Error — document MUST be rejected.
    Error,
    /// Warning — document MAY be processed with caveats; UI surfaces the
    /// condition.
    Warning,
    /// Info — informational only; never blocks rendering.
    Info,
}

/// Tag identifying which document kind a diagnostic relates to.
///
/// Set to [`DocumentKindLabel::None`] for diagnostics that are produced
/// before the kind has been discriminated (Stage 2-3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentKindLabel {
    /// Manifest document.
    Manifest,
    /// Content document.
    Content,
    /// Transaction document.
    Transaction,
    /// Content index resource (Section 09). Not an Entangled signed
    /// document but a `K_publisher`-committed JSON resource that the
    /// client fetches alongside the manifest.
    ContentIndex,
    /// Kind not yet known (Stage 2-3 diagnostics).
    None,
}

/// Normative diagnostic code (§11).
///
/// Each variant is mapped to its on-the-wire string form via an explicit
/// `#[serde(rename = "...")]` to avoid any ambiguity in serde's
/// `SCREAMING_SNAKE_CASE` heuristics for adjacent uppercase letters and
/// digits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(missing_docs)] // each variant's name is documented by §11; per-variant prose would
                       // duplicate the spec.
pub enum DiagnosticCode {
    // Stage 1 — Transport (§11)
    #[serde(rename = "E_TRANSPORT_STATUS")]
    ETransportStatus,
    #[serde(rename = "E_TRANSPORT_REDIRECT")]
    ETransportRedirect,
    #[serde(rename = "E_TRANSPORT_CONTENT_TYPE")]
    ETransportContentType,
    #[serde(rename = "E_TRANSPORT_CONTENT_LENGTH")]
    ETransportContentLength,
    #[serde(rename = "E_TRANSPORT_BODY_FAILURE")]
    ETransportBodyFailure,
    #[serde(rename = "E_TRANSPORT_RATE_LIMITED")]
    ETransportRateLimited,
    #[serde(rename = "E_TRANSPORT_NOT_FOUND")]
    ETransportNotFound,
    #[serde(rename = "E_TRANSPORT_METHOD_NOT_ALLOWED")]
    ETransportMethodNotAllowed,
    #[serde(rename = "E_TRANSPORT_PAYLOAD_TOO_LARGE")]
    ETransportPayloadTooLarge,
    #[serde(rename = "E_TRANSPORT_UNAVAILABLE")]
    ETransportUnavailable,
    #[serde(rename = "E_TRANSPORT_BAD_REQUEST")]
    ETransportBadRequest,
    #[serde(rename = "E_TRANSPORT_CONTENT_ENCODING")]
    ETransportContentEncoding,
    #[serde(rename = "E_TRANSPORT_TRANSFER_ENCODING")]
    ETransportTransferEncoding,

    // Stage 2 — Input
    #[serde(rename = "E_INPUT_BYTE_CAP")]
    EInputByteCap,
    #[serde(rename = "E_INPUT_UTF8")]
    EInputUtf8,
    #[serde(rename = "E_INPUT_BOM")]
    EInputBom,

    // Stage 3 — Parsing
    #[serde(rename = "E_PARSE_JSON")]
    EParseJson,
    #[serde(rename = "E_PARSE_NESTING_DEPTH")]
    EParseNestingDepth,
    #[serde(rename = "E_PARSE_STRING_LENGTH")]
    EParseStringLength,
    #[serde(rename = "E_PARSE_ARRAY_LENGTH")]
    EParseArrayLength,
    #[serde(rename = "E_PARSE_OBJECT_KEYS")]
    EParseObjectKeys,
    #[serde(rename = "E_PARSE_DUPLICATE_KEY")]
    EParseDuplicateKey,

    // Stage 4 — Document kind discrimination
    #[serde(rename = "E_KIND_MISSING_FIELDS")]
    EKindMissingFields,
    #[serde(rename = "E_KIND_SPEC_VERSION")]
    EKindSpecVersion,
    #[serde(rename = "E_KIND_UNKNOWN")]
    EKindUnknown,

    // Stage 5 — Schema
    #[serde(rename = "E_SCHEMA_REQUIRED_FIELD")]
    ESchemaRequiredField,
    #[serde(rename = "E_SCHEMA_UNKNOWN_FIELD")]
    ESchemaUnknownField,
    #[serde(rename = "E_SCHEMA_BLOCK_NOT_PERMITTED")]
    ESchemaBlockNotPermitted,
    #[serde(rename = "E_SCHEMA_FIELD_TYPE")]
    ESchemaFieldType,
    #[serde(rename = "E_SCHEMA_FIELD_RANGE")]
    ESchemaFieldRange,
    #[serde(rename = "E_SCHEMA_FIELD_SYNTAX")]
    ESchemaFieldSyntax,
    #[serde(rename = "E_SCHEMA_ENUM_VIOLATION")]
    ESchemaEnumViolation,
    #[serde(rename = "E_SCHEMA_DUPLICATE_ENTRY")]
    ESchemaDuplicateEntry,
    #[serde(rename = "E_SCHEMA_FIELD_LENGTH")]
    ESchemaFieldLength,
    #[serde(rename = "E_SCHEMA_NULL_VALUE")]
    ESchemaNullValue,
    #[serde(rename = "E_SCHEMA_NON_INTEGER")]
    ESchemaNonInteger,
    #[serde(rename = "E_SCHEMA_MALFORMED_UNICODE")]
    ESchemaMalformedUnicode,
    /// §11 (rc.21 N62). The manifest's `state_policy` declares an
    /// aggregate worst-case request-state encoded contribution that
    /// exceeds the §09 `state_budget` (53248 bytes for v1.0). The
    /// satisfiability invariant is computed from the manifest payload
    /// alone and does not depend on the client's retained state.
    /// Structured `details` carry `component` (`"state"` is the only
    /// v1.0 value), `declared_bytes` (the computed aggregate), and
    /// `budget_bytes` (the applicable limit). Distinct from the
    /// runtime-side `E_STATE_TRANSMIT_BUDGET` (manifest validation vs
    /// individual `set` operation; both codes coexist in v1.0).
    #[serde(rename = "E_SUBMIT_BUDGET")]
    ESubmitBudget,

    // Stage 6 — Signature
    #[serde(rename = "E_SIG_VERIFICATION")]
    ESigVerification,
    #[serde(rename = "E_SIG_INVALID_KEY")]
    ESigInvalidKey,
    #[serde(rename = "E_SIG_MALFORMED")]
    ESigMalformed,

    // Stage 7 — Trust state
    #[serde(rename = "E_TRUST_MISMATCH")]
    ETrustMismatch,
    #[serde(rename = "E_TRUST_USER_REJECTED")]
    ETrustUserRejected,
    #[serde(rename = "I_TRUST_FIRST_CONTACT")]
    ITrustFirstContact,
    #[serde(rename = "I_TRUST_TOFU_PINNED")]
    ITrustTofuPinned,
    #[serde(rename = "I_TRUST_VERIFIED")]
    ITrustVerified,

    // Stage 8 — Canary
    #[serde(rename = "E_CANARY_INVALID")]
    ECanaryInvalid,
    #[serde(rename = "E_CANARY_DOWNGRADE")]
    ECanaryDowngrade,
    #[serde(rename = "E_CANARY_CONFLICT")]
    ECanaryConflict,
    /// §11 (rc.19 N55/N60). A new manifest's `canary.runtime_pubkey`
    /// reuses a value previously authorized for the same
    /// `K_publisher.pub`. MUST-level against the immediately preceding
    /// verified manifest (N55); SHOULD-level against any prior entry in
    /// publisher history (N60). The diagnostic `details.window_position`
    /// distinguishes the two cases: `1` for the immediate-preceding
    /// match, `>= 2` for a deeper-history match.
    #[serde(rename = "E_CANARY_RUNTIME_REUSE")]
    ECanaryRuntimeReuse,
    #[serde(rename = "W_CANARY_NEAR_EXPIRATION")]
    WCanaryNearExpiration,
    #[serde(rename = "E_CANARY_EXPIRED")]
    ECanaryExpired,
    #[serde(rename = "W_CANARY_GAP")]
    WCanaryGap,
    #[serde(rename = "W_CANARY_UNAVAILABLE")]
    WCanaryUnavailable,

    // Stage 9 — Binding
    #[serde(rename = "E_BIND_PATH")]
    EBindPath,
    #[serde(rename = "E_BIND_RESPONSE_PATH")]
    EBindResponsePath,
    #[serde(rename = "E_BIND_REQUEST_ID")]
    EBindRequestId,
    #[serde(rename = "E_BIND_REQUEST_HASH")]
    EBindRequestHash,
    #[serde(rename = "E_BIND_ORIGIN")]
    EBindOrigin,
    /// §11 (rc.13). The `successor_origin.publisher_pubkey` resolved during
    /// origin migration does not match the announcing manifest's
    /// `publisher_pubkey`. Reported by the migration helper after the
    /// successor manifest has cleared its own Stage 6 self-verification.
    #[serde(rename = "E_MIGRATION_MISMATCH")]
    EMigrationMismatch,
    /// §11 (rc.13). The announcing manifest's `migration_pointer` is
    /// structurally well-formed but semantically invalid (successor address
    /// equals announcing address, `announced_at` after `updated`, or carrier
    /// mismatch). Extended in rc.14 to cover the per-flow chain-cycle case
    /// (a `successor_origin.address` already present in the
    /// `visited_origins` set; `details.reason = "chain_cycle"`).
    #[serde(rename = "E_MIGRATION_INVALID")]
    EMigrationInvalid,
    /// §11 (rc.14). The manifest's `origin.not_after` is present and the
    /// client's clock (subject to the §10 clock-skew tolerance) is at or
    /// after the declared instant; the manifest is not accepted as current.
    /// Detected at Stage 9 after carrier origin binding succeeds.
    #[serde(rename = "E_ORIGIN_EXPIRED")]
    EOriginExpired,
    /// §11 (rc.14). The manifest's `origin.not_after` is present but
    /// violates a semantic constraint: it is not strictly later than
    /// `canary.issued_at`, or it is more than five years after
    /// `canary.issued_at`. Detected at Stage 5; cataloged under the §11
    /// Binding diagnostics with the rest of the origin / migration codes.
    #[serde(rename = "E_ORIGIN_INVALID")]
    EOriginInvalid,

    // Stage 9 — Content index (§11 rc.19, N49)
    /// Manifest declares `content_root` but `/content_index.json` fetch
    /// failed at transport level.
    #[serde(rename = "E_CONTENT_INDEX_FETCH_FAILED")]
    EContentIndexFetchFailed,
    /// SHA-256 digest of fetched `/content_index.json` bytes does not match
    /// the manifest's `content_root` value.
    #[serde(rename = "E_CONTENT_INDEX_HASH_MISMATCH")]
    EContentIndexHashMismatch,
    /// Content index fetched and hash-verified but fails structural
    /// validation (invalid JSON, closed-structure violation, path syntax
    /// violation, entry field violation, or exceeds 1 MiB cap).
    #[serde(rename = "E_CONTENT_INDEX_INVALID")]
    EContentIndexInvalid,
    /// Content index has an entry for the document's path, but the document
    /// omits `seq`.
    #[serde(rename = "E_CONTENT_SEQ_MISSING")]
    EContentSeqMissing,
    /// Content document's `seq` is strictly less than the content index
    /// entry's `seq` for the same path (rollback).
    #[serde(rename = "E_CONTENT_SEQ_ROLLBACK")]
    EContentSeqRollback,
    /// Content document's `seq` is strictly greater than the content index
    /// entry's `seq` for the same path (uncommitted).
    #[serde(rename = "E_CONTENT_SEQ_UNCOMMITTED")]
    EContentSeqUncommitted,
    /// Content document's `seq` equals the index entry's `seq`, but the
    /// SHA-256 digest of the response body bytes does not match the index
    /// entry's `hash`.
    #[serde(rename = "E_CONTENT_HASH_MISMATCH")]
    EContentHashMismatch,

    // State (off-pipeline)
    #[serde(rename = "E_STATE_UNDECLARED")]
    EStateUndeclared,
    #[serde(rename = "E_STATE_VALUE_SIZE")]
    EStateValueSize,
    #[serde(rename = "E_STATE_TTL")]
    EStateTtl,
    #[serde(rename = "E_STATE_OP")]
    EStateOp,
    #[serde(rename = "E_STATE_STORAGE_CAP")]
    EStateStorageCap,
    /// §11:286 (rc.19+). Committing a request-mode `set` operation
    /// would make the retained request-state aggregate overflow the
    /// minimal-submit 64 KiB transmit budget, so the operation is
    /// rejected locally before commit. Distinct from `E_SUBMIT_BUDGET`
    /// (Stage 5 publisher-policy satisfiability invariant): the former
    /// rejects a satisfiable policy's individual run-time set, the
    /// latter rejects an unsatisfiable policy outright. Structured
    /// `details` SHOULD include `namespace`, `key`, `projected_bytes`,
    /// `cap_bytes` (65536).
    #[serde(rename = "E_STATE_TRANSMIT_BUDGET")]
    EStateTransmitBudget,
    #[serde(rename = "E_STATE_DUPLICATE")]
    EStateDuplicate,
    #[serde(rename = "I_STATE_CONSENT_REJECTED")]
    IStateConsentRejected,
    #[serde(rename = "I_STATE_CONSENT_REMEMBERED")]
    IStateConsentRemembered,

    // Historical content (off-pipeline).
    //
    // Caller obligation: historical-content authorization (§10:510-553)
    // lives in the caller's trust-state and publisher-history layer, which
    // this crate declares out of scope (see the crate root). The crate
    // defines these codes for §11 catalog completeness but does NOT emit
    // them: it has no authorization-history store, no key-trial order
    // (§10:545), and no rendering-record store. A caller building that layer
    // is responsible for emitting them, and in particular MUST implement the
    // §10:522 publication-existence check that fires
    // `E_HISTORICAL_NO_PUBLICATION_PROOF` - it is security-critical, because
    // without it an attacker holding an exfiltrated former `K_runtime_priv`
    // can fabricate documents that verify as historically authentic but were
    // never published.
    #[serde(rename = "E_HISTORICAL_NO_AUTHORIZATION")]
    EHistoricalNoAuthorization,
    #[serde(rename = "E_HISTORICAL_TRUST_BLOCKED")]
    EHistoricalTrustBlocked,
    /// §11 (rc.19 N52). Historical content document verification reached
    /// a state where neither a previously-verified content index entry
    /// nor a prior rendering record names the document's `(path, seq,
    /// hash)` tuple under the authorizing manifest. Off-pipeline; the
    /// crate exposes the code for callers that implement the historical
    /// content path. See §10 "Historical content".
    #[serde(rename = "E_HISTORICAL_NO_PUBLICATION_PROOF")]
    EHistoricalNoPublicationProof,
    #[serde(rename = "W_HISTORICAL_RENDERED")]
    WHistoricalRendered,
    #[serde(rename = "E_HISTORICAL_RUNTIME_AMBIGUOUS")]
    EHistoricalRuntimeAmbiguous,

    // Image resource (off-pipeline; warnings).
    //
    // Caller obligation: image fetch-time validation (§03) lives in the
    // caller's image-fetch/render layer, which this crate declares out of
    // scope (see the crate root: "image decoding and rendering"). The crate
    // defines these codes for §11 catalog completeness but does NOT emit
    // them: it performs no image fetch, no SHA-256 verification of image
    // bytes, no 2 MiB response-cap enforcement (the `MAX_IMAGE_RESPONSE_BYTES`
    // constant is provided for callers but not read here), no decode, no
    // dimension or animated-WebP check. A caller building the image layer is
    // responsible for emitting these codes per the §03 fetch-time MUSTs.
    #[serde(rename = "W_IMAGE_HASH_MISMATCH")]
    WImageHashMismatch,
    #[serde(rename = "W_IMAGE_OVERSIZE")]
    WImageOversize,
    #[serde(rename = "W_IMAGE_CONTENT_TYPE")]
    WImageContentType,
    #[serde(rename = "W_IMAGE_DIMENSIONS")]
    WImageDimensions,
    #[serde(rename = "W_IMAGE_DECODE_FAILED")]
    WImageDecodeFailed,
    #[serde(rename = "W_IMAGE_FETCH_FAILED")]
    WImageFetchFailed,
    #[serde(rename = "W_IMAGE_BUDGET")]
    WImageBudget,
}

impl DiagnosticCode {
    /// Normative severity per §11.
    pub const fn severity(self) -> Severity {
        use DiagnosticCode::*;
        match self {
            // Warning-severity codes.
            WCanaryNearExpiration
            | WCanaryGap
            | WCanaryUnavailable
            | WHistoricalRendered
            | WImageHashMismatch
            | WImageOversize
            | WImageContentType
            | WImageDimensions
            | WImageDecodeFailed
            | WImageFetchFailed
            | WImageBudget => Severity::Warning,

            // Info-severity codes.
            ITrustFirstContact
            | ITrustTofuPinned
            | ITrustVerified
            | IStateConsentRejected
            | IStateConsentRemembered => Severity::Info,

            // Everything else is an error.
            _ => Severity::Error,
        }
    }

    /// Pipeline stage per §10/§11. `0` for off-pipeline diagnostics.
    pub const fn stage(self) -> u8 {
        use DiagnosticCode::*;
        match self {
            // Stage 1 — Transport.
            ETransportStatus
            | ETransportRedirect
            | ETransportContentType
            | ETransportContentLength
            | ETransportBodyFailure
            | ETransportRateLimited
            | ETransportNotFound
            | ETransportMethodNotAllowed
            | ETransportPayloadTooLarge
            | ETransportUnavailable
            | ETransportBadRequest
            | ETransportContentEncoding
            | ETransportTransferEncoding => 1,

            // Stage 2 — Input.
            EInputByteCap | EInputUtf8 | EInputBom => 2,

            // Stage 3 — Parsing.
            EParseJson | EParseNestingDepth | EParseStringLength | EParseArrayLength
            | EParseObjectKeys | EParseDuplicateKey => 3,

            // Stage 4 — Document kind discrimination.
            EKindMissingFields | EKindSpecVersion | EKindUnknown => 4,

            // Stage 5 — Schema. `E_ORIGIN_INVALID` was cataloged under
            // Stage 9 in rc.14 through rc.22 even though §06:171 emits
            // it as a Stage 5 cross-field semantic check on
            // `origin.not_after` and `canary.issued_at`. rc.23 N65
            // (AMB-05) corrected the catalog row to Stage 5 to match
            // the actual emission stage; the api stage classifier now
            // reflects that placement.
            ESchemaRequiredField
            | ESchemaUnknownField
            | ESchemaBlockNotPermitted
            | ESchemaFieldType
            | ESchemaFieldRange
            | ESchemaFieldSyntax
            | ESchemaEnumViolation
            | ESchemaDuplicateEntry
            | ESchemaFieldLength
            | ESchemaNullValue
            | ESchemaNonInteger
            | ESchemaMalformedUnicode
            | ESubmitBudget
            | EOriginInvalid => 5,

            // Stage 6 — Signature, plus the manifest identity pre-check
            // detected during Stage 6 per §11 (rc.10): `E_TRUST_MISMATCH`
            // takes precedence over `E_SIG_VERIFICATION` and is reported
            // with `stage: 6`. `E_TRUST_USER_REJECTED` accompanies the same
            // pre-check when the user rejects the presented identity.
            ESigVerification | ESigInvalidKey | ESigMalformed | ETrustMismatch
            | ETrustUserRejected => 6,

            // Stage 7 — Trust state transitions only (First contact /
            // TOFU pinning / external verification). The mismatch /
            // user-rejected codes moved to Stage 6 in rc.10.
            ITrustFirstContact | ITrustTofuPinned | ITrustVerified => 7,

            // Stage 8 — Canary. `E_CANARY_EXPIRED` was `W_CANARY_EXPIRED`
            // at warning severity in rc.10 through rc.22; rc.23 N64
            // (AMB-09) renamed and promoted it to error severity to
            // align with the §08:183 MUST-block.
            ECanaryInvalid
            | ECanaryDowngrade
            | ECanaryConflict
            | ECanaryRuntimeReuse
            | WCanaryNearExpiration
            | ECanaryExpired
            | WCanaryGap
            | WCanaryUnavailable => 8,

            // Stage 9 — Binding (incl. origin-migration codes from rc.13,
            // origin not-after expiry from rc.14, and content-index codes
            // from rc.19). `E_ORIGIN_INVALID` was cataloged here from
            // rc.14 through rc.22; rc.23 N65 (AMB-05) moved it to the
            // Stage 5 group above to match the §06:171 / §10:191
            // emission stage.
            EBindPath
            | EBindResponsePath
            | EBindRequestId
            | EBindRequestHash
            | EBindOrigin
            | EMigrationMismatch
            | EMigrationInvalid
            | EOriginExpired
            | EContentIndexFetchFailed
            | EContentIndexHashMismatch
            | EContentIndexInvalid
            | EContentSeqMissing
            | EContentSeqRollback
            | EContentSeqUncommitted
            | EContentHashMismatch => 9,

            // Off-pipeline (state, historical, image).
            EStateUndeclared
            | EStateValueSize
            | EStateTtl
            | EStateOp
            | EStateStorageCap
            | EStateTransmitBudget
            | EStateDuplicate
            | IStateConsentRejected
            | IStateConsentRemembered
            | EHistoricalNoAuthorization
            | EHistoricalTrustBlocked
            | EHistoricalNoPublicationProof
            | WHistoricalRendered
            | EHistoricalRuntimeAmbiguous
            | WImageHashMismatch
            | WImageOversize
            | WImageContentType
            | WImageDimensions
            | WImageDecodeFailed
            | WImageFetchFailed
            | WImageBudget => 0,
        }
    }
}

impl fmt::Display for DiagnosticCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The serde rename forms are the normative on-the-wire identifiers.
        let json = serde_json::to_string(self).map_err(|_| fmt::Error)?;
        f.write_str(json.trim_matches('"'))
    }
}

/// Structured diagnostic payload (§11).
///
/// `stage` and `severity` are derived from `code` at construction time and
/// MUST NOT be set independently.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Diagnostic {
    /// Normative diagnostic code.
    pub code: DiagnosticCode,
    /// Pipeline stage at which the diagnostic was produced (`0` for
    /// off-pipeline diagnostics).
    pub stage: u8,
    /// Normative severity for `code`.
    pub severity: Severity,
    /// Document kind under which the diagnostic was raised.
    pub document_kind: DocumentKindLabel,
    /// Free-form human-readable message; not normative.
    pub message: String,
    /// Optional structured details. Format is implementation-specific.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub details: Option<serde_json::Value>,
}

impl Diagnostic {
    /// Build a diagnostic. `stage` and `severity` are derived from `code`.
    pub fn new(
        code: DiagnosticCode,
        document_kind: DocumentKindLabel,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            stage: code.stage(),
            severity: code.severity(),
            document_kind,
            message: message.into(),
            details: None,
        }
    }

    /// Attach optional structured `details` payload.
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for Diagnostic {}
