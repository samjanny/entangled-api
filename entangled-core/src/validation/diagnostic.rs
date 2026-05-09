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
    #[serde(rename = "W_CANARY_NEAR_EXPIRATION")]
    WCanaryNearExpiration,
    #[serde(rename = "W_CANARY_EXPIRED")]
    WCanaryExpired,
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
    #[serde(rename = "E_STATE_DUPLICATE")]
    EStateDuplicate,
    #[serde(rename = "I_STATE_CONSENT_REJECTED")]
    IStateConsentRejected,
    #[serde(rename = "I_STATE_CONSENT_REMEMBERED")]
    IStateConsentRemembered,

    // Historical content (off-pipeline)
    #[serde(rename = "E_HISTORICAL_NO_AUTHORIZATION")]
    EHistoricalNoAuthorization,
    #[serde(rename = "E_HISTORICAL_TRUST_BLOCKED")]
    EHistoricalTrustBlocked,
    #[serde(rename = "W_HISTORICAL_RENDERED")]
    WHistoricalRendered,
    #[serde(rename = "W_HISTORICAL_RUNTIME_AMBIGUOUS")]
    WHistoricalRuntimeAmbiguous,

    // Image resource (off-pipeline; warnings)
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
            | WCanaryExpired
            | WCanaryGap
            | WCanaryUnavailable
            | WHistoricalRendered
            | WHistoricalRuntimeAmbiguous
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

            // Stage 5 — Schema.
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
            | ESchemaMalformedUnicode => 5,

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

            // Stage 8 — Canary.
            ECanaryInvalid
            | ECanaryDowngrade
            | ECanaryConflict
            | WCanaryNearExpiration
            | WCanaryExpired
            | WCanaryGap
            | WCanaryUnavailable => 8,

            // Stage 9 — Binding.
            EBindPath | EBindResponsePath | EBindRequestId | EBindRequestHash | EBindOrigin => 9,

            // Off-pipeline (state, historical, image).
            EStateUndeclared
            | EStateValueSize
            | EStateTtl
            | EStateOp
            | EStateStorageCap
            | EStateDuplicate
            | IStateConsentRejected
            | IStateConsentRemembered
            | EHistoricalNoAuthorization
            | EHistoricalTrustBlocked
            | WHistoricalRendered
            | WHistoricalRuntimeAmbiguous
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
