//! Diagnostic codes, severities, and the structured `Diagnostic` payload.
//!
//! The catalog mirrors the §11 normative table. Severity and pipeline stage
//! are protocol-level properties: implementations MUST NOT reclassify a code
//! when reporting it (§11).

use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentKindLabel {
    Manifest,
    Content,
    Transaction,
    None,
}

/// Normative diagnostic code (§11).
///
/// Each variant is mapped to its on-the-wire string form via an explicit
/// `#[serde(rename = "...")]` to avoid any ambiguity in serde's
/// `SCREAMING_SNAKE_CASE` heuristics for adjacent uppercase letters and
/// digits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
            | WImageHashMismatch
            | WImageOversize
            | WImageContentType
            | WImageDimensions
            | WImageDecodeFailed
            | WImageFetchFailed => Severity::Warning,

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
            | ETransportBadRequest => 1,

            // Stage 2 — Input.
            EInputByteCap | EInputUtf8 | EInputBom => 2,

            // Stage 3 — Parsing.
            EParseJson | EParseNestingDepth | EParseStringLength | EParseArrayLength
            | EParseObjectKeys => 3,

            // Stage 4 — Document kind discrimination.
            EKindMissingFields | EKindSpecVersion | EKindUnknown => 4,

            // Stage 5 — Schema.
            ESchemaRequiredField
            | ESchemaUnknownField
            | ESchemaBlockNotPermitted
            | ESchemaFieldType
            | ESchemaFieldRange
            | ESchemaFieldSyntax
            | ESchemaFieldLength
            | ESchemaNullValue
            | ESchemaNonInteger
            | ESchemaMalformedUnicode => 5,

            // Stage 6 — Signature.
            ESigVerification | ESigInvalidKey | ESigMalformed => 6,

            // Stage 7 — Trust state.
            ETrustMismatch | ETrustUserRejected | ITrustFirstContact | ITrustTofuPinned
            | ITrustVerified => 7,

            // Stage 8 — Canary.
            ECanaryInvalid
            | ECanaryDowngrade
            | WCanaryNearExpiration
            | WCanaryExpired
            | WCanaryGap
            | WCanaryUnavailable => 8,

            // Stage 9 — Binding.
            EBindPath | EBindResponsePath | EBindOrigin => 9,

            // Off-pipeline (state, historical, image).
            EStateUndeclared
            | EStateValueSize
            | EStateTtl
            | EStateOp
            | EStateStorageCap
            | IStateConsentRejected
            | IStateConsentRemembered
            | EHistoricalNoAuthorization
            | EHistoricalTrustBlocked
            | WHistoricalRendered
            | WImageHashMismatch
            | WImageOversize
            | WImageContentType
            | WImageDimensions
            | WImageDecodeFailed
            | WImageFetchFailed => 0,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Diagnostic {
    pub code: DiagnosticCode,
    pub stage: u8,
    pub severity: Severity,
    pub document_kind: DocumentKindLabel,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub details: Option<serde_json::Value>,
}

impl Diagnostic {
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
