use entangled_core::validation::{DiagnosticCode, Severity};

#[test]
fn esig_verification_serializes_exactly() {
    let s = serde_json::to_string(&DiagnosticCode::ESigVerification).unwrap();
    assert_eq!(s, "\"E_SIG_VERIFICATION\"");
}

#[test]
fn all_codes_round_trip_via_json() {
    let codes = [
        DiagnosticCode::ETransportStatus,
        DiagnosticCode::ETransportRedirect,
        DiagnosticCode::ETransportContentType,
        DiagnosticCode::ETransportContentLength,
        DiagnosticCode::ETransportBodyFailure,
        DiagnosticCode::ETransportRateLimited,
        DiagnosticCode::ETransportNotFound,
        DiagnosticCode::ETransportMethodNotAllowed,
        DiagnosticCode::ETransportPayloadTooLarge,
        DiagnosticCode::ETransportUnavailable,
        DiagnosticCode::ETransportBadRequest,
        DiagnosticCode::EInputByteCap,
        DiagnosticCode::EInputUtf8,
        DiagnosticCode::EInputBom,
        DiagnosticCode::EParseJson,
        DiagnosticCode::EParseNestingDepth,
        DiagnosticCode::EParseStringLength,
        DiagnosticCode::EParseArrayLength,
        DiagnosticCode::EParseObjectKeys,
        DiagnosticCode::EKindMissingFields,
        DiagnosticCode::EKindSpecVersion,
        DiagnosticCode::EKindUnknown,
        DiagnosticCode::ESchemaRequiredField,
        DiagnosticCode::ESchemaUnknownField,
        DiagnosticCode::ESchemaBlockNotPermitted,
        DiagnosticCode::ESchemaFieldType,
        DiagnosticCode::ESchemaFieldRange,
        DiagnosticCode::ESchemaFieldSyntax,
        DiagnosticCode::ESchemaFieldLength,
        DiagnosticCode::ESchemaNullValue,
        DiagnosticCode::ESchemaNonInteger,
        DiagnosticCode::ESchemaMalformedUnicode,
        DiagnosticCode::ESigVerification,
        DiagnosticCode::ESigInvalidKey,
        DiagnosticCode::ESigMalformed,
        DiagnosticCode::ETrustMismatch,
        DiagnosticCode::ETrustUserRejected,
        DiagnosticCode::ITrustFirstContact,
        DiagnosticCode::ITrustTofuPinned,
        DiagnosticCode::ITrustVerified,
        DiagnosticCode::ECanaryInvalid,
        DiagnosticCode::ECanaryDowngrade,
        DiagnosticCode::WCanaryNearExpiration,
        DiagnosticCode::WCanaryExpired,
        DiagnosticCode::WCanaryGap,
        DiagnosticCode::WCanaryUnavailable,
        DiagnosticCode::EBindPath,
        DiagnosticCode::EBindResponsePath,
        DiagnosticCode::EBindOrigin,
        DiagnosticCode::EStateUndeclared,
        DiagnosticCode::EStateValueSize,
        DiagnosticCode::EStateTtl,
        DiagnosticCode::EStateOp,
        DiagnosticCode::EStateStorageCap,
        DiagnosticCode::IStateConsentRejected,
        DiagnosticCode::IStateConsentRemembered,
        DiagnosticCode::EHistoricalNoAuthorization,
        DiagnosticCode::EHistoricalTrustBlocked,
        DiagnosticCode::WHistoricalRendered,
        DiagnosticCode::WImageHashMismatch,
        DiagnosticCode::WImageOversize,
        DiagnosticCode::WImageContentType,
        DiagnosticCode::WImageDimensions,
        DiagnosticCode::WImageDecodeFailed,
        DiagnosticCode::WImageFetchFailed,
    ];

    for c in codes {
        let s = serde_json::to_string(&c).unwrap();
        let back: DiagnosticCode = serde_json::from_str(&s).unwrap();
        assert_eq!(c, back, "round-trip failed for {s}");
    }
}

#[test]
fn severity_for_input_error_is_error() {
    assert_eq!(DiagnosticCode::EInputByteCap.severity(), Severity::Error);
}

#[test]
fn severity_for_canary_expired_is_warning() {
    assert_eq!(DiagnosticCode::WCanaryExpired.severity(), Severity::Warning);
}

#[test]
fn severity_for_trust_verified_is_info() {
    assert_eq!(DiagnosticCode::ITrustVerified.severity(), Severity::Info);
}

#[test]
fn stage_for_input_byte_cap_is_2() {
    assert_eq!(DiagnosticCode::EInputByteCap.stage(), 2);
}

#[test]
fn stage_for_state_undeclared_is_0() {
    assert_eq!(DiagnosticCode::EStateUndeclared.stage(), 0);
}
