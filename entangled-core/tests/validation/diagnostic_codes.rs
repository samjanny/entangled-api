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
        DiagnosticCode::ETransportContentEncoding,
        DiagnosticCode::ETransportTransferEncoding,
        DiagnosticCode::EInputByteCap,
        DiagnosticCode::EInputUtf8,
        DiagnosticCode::EInputBom,
        DiagnosticCode::EParseJson,
        DiagnosticCode::EParseNestingDepth,
        DiagnosticCode::EParseStringLength,
        DiagnosticCode::EParseArrayLength,
        DiagnosticCode::EParseObjectKeys,
        DiagnosticCode::EParseDuplicateKey,
        DiagnosticCode::EKindMissingFields,
        DiagnosticCode::EKindSpecVersion,
        DiagnosticCode::EKindUnknown,
        DiagnosticCode::ESchemaRequiredField,
        DiagnosticCode::ESchemaUnknownField,
        DiagnosticCode::ESchemaBlockNotPermitted,
        DiagnosticCode::ESchemaFieldType,
        DiagnosticCode::ESchemaFieldRange,
        DiagnosticCode::ESchemaFieldSyntax,
        DiagnosticCode::ESchemaEnumViolation,
        DiagnosticCode::ESchemaDuplicateEntry,
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
        DiagnosticCode::ECanaryConflict,
        DiagnosticCode::WCanaryNearExpiration,
        DiagnosticCode::ECanaryExpired,
        DiagnosticCode::WCanaryGap,
        DiagnosticCode::WCanaryUnavailable,
        DiagnosticCode::EBindPath,
        DiagnosticCode::EBindResponsePath,
        DiagnosticCode::EBindRequestId,
        DiagnosticCode::EBindRequestHash,
        DiagnosticCode::EBindOrigin,
        DiagnosticCode::EMigrationMismatch,
        DiagnosticCode::EMigrationInvalid,
        DiagnosticCode::EOriginExpired,
        DiagnosticCode::EOriginInvalid,
        DiagnosticCode::EStateUndeclared,
        DiagnosticCode::EStateValueSize,
        DiagnosticCode::EStateTtl,
        DiagnosticCode::EStateOp,
        DiagnosticCode::EStateStorageCap,
        DiagnosticCode::EStateDuplicate,
        DiagnosticCode::IStateConsentRejected,
        DiagnosticCode::IStateConsentRemembered,
        DiagnosticCode::EHistoricalNoAuthorization,
        DiagnosticCode::EHistoricalTrustBlocked,
        DiagnosticCode::WHistoricalRendered,
        DiagnosticCode::EHistoricalRuntimeAmbiguous,
        DiagnosticCode::WImageHashMismatch,
        DiagnosticCode::WImageOversize,
        DiagnosticCode::WImageContentType,
        DiagnosticCode::WImageDimensions,
        DiagnosticCode::WImageDecodeFailed,
        DiagnosticCode::WImageFetchFailed,
        DiagnosticCode::WImageBudget,
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
fn severity_for_canary_expired_is_error() {
    // §11 (rc.23 N64 / AMB-09): `W_CANARY_EXPIRED` was renamed to
    // `E_CANARY_EXPIRED` and promoted from `warning` to `error` to
    // align with the §08:183 MUST-block on rendering. The
    // §08:185 per-session user-override is the spec-defined
    // laxer-policy carve-out, distinct from a §11:87 client-side
    // reclassification.
    assert_eq!(DiagnosticCode::ECanaryExpired.severity(), Severity::Error);
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

#[test]
fn parse_duplicate_key_is_stage_3_error() {
    assert_eq!(DiagnosticCode::EParseDuplicateKey.stage(), 3);
    assert_eq!(
        DiagnosticCode::EParseDuplicateKey.severity(),
        Severity::Error
    );
}

#[test]
fn canary_conflict_is_stage_8_error() {
    assert_eq!(DiagnosticCode::ECanaryConflict.stage(), 8);
    assert_eq!(DiagnosticCode::ECanaryConflict.severity(), Severity::Error);
}

#[test]
fn bind_request_id_and_hash_are_stage_9_errors() {
    assert_eq!(DiagnosticCode::EBindRequestId.stage(), 9);
    assert_eq!(DiagnosticCode::EBindRequestHash.stage(), 9);
    assert_eq!(DiagnosticCode::EBindRequestId.severity(), Severity::Error);
    assert_eq!(DiagnosticCode::EBindRequestHash.severity(), Severity::Error);
}

#[test]
fn state_duplicate_is_off_pipeline_error() {
    assert_eq!(DiagnosticCode::EStateDuplicate.stage(), 0);
    assert_eq!(DiagnosticCode::EStateDuplicate.severity(), Severity::Error);
}

#[test]
fn image_budget_is_off_pipeline_warning() {
    assert_eq!(DiagnosticCode::WImageBudget.stage(), 0);
    assert_eq!(DiagnosticCode::WImageBudget.severity(), Severity::Warning);
}

#[test]
fn parse_duplicate_key_serializes_exactly() {
    let s = serde_json::to_string(&DiagnosticCode::EParseDuplicateKey).unwrap();
    assert_eq!(s, "\"E_PARSE_DUPLICATE_KEY\"");
}

#[test]
fn canary_conflict_serializes_exactly() {
    let s = serde_json::to_string(&DiagnosticCode::ECanaryConflict).unwrap();
    assert_eq!(s, "\"E_CANARY_CONFLICT\"");
}

#[test]
fn bind_request_id_serializes_exactly() {
    let s = serde_json::to_string(&DiagnosticCode::EBindRequestId).unwrap();
    assert_eq!(s, "\"E_BIND_REQUEST_ID\"");
}

#[test]
fn bind_request_hash_serializes_exactly() {
    let s = serde_json::to_string(&DiagnosticCode::EBindRequestHash).unwrap();
    assert_eq!(s, "\"E_BIND_REQUEST_HASH\"");
}

#[test]
fn state_duplicate_serializes_exactly() {
    let s = serde_json::to_string(&DiagnosticCode::EStateDuplicate).unwrap();
    assert_eq!(s, "\"E_STATE_DUPLICATE\"");
}

#[test]
fn image_budget_serializes_exactly() {
    let s = serde_json::to_string(&DiagnosticCode::WImageBudget).unwrap();
    assert_eq!(s, "\"W_IMAGE_BUDGET\"");
}

#[test]
fn origin_not_after_codes_have_correct_stages() {
    // §11 v1.0-rc.14 introduced both codes under the Binding family
    // (Stage 9). §11 v1.0-rc.23 N65 (AMB-05) moved `E_ORIGIN_INVALID`
    // to the Schema (Stage 5) catalog because the actual emission per
    // §06:171 and §10:191 is a Stage 5 cross-field semantic check on
    // `origin.not_after` and `canary.issued_at`. `E_ORIGIN_EXPIRED`
    // (the Stage 9 clock check) stays in the Binding catalog.
    assert_eq!(DiagnosticCode::EOriginExpired.stage(), 9);
    assert_eq!(DiagnosticCode::EOriginInvalid.stage(), 5);
    assert_eq!(DiagnosticCode::EOriginExpired.severity(), Severity::Error);
    assert_eq!(DiagnosticCode::EOriginInvalid.severity(), Severity::Error);
    assert_eq!(
        serde_json::to_string(&DiagnosticCode::EOriginExpired).unwrap(),
        "\"E_ORIGIN_EXPIRED\""
    );
    assert_eq!(
        serde_json::to_string(&DiagnosticCode::EOriginInvalid).unwrap(),
        "\"E_ORIGIN_INVALID\""
    );
}

#[test]
fn transport_content_encoding_is_stage_1_error() {
    // §09 / §11 v1.0-rc.4: forbidden HTTP-stack header on Entangled responses.
    assert_eq!(DiagnosticCode::ETransportContentEncoding.stage(), 1);
    assert_eq!(
        DiagnosticCode::ETransportContentEncoding.severity(),
        Severity::Error
    );
}

#[test]
fn transport_transfer_encoding_is_stage_1_error() {
    assert_eq!(DiagnosticCode::ETransportTransferEncoding.stage(), 1);
    assert_eq!(
        DiagnosticCode::ETransportTransferEncoding.severity(),
        Severity::Error
    );
}

#[test]
fn trust_mismatch_is_stage_6_error_per_rc_10() {
    // §11 (rc.10): `E_TRUST_MISMATCH` is detected during the Stage 6
    // manifest identity pre-check and takes precedence over
    // `E_SIG_VERIFICATION`. Stage attribution moved from 7 to 6.
    assert_eq!(DiagnosticCode::ETrustMismatch.stage(), 6);
    assert_eq!(DiagnosticCode::ETrustUserRejected.stage(), 6);
    assert_eq!(DiagnosticCode::ETrustMismatch.severity(), Severity::Error);
}

#[test]
fn trust_state_transitions_remain_stage_7() {
    // The First-contact / TOFU-pinned / externally-verified transitions
    // are emitted as part of Stage 7 trust-state resolution.
    assert_eq!(DiagnosticCode::ITrustFirstContact.stage(), 7);
    assert_eq!(DiagnosticCode::ITrustTofuPinned.stage(), 7);
    assert_eq!(DiagnosticCode::ITrustVerified.stage(), 7);
}

#[test]
fn schema_duplicate_entry_is_stage_5_error() {
    assert_eq!(DiagnosticCode::ESchemaDuplicateEntry.stage(), 5);
    assert_eq!(
        DiagnosticCode::ESchemaDuplicateEntry.severity(),
        Severity::Error
    );
}

#[test]
fn schema_duplicate_entry_serializes_exactly() {
    let s = serde_json::to_string(&DiagnosticCode::ESchemaDuplicateEntry).unwrap();
    assert_eq!(s, "\"E_SCHEMA_DUPLICATE_ENTRY\"");
}

#[test]
fn historical_runtime_ambiguous_is_off_pipeline_error() {
    // §11 (rc.23 N66): `W_HISTORICAL_RUNTIME_AMBIGUOUS` was renamed to
    // `E_HISTORICAL_RUNTIME_AMBIGUOUS` and promoted from `warning` to
    // `error` to align with the §10:553 MUST that the document is
    // rejected and not rendered (the prior catalog row was the same
    // catalog-vs-behavior mismatch pattern that N64 / AMB-09 closed
    // for `W_CANARY_EXPIRED`). Stage classification remains 0
    // (off-pipeline historical-content group).
    assert_eq!(DiagnosticCode::EHistoricalRuntimeAmbiguous.stage(), 0);
    assert_eq!(
        DiagnosticCode::EHistoricalRuntimeAmbiguous.severity(),
        Severity::Error
    );
}

#[test]
fn historical_runtime_ambiguous_serializes_exactly() {
    let s = serde_json::to_string(&DiagnosticCode::EHistoricalRuntimeAmbiguous).unwrap();
    assert_eq!(s, "\"E_HISTORICAL_RUNTIME_AMBIGUOUS\"");
}

#[test]
fn transport_content_encoding_serializes_exactly() {
    let s = serde_json::to_string(&DiagnosticCode::ETransportContentEncoding).unwrap();
    assert_eq!(s, "\"E_TRANSPORT_CONTENT_ENCODING\"");
}

#[test]
fn transport_transfer_encoding_serializes_exactly() {
    let s = serde_json::to_string(&DiagnosticCode::ETransportTransferEncoding).unwrap();
    assert_eq!(s, "\"E_TRANSPORT_TRANSFER_ENCODING\"");
}
