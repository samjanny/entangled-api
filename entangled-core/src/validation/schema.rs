//! Stage 5 dispatch — top-level validators and end-to-end pipelines for
//! manifest, content, and transaction documents.
//!
//! The serde error message format used by `map_serde_err` is not part of
//! serde's public API. If serde changes the wording, the mapping may need
//! adjustment. Tests in `tests/validation/` cover the current behavior of
//! serde_json 1.0.149.

use serde_json::Value;

use crate::types::canary::Canary;
use crate::types::document::{ContentDocument, Document, TransactionDocument};
use crate::types::manifest::{Manifest, MigrationPointer, NavEntry, Origin};
use crate::types::meta::Meta;
use crate::types::state::{StatePolicyEntry, StateUpdateOp};
use crate::types::timestamp::EntangledTimestamp;

use super::blocks::validate_blocks;
use super::clock::check_future_timestamp;
use super::diagnostic::{Diagnostic, DiagnosticCode, DocumentKindLabel};
use super::input::{check_input, InputKind};
use super::kind::{discriminate_kind, DocumentKind};
use super::limits::{
    CANARY_FRESHNESS_PROOF_MAX_BYTES, CANARY_STATEMENT_MAX_BYTES, MAX_BLOCKS_CONTENT,
    MAX_BLOCKS_TRANSACTION, MAX_NAVIGATION_ENTRIES, META_TITLE_MAX_BYTES,
    MIN_REFRESH_INTERVAL_RANGE, NAVIGATION_LABEL_MAX_BYTES, ORIGIN_NOT_AFTER_MAX_HORIZON_SECS,
};
use super::parse::parse_with_limits;
use super::state::{validate_state_policy, validate_state_updates_standalone};
use super::strings::{check_nfc, no_control_chars};
use crate::types::blocks::Block;

// -----------------------------------------------------------------------------
// Public top-level pipelines (Stages 2–5)
// -----------------------------------------------------------------------------

/// Run Stages 2-5 on a manifest envelope and return the typed [`Manifest`].
///
/// `now` is the local wall-clock time used for the §06 / §10 clock-skew
/// check on `manifest.updated`: a manifest dated more than 300 seconds ahead
/// of `now` is rejected with `E_SCHEMA_FIELD_SYNTAX` carrying
/// `reason: "future_beyond_skew_tolerance"` in `details` (§10 rc.10).
///
/// # Errors
///
/// Returns the first applicable Stage 2-5 diagnostic.
pub fn parse_and_validate_manifest(
    bytes: &[u8],
    now: &EntangledTimestamp,
) -> Result<Manifest, Diagnostic> {
    parse_and_validate_manifest_with_value(bytes, now).map(|(m, _)| m)
}

/// Same as [`parse_and_validate_manifest`] but also returns the raw
/// parsed wire [`Value`] (post-parse / post-schema, with `kind` still
/// present and `sig` still attached).
///
/// Used by [`crate::document::parse_and_verify_manifest`] to compute the
/// signature input directly over the wire bytes rather than over a
/// round-trip of the typed [`Manifest`]. Returning both pins the signed
/// bytes to the bytes the parser actually observed, removing dependence
/// on every [`serde::Serialize`] impl being faithful to its
/// [`serde::Deserialize`] counterpart.
///
/// # Errors
///
/// Returns the first applicable Stage 2-5 diagnostic.
pub fn parse_and_validate_manifest_with_value(
    bytes: &[u8],
    now: &EntangledTimestamp,
) -> Result<(Manifest, Value), Diagnostic> {
    let s = check_input(bytes, InputKind::Manifest)?;
    let value = parse_with_limits(s).map_err(|d| set_kind(d, DocumentKindLabel::Manifest))?;
    let kind = discriminate_kind(&value)?;
    if kind != DocumentKind::Manifest {
        return Err(Diagnostic::new(
            DiagnosticCode::EKindUnknown,
            DocumentKindLabel::None,
            format!("expected manifest, got {kind:?}"),
        ));
    }
    schema_prepass(&value, DocumentKindLabel::Manifest)?;
    // Clone before `from_value` (which consumes) so we can return both the
    // typed model and the wire Value. Bounded by the Stage 2 1 MiB input cap.
    let doc: Document = serde_json::from_value(value.clone())
        .map_err(|e| map_serde_err(e, DocumentKindLabel::Manifest))?;
    let manifest = match doc {
        Document::Manifest(m) => m,
        _ => unreachable!("Stage 4 already discriminated as manifest"),
    };
    validate_manifest(&manifest, now)?;
    Ok((manifest, value))
}

/// Run Stages 2-5 on a content envelope and return the typed
/// [`ContentDocument`].
///
/// # Errors
///
/// Returns the first applicable Stage 2-5 diagnostic.
pub fn parse_and_validate_content(bytes: &[u8]) -> Result<ContentDocument, Diagnostic> {
    parse_and_validate_content_with_value(bytes).map(|(c, _)| c)
}

/// Same as [`parse_and_validate_content`] but also returns the raw
/// parsed wire [`Value`]. See
/// [`parse_and_validate_manifest_with_value`] for rationale.
///
/// # Errors
///
/// Returns the first applicable Stage 2-5 diagnostic.
pub fn parse_and_validate_content_with_value(
    bytes: &[u8],
) -> Result<(ContentDocument, Value), Diagnostic> {
    let s = check_input(bytes, InputKind::ContentDocument)?;
    let value = parse_with_limits(s).map_err(|d| set_kind(d, DocumentKindLabel::Content))?;
    let kind = discriminate_kind(&value)?;
    if kind != DocumentKind::Content {
        return Err(Diagnostic::new(
            DiagnosticCode::EKindUnknown,
            DocumentKindLabel::None,
            format!("expected content, got {kind:?}"),
        ));
    }
    schema_prepass(&value, DocumentKindLabel::Content)?;
    let doc: Document = serde_json::from_value(value.clone())
        .map_err(|e| map_serde_err(e, DocumentKindLabel::Content))?;
    let content = match doc {
        Document::Content(c) => c,
        _ => unreachable!("Stage 4 already discriminated as content"),
    };
    validate_content(&content)?;
    Ok((content, value))
}

/// Run Stages 2-5 on a transaction envelope and return the typed
/// [`TransactionDocument`].
///
/// # Errors
///
/// Returns the first applicable Stage 2-5 diagnostic.
pub fn parse_and_validate_transaction(bytes: &[u8]) -> Result<TransactionDocument, Diagnostic> {
    parse_and_validate_transaction_with_value(bytes).map(|(t, _)| t)
}

/// Same as [`parse_and_validate_transaction`] but also returns the raw
/// parsed wire [`Value`]. See
/// [`parse_and_validate_manifest_with_value`] for rationale.
///
/// # Errors
///
/// Returns the first applicable Stage 2-5 diagnostic.
pub fn parse_and_validate_transaction_with_value(
    bytes: &[u8],
) -> Result<(TransactionDocument, Value), Diagnostic> {
    let s = check_input(bytes, InputKind::TransactionDocument)?;
    let value = parse_with_limits(s).map_err(|d| set_kind(d, DocumentKindLabel::Transaction))?;
    let kind = discriminate_kind(&value)?;
    if kind != DocumentKind::Transaction {
        return Err(Diagnostic::new(
            DiagnosticCode::EKindUnknown,
            DocumentKindLabel::None,
            format!("expected transaction, got {kind:?}"),
        ));
    }
    schema_prepass(&value, DocumentKindLabel::Transaction)?;
    let doc: Document = serde_json::from_value(value.clone())
        .map_err(|e| map_serde_err(e, DocumentKindLabel::Transaction))?;
    let tx = match doc {
        Document::Transaction(t) => t,
        _ => unreachable!("Stage 4 already discriminated as transaction"),
    };
    validate_transaction(&tx)?;
    Ok((tx, value))
}

// -----------------------------------------------------------------------------
// Public per-kind validators (post-deserialize)
// -----------------------------------------------------------------------------

/// Run Stage 5 schema/range/syntax checks on a typed [`Manifest`] (e.g.,
/// after manual construction).
///
/// `now` is the local wall-clock time used for the §06 / §10 clock-skew
/// check on `manifest.updated`.
///
/// # Errors
///
/// Returns the first applicable Stage 5 diagnostic.
pub fn validate_manifest(manifest: &Manifest, now: &EntangledTimestamp) -> Result<(), Diagnostic> {
    validate_manifest_fields(
        manifest.min_refresh_interval,
        &manifest.navigation,
        &manifest.state_policy,
        &manifest.canary,
        &manifest.updated,
        now,
    )?;
    validate_origin_not_after(&manifest.origin, &manifest.canary)?;
    if let Some(mp) = &manifest.migration_pointer {
        validate_migration_pointer(mp, &manifest.origin, &manifest.updated)?;
    }
    Ok(())
}

/// Run Stage 5 schema/range/syntax checks on a typed [`ContentDocument`].
///
/// # Errors
///
/// Returns the first applicable Stage 5 diagnostic.
pub fn validate_content(doc: &ContentDocument) -> Result<(), Diagnostic> {
    validate_content_fields(&doc.meta, &doc.blocks, doc.seq)
}

/// Run Stage 5 schema/range/syntax checks on a typed
/// [`TransactionDocument`].
///
/// # Errors
///
/// Returns the first applicable Stage 5 diagnostic.
pub fn validate_transaction(doc: &TransactionDocument) -> Result<(), Diagnostic> {
    validate_transaction_fields(&doc.blocks, &doc.state_updates)
}

/// Stage 5 checks shared between [`validate_manifest`] and
/// [`crate::document::unsigned::UnsignedManifest`]: range, length, and syntax
/// of the post-deserialize fields that do not depend on the signature.
///
/// `updated` is passed separately because this validator is also called
/// pre-signing from `UnsignedManifest`, where the field lives on the
/// unsigned struct (there is no `Manifest` to borrow from yet). `now` is
/// the wall-clock reference for the §06 clock-skew check on `updated`.
pub(crate) fn validate_manifest_fields(
    min_refresh_interval: u32,
    navigation: &[NavEntry],
    state_policy: &[StatePolicyEntry],
    canary: &Canary,
    updated: &EntangledTimestamp,
    now: &EntangledTimestamp,
) -> Result<(), Diagnostic> {
    // §06: reject `updated` more than 300s in the future. Run this early so a
    // grossly misdated manifest is rejected before more expensive structural
    // walks (state_policy, navigation, canary).
    check_future_timestamp(
        updated,
        now,
        "manifest.updated",
        DocumentKindLabel::Manifest,
    )?;

    if !MIN_REFRESH_INTERVAL_RANGE.contains(&min_refresh_interval) {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldRange,
            DocumentKindLabel::Manifest,
            format!(
                "min_refresh_interval {} out of range {}..={}",
                min_refresh_interval,
                MIN_REFRESH_INTERVAL_RANGE.start(),
                MIN_REFRESH_INTERVAL_RANGE.end()
            ),
        ));
    }

    if navigation.len() > MAX_NAVIGATION_ENTRIES {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldLength,
            DocumentKindLabel::Manifest,
            format!(
                "navigation has {} entries, max is {MAX_NAVIGATION_ENTRIES}",
                navigation.len()
            ),
        ));
    }
    for nav in navigation {
        if nav.label.len() > NAVIGATION_LABEL_MAX_BYTES {
            return Err(Diagnostic::new(
                DiagnosticCode::ESchemaFieldLength,
                DocumentKindLabel::Manifest,
                format!(
                    "navigation label of {} bytes exceeds cap of {NAVIGATION_LABEL_MAX_BYTES}",
                    nav.label.len()
                ),
            ));
        }
        if !no_control_chars(&nav.label, false) {
            return Err(Diagnostic::new(
                DiagnosticCode::ESchemaFieldSyntax,
                DocumentKindLabel::Manifest,
                "navigation label contains control characters",
            ));
        }
        // §04 (rc.13): user-visible strings MUST be NFC.
        check_nfc(&nav.label, "navigation.label", DocumentKindLabel::Manifest)?;
    }

    validate_state_policy(state_policy)?;

    // Canary structural string limits. Interval bounds and `issued_at` future
    // checks are Stage 8 (later phase).
    if canary.statement.len() > CANARY_STATEMENT_MAX_BYTES {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldLength,
            DocumentKindLabel::Manifest,
            format!(
                "canary.statement of {} bytes exceeds cap of {CANARY_STATEMENT_MAX_BYTES}",
                canary.statement.len()
            ),
        ));
    }
    if !no_control_chars(&canary.statement, true) {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldSyntax,
            DocumentKindLabel::Manifest,
            "canary.statement contains control characters other than line feed",
        ));
    }
    // §04 (rc.13): user-visible strings MUST be NFC.
    check_nfc(
        &canary.statement,
        "canary.statement",
        DocumentKindLabel::Manifest,
    )?;
    if let Some(fp) = &canary.freshness_proof {
        if fp.is_empty() {
            return Err(Diagnostic::new(
                DiagnosticCode::ESchemaFieldSyntax,
                DocumentKindLabel::Manifest,
                "canary.freshness_proof, when present, must not be empty",
            ));
        }
        if fp.len() > CANARY_FRESHNESS_PROOF_MAX_BYTES {
            return Err(Diagnostic::new(
                DiagnosticCode::ESchemaFieldLength,
                DocumentKindLabel::Manifest,
                format!(
                    "canary.freshness_proof of {} bytes exceeds cap of {CANARY_FRESHNESS_PROOF_MAX_BYTES}",
                    fp.len()
                ),
            ));
        }
        if !no_control_chars(fp, false) {
            return Err(Diagnostic::new(
                DiagnosticCode::ESchemaFieldSyntax,
                DocumentKindLabel::Manifest,
                "canary.freshness_proof contains control characters",
            ));
        }
        // §08 explicit NFC rule (rc.19 N59): the user-visible
        // `freshness_proof` is subject to the §04 NFC requirement.
        check_nfc(fp, "canary.freshness_proof", DocumentKindLabel::Manifest)?;
    }

    Ok(())
}

/// Validate a manifest's `migration_pointer` block (§06 v1.0-rc.13;
/// successor-shape tightening in v1.0-rc.14).
///
/// Per §06 the announcement is structurally well-formed if and only if:
///
/// * `successor_origin` carries no `not_after`. The successor pointer
///   schema has exactly three fields (`carrier`, `address`,
///   `origin_pubkey`) per §06; `not_after` belongs to the successor's
///   own manifest, fetched and verified at Stage 9 (rc.14 addition).
/// * `successor_origin.address` differs from the announcing
///   `origin.address` (no self-pointing migration);
/// * `successor_origin.carrier` equals the announcing `origin.carrier`
///   (cross-carrier migration is out of scope for v1.0; in v1.0 only
///   `tor-v3` exists, so this is automatic for well-formed manifests but
///   the rule is normative);
/// * `announced_at` is not later than the announcing manifest's `updated`
///   (the publisher cannot retroactively post-date an announcement).
///
/// All four failures are reported as `E_MIGRATION_INVALID` (§11 rc.13,
/// row extended in rc.14). The structural well-formedness check fires
/// before `verify_migration_announcement`, which compares publisher
/// pubkeys across the announcing and successor manifests after both
/// have cleared their own pipeline. The per-flow chain-cycle check is
/// a separate Stage 9 concern handled by
/// [`crate::validation::check_migration_chain_cycle`].
pub fn validate_migration_pointer(
    mp: &MigrationPointer,
    announcing_origin: &Origin,
    announcing_updated: &EntangledTimestamp,
) -> Result<(), Diagnostic> {
    if mp.successor_origin.not_after.is_some() {
        // §06:373 (v1.0-rc.14): `successor_origin` has exactly three
        // fields (carrier, address, origin_pubkey). `not_after` is a
        // closed-schema violation for the successor pointer (it belongs
        // to the successor's own manifest, fetched and verified at
        // Stage 9). The shared `Origin` type carries `not_after` as
        // optional because the top-level `origin` may declare it; the
        // closed-shape constraint on the successor pointer is enforced
        // here. Reported as `E_SCHEMA_UNKNOWN_FIELD` rather than
        // `E_MIGRATION_INVALID` to stay within the §11 N57 closed-enum
        // `details.reason` vocabulary for the latter code.
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaUnknownField,
            DocumentKindLabel::Manifest,
            "migration_pointer.successor_origin must not carry not_after",
        )
        .with_details(serde_json::json!({
            "field_path": "migration_pointer.successor_origin.not_after",
        })));
    }
    if mp.successor_origin.address == announcing_origin.address {
        // rc.19 N57: identifier renamed `self_pointing_migration` ->
        // `self_pointer` to match the §11 closed-enum vocabulary.
        return Err(Diagnostic::new(
            DiagnosticCode::EMigrationInvalid,
            DocumentKindLabel::Manifest,
            "migration_pointer.successor_origin.address must differ from origin.address",
        )
        .with_details(serde_json::json!({
            "field_path": "migration_pointer.successor_origin.address",
            "reason": "self_pointer",
            "announcing_origin_address": announcing_origin.address.as_str(),
            "successor_origin_address": mp.successor_origin.address.as_str(),
        })));
    }
    if mp.successor_origin.carrier != announcing_origin.carrier {
        return Err(Diagnostic::new(
            DiagnosticCode::EMigrationInvalid,
            DocumentKindLabel::Manifest,
            "migration_pointer.successor_origin.carrier must equal origin.carrier",
        )
        .with_details(serde_json::json!({
            "field_path": "migration_pointer.successor_origin.carrier",
            "reason": "carrier_mismatch",
            "announcing_origin_address": announcing_origin.address.as_str(),
            "successor_origin_address": mp.successor_origin.address.as_str(),
        })));
    }
    if mp.announced_at > *announcing_updated {
        // rc.19 N57: identifier renamed `announced_after_updated` ->
        // `announced_at_after_updated` to match the §11 vocabulary.
        return Err(Diagnostic::new(
            DiagnosticCode::EMigrationInvalid,
            DocumentKindLabel::Manifest,
            "migration_pointer.announced_at must not be later than manifest.updated",
        )
        .with_details(serde_json::json!({
            "field_path": "migration_pointer.announced_at",
            "reason": "announced_at_after_updated",
            "announcing_origin_address": announcing_origin.address.as_str(),
            "successor_origin_address": mp.successor_origin.address.as_str(),
        })));
    }
    Ok(())
}

/// Validate `origin.not_after` against `canary.issued_at` (§06 v1.0-rc.14).
///
/// When `origin.not_after` is absent the helper returns `Ok(())` — declaring
/// no publisher-side expiration is the steady-state shape. When present the
/// helper enforces the two `MUST` constraints from §06:
///
/// * `not_after` MUST be strictly later than `canary.issued_at`. An
///   expiration at or before issuance is ill-formed.
/// * `not_after` MUST NOT be more than five years
///   ([`ORIGIN_NOT_AFTER_MAX_HORIZON_SECS`] seconds) after
///   `canary.issued_at`. The ceiling bounds the maximum window during
///   which a compromised `K_origin` can serve cached clients of an
///   unrotated origin.
///
/// The `SHOULD` constraint ("strictly later than `canary.next_expected`") is
/// not enforced as a Stage 5 reject per §06; an implementation MAY surface
/// it as a warning at a higher layer, but the spec explicitly permits it.
///
/// Failures are reported as `E_ORIGIN_INVALID` with `details.reason` set to
/// the §11 vocabulary (`not_after_not_later_than_issued_at` or
/// `not_after_beyond_5y`), plus the offending `not_after` and the
/// `canary.issued_at` it was compared against. The identifier was renamed
/// from `not_after_not_after_issued_at` (typo) in v1.0-rc.19 (N56).
pub fn validate_origin_not_after(origin: &Origin, canary: &Canary) -> Result<(), Diagnostic> {
    let Some(not_after) = origin.not_after else {
        return Ok(());
    };

    if not_after <= canary.issued_at {
        return Err(Diagnostic::new(
            DiagnosticCode::EOriginInvalid,
            DocumentKindLabel::Manifest,
            "origin.not_after must be strictly later than canary.issued_at",
        )
        .with_details(serde_json::json!({
            "field_path": "origin.not_after",
            "reason": "not_after_not_later_than_issued_at",
            "not_after": not_after.to_string(),
            "issued_at": canary.issued_at.to_string(),
        })));
    }

    let horizon = not_after.unix_timestamp() - canary.issued_at.unix_timestamp();
    if horizon > ORIGIN_NOT_AFTER_MAX_HORIZON_SECS {
        return Err(Diagnostic::new(
            DiagnosticCode::EOriginInvalid,
            DocumentKindLabel::Manifest,
            "origin.not_after must not be more than 5 years after canary.issued_at",
        )
        .with_details(serde_json::json!({
            "field_path": "origin.not_after",
            "reason": "not_after_beyond_5y",
            "not_after": not_after.to_string(),
            "issued_at": canary.issued_at.to_string(),
            "horizon_seconds": horizon,
            "max_horizon_seconds": ORIGIN_NOT_AFTER_MAX_HORIZON_SECS,
        })));
    }

    Ok(())
}

pub(crate) fn validate_content_fields(
    meta: &Meta,
    blocks: &[Block],
    seq: Option<u64>,
) -> Result<(), Diagnostic> {
    if let Some(s) = seq {
        if s < 1 {
            return Err(Diagnostic::new(
                DiagnosticCode::ESchemaFieldRange,
                DocumentKindLabel::Content,
                "seq must be at least 1",
            ));
        }
    }
    if meta.title.len() > META_TITLE_MAX_BYTES {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldLength,
            DocumentKindLabel::Content,
            format!(
                "meta.title of {} bytes exceeds cap of {META_TITLE_MAX_BYTES}",
                meta.title.len()
            ),
        ));
    }
    if !no_control_chars(&meta.title, false) {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldSyntax,
            DocumentKindLabel::Content,
            "meta.title contains control characters",
        ));
    }
    // §04 (rc.13): user-visible strings MUST be NFC.
    check_nfc(&meta.title, "meta.title", DocumentKindLabel::Content)?;

    if blocks.is_empty() {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaRequiredField,
            DocumentKindLabel::Content,
            "content blocks must contain at least one block",
        ));
    }
    if blocks.len() > MAX_BLOCKS_CONTENT {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldLength,
            DocumentKindLabel::Content,
            format!(
                "content blocks has {} entries, max is {MAX_BLOCKS_CONTENT}",
                blocks.len()
            ),
        ));
    }

    validate_blocks(blocks, DocumentKind::Content)
}

pub(crate) fn validate_transaction_fields(
    blocks: &[Block],
    state_updates: &[StateUpdateOp],
) -> Result<(), Diagnostic> {
    if blocks.is_empty() {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaRequiredField,
            DocumentKindLabel::Transaction,
            "transaction must contain at least one block",
        ));
    }
    if blocks.len() > MAX_BLOCKS_TRANSACTION {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldLength,
            DocumentKindLabel::Transaction,
            format!(
                "transaction blocks has {} entries, max is {MAX_BLOCKS_TRANSACTION}",
                blocks.len()
            ),
        ));
    }

    validate_blocks(blocks, DocumentKind::Transaction)?;
    validate_state_updates_standalone(state_updates)?;
    Ok(())
}

// -----------------------------------------------------------------------------
// Pre-pass over the parsed Value
// -----------------------------------------------------------------------------

/// Detects `null` literals and out-of-grammar numbers anywhere in the
/// document. §04 v1.0-rc.5: floats and integers outside the 64-bit signed
/// range are rejected lexically with `E_SCHEMA_NON_INTEGER` before any
/// schema-level type/range check fires.
fn schema_prepass(root: &Value, kind: DocumentKindLabel) -> Result<(), Diagnostic> {
    let mut stack: Vec<&Value> = vec![root];
    while let Some(node) = stack.pop() {
        match node {
            Value::Null => {
                return Err(Diagnostic::new(
                    DiagnosticCode::ESchemaNullValue,
                    kind,
                    "null literal is not permitted",
                ));
            }
            Value::Number(n) if n.is_f64() => {
                return Err(Diagnostic::new(
                    DiagnosticCode::ESchemaNonInteger,
                    kind,
                    format!("non-integer numeric value: {n}"),
                ));
            }
            // §04 v1.0-rc.5: the protocol's integer grammar is 64-bit
            // signed. Values strictly above i64::MAX (e.g. 2^63 written as
            // a JSON literal) are not representable in the grammar; they
            // are reported as `E_SCHEMA_NON_INTEGER` at Stage 5 — the
            // rejection precedes serde's per-field range narrowing
            // (`u32::deserialize`) so the diagnostic matches the lexical
            // failure rather than a downstream field-range failure.
            Value::Number(n) if n.as_i64().is_none() && !n.is_f64() => {
                return Err(Diagnostic::new(
                    DiagnosticCode::ESchemaNonInteger,
                    kind,
                    format!("integer literal {n} exceeds the 64-bit signed range"),
                ));
            }
            Value::Array(arr) => {
                for v in arr {
                    stack.push(v);
                }
            }
            Value::Object(map) => {
                for v in map.values() {
                    stack.push(v);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

fn set_kind(mut d: Diagnostic, kind: DocumentKindLabel) -> Diagnostic {
    d.document_kind = kind;
    d
}

/// Maps a `serde_json::Error` produced while deserializing a validated
/// `Value` into a Stage 5 `Diagnostic`. Distinguishes the canonical
/// "missing field", "unknown field", and "invalid type" forms; classifies
/// custom errors emitted by Phase 1 newtypes by phrase matching.
fn map_serde_err(err: serde_json::Error, kind: DocumentKindLabel) -> Diagnostic {
    let msg = err.to_string();

    let code = if msg.contains("missing field") {
        DiagnosticCode::ESchemaRequiredField
    } else if msg.contains("unknown field") {
        DiagnosticCode::ESchemaUnknownField
    } else if msg.contains("unknown variant") {
        // serde reports a closed-enum miss (e.g. block `kind: "marquee"`,
        // unknown state-policy `mode`, unknown feedback `variant`) as
        // "unknown variant". §11 (rc.9) classifies this as
        // `E_SCHEMA_ENUM_VIOLATION`, distinct from purely syntactic field
        // violations (`E_SCHEMA_FIELD_SYNTAX`).
        DiagnosticCode::ESchemaEnumViolation
    } else if msg.contains("invalid type") {
        DiagnosticCode::ESchemaFieldType
    } else if is_range_message(&msg) {
        DiagnosticCode::ESchemaFieldRange
    } else if is_syntax_message(&msg) {
        // §04 / §11 (rc.9): base64url and ASCII-fixed-form length violations
        // (e.g. a 43-char `sig` instead of 86) are reported at Stage 5 as
        // `E_SCHEMA_FIELD_SYNTAX`, not `E_SCHEMA_FIELD_LENGTH`. The dedicated
        // length code is reserved for fields whose syntax permits a variable
        // size up to a declared cap (navigation labels, list aggregates,
        // submit-form arrays, etc.). Order matters here: detect base64url /
        // syntax messages before the generic length heuristic.
        DiagnosticCode::ESchemaFieldSyntax
    } else if is_length_message(&msg) {
        DiagnosticCode::ESchemaFieldLength
    } else {
        DiagnosticCode::ESchemaFieldType
    };

    Diagnostic::new(code, kind, msg.clone())
        .with_details(serde_json::json!({ "serde_message": msg }))
}

fn is_range_message(msg: &str) -> bool {
    msg.contains("must be in")
        || msg.contains("out of range")
        || msg.contains("out-of-range")
        || msg.contains("between")
}

fn is_length_message(msg: &str) -> bool {
    msg.contains("exceeds maximum length")
        || msg.contains("expected ")
            && (msg.contains("base64url characters") || msg.contains("ASCII characters"))
}

fn is_syntax_message(msg: &str) -> bool {
    // Phase 1 newtype error messages.
    msg.contains("slug")
        || msg.contains("path")
        || msg.contains("timestamp")
        || msg.contains("base64url")
        || msg.contains("onion")
        || msg.contains("spec_version")
}
