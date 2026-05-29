//! Stage 5 — standalone state validators (no policy lookup).
//!
//! Cross-checks against the manifest's declared `state_policy` (such as the
//! `(namespace, key)` declaration check or `value.len() <= max_size`) belong
//! to a later phase and require the current manifest at evaluation time.
//!
//! Note: an unknown `op` value in a state update produces a serde
//! deserialization error mapped to `E_SCHEMA_ENUM_VIOLATION` at Stage 5
//! (§11 closed-enum violation); the dedicated `E_STATE_OP` code is
//! reserved for state-update operation processing in later phases.

use std::collections::HashSet;

use crate::types::slug::Slug;
use crate::types::state::{StateMode, StatePolicyEntry, StateUpdateOp};

use super::diagnostic::{Diagnostic, DiagnosticCode, DocumentKindLabel};
use super::limits::{
    MAX_STATE_POLICY_ENTRIES, MAX_STATE_UPDATES, STATE_MAX_LIFETIME_RANGE, STATE_MAX_SIZE_RANGE,
    STATE_PURPOSE_MAX_BYTES, STATE_TTL_HARD_RANGE, STATE_VALUE_MAX_BYTES,
    SUBMIT_STATE_BUDGET_BYTES,
};
use super::strings::{check_nfc, no_control_chars};

/// Fixed JSON envelope of a single `request_state` entry, excluding the
/// `namespace` value, the `key` value, and the `value` value but including
/// all surrounding quoting and structural punctuation.
///
/// Counted from the literal entry shape used in the §09 partition and the
/// corpus accounting:
///
/// ```text
/// {"namespace":"...","key":"...","value":"..."}
/// ```
///
/// `{"namespace":"` = 14, `","key":"` = 9, `","value":"` = 11, `"}` = 2.
/// Total = 36 bytes (assuming `namespace`/`key`/`value` contain no
/// JSON-escape-bearing characters; slug syntax guarantees this for
/// `namespace` and `key`).
pub const REQUEST_STATE_ENTRY_ENVELOPE_BYTES: usize = 36;

/// Encoded wire contribution of a single `request_state` entry given the
/// concrete byte lengths of `namespace`, `key`, and `value` — i.e. the
/// JSON shape `{"namespace":"...","key":"...","value":"..."}` measured
/// on the wire. Used by:
///
/// * the Stage 5 N62 satisfiability invariant
///   ([`validate_state_policy`]), where `value_bytes` is the entry's
///   declared `max_size`;
/// * the runtime [`crate::state::StateStore`] transmit-budget check
///   ([`E_STATE_TRANSMIT_BUDGET`](crate::validation::DiagnosticCode::EStateTransmitBudget)),
///   where `value_bytes` is the actual `value.len()` retained.
///
/// `value_bytes` is a raw UTF-8 byte length in both call sites: the
/// declared `max_size` (also a raw UTF-8 byte length per §07 max_size,
/// rc.24 AMB-08) at Stage 5, and `String::len()` (UTF-8 bytes) at
/// runtime. The `value` is NOT JSON-escape-expanded here. The fixed
/// 36-byte envelope assumes `namespace`/`key`/`value` carry no
/// escape-bearing characters; slug syntax guarantees this for
/// `namespace` and `key`, and the Stage 5 aggregate is an envelope-level
/// necessary bound that does not escape-expand the value (the runtime
/// `E_STATE_TRANSMIT_BUDGET` check is where actual escaped wire bytes
/// are accounted; rc.24 §09 "Submit body budget partition").
///
/// [`E_STATE_TRANSMIT_BUDGET`]: crate::validation::DiagnosticCode::EStateTransmitBudget
#[must_use]
pub fn encoded_request_state_entry_bytes(
    namespace_bytes: usize,
    key_bytes: usize,
    value_bytes: usize,
) -> usize {
    REQUEST_STATE_ENTRY_ENVELOPE_BYTES + namespace_bytes + key_bytes + value_bytes
}

/// Validate a manifest's `state_policy` array (Stage 5).
///
/// Checks the array cap, per-entry numeric ranges, purpose length and
/// syntax, and uniqueness of `(namespace, key)` pairs.
///
/// # Errors
///
/// Returns the first applicable Stage 5 diagnostic.
pub fn validate_state_policy(policy: &[StatePolicyEntry]) -> Result<(), Diagnostic> {
    if policy.len() > MAX_STATE_POLICY_ENTRIES {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldLength,
            DocumentKindLabel::Manifest,
            format!(
                "state_policy has {} entries, max is {MAX_STATE_POLICY_ENTRIES}",
                policy.len()
            ),
        ));
    }
    let mut seen: HashSet<(&Slug, &Slug)> = HashSet::with_capacity(policy.len());
    for e in policy {
        if !seen.insert((&e.namespace, &e.key)) {
            return Err(Diagnostic::new(
                DiagnosticCode::ESchemaDuplicateEntry,
                DocumentKindLabel::Manifest,
                "duplicate (namespace, key) in state_policy",
            )
            .with_details(serde_json::json!({
                "field_path": "state_policy",
                "duplicate_namespace": e.namespace.as_str(),
                "duplicate_key": e.key.as_str(),
            })));
        }
        if !STATE_MAX_SIZE_RANGE.contains(&e.max_size) {
            return Err(Diagnostic::new(
                DiagnosticCode::ESchemaFieldRange,
                DocumentKindLabel::Manifest,
                format!(
                    "state_policy.max_size {} out of range {}..={}",
                    e.max_size,
                    STATE_MAX_SIZE_RANGE.start(),
                    STATE_MAX_SIZE_RANGE.end()
                ),
            ));
        }
        if !STATE_MAX_LIFETIME_RANGE.contains(&e.max_lifetime) {
            return Err(Diagnostic::new(
                DiagnosticCode::ESchemaFieldRange,
                DocumentKindLabel::Manifest,
                format!(
                    "state_policy.max_lifetime {} out of range {}..={}",
                    e.max_lifetime,
                    STATE_MAX_LIFETIME_RANGE.start(),
                    STATE_MAX_LIFETIME_RANGE.end()
                ),
            ));
        }
        if e.purpose.len() > STATE_PURPOSE_MAX_BYTES {
            return Err(Diagnostic::new(
                DiagnosticCode::ESchemaFieldLength,
                DocumentKindLabel::Manifest,
                format!(
                    "state_policy.purpose of {} bytes exceeds cap of {STATE_PURPOSE_MAX_BYTES}",
                    e.purpose.len()
                ),
            ));
        }
        // §07: purpose MUST NOT contain control chars in U+0000..=U+001F or
        // U+007F. Line feed is part of that range and is therefore rejected.
        if !no_control_chars(&e.purpose, false) {
            return Err(Diagnostic::new(
                DiagnosticCode::ESchemaFieldSyntax,
                DocumentKindLabel::Manifest,
                "state_policy.purpose contains control characters",
            ));
        }
        // §04 (rc.13): user-visible strings MUST be NFC.
        check_nfc(
            &e.purpose,
            "state_policy.purpose",
            DocumentKindLabel::Manifest,
        )?;
    }

    // §07 / §09 submit budget satisfiability (rc.21 N62). Aggregate the
    // worst-case encoded wire contribution of every `mode = request` entry
    // as if each held a value at its declared `max_size`. Reject when the
    // aggregate exceeds `SUBMIT_STATE_BUDGET_BYTES`. Client-only entries
    // do not contribute (they are never transmitted).
    let declared_bytes = aggregate_request_state_bytes(policy);
    if declared_bytes > SUBMIT_STATE_BUDGET_BYTES {
        return Err(Diagnostic::new(
            DiagnosticCode::ESubmitBudget,
            DocumentKindLabel::Manifest,
            format!(
                "state_policy aggregate worst-case wire contribution {declared_bytes} \
                 bytes exceeds the {SUBMIT_STATE_BUDGET_BYTES}-byte state_budget",
            ),
        )
        .with_details(serde_json::json!({
            "component": "state",
            "declared_bytes": declared_bytes,
            "budget_bytes": SUBMIT_STATE_BUDGET_BYTES,
        })));
    }

    Ok(())
}

/// Compute the worst-case encoded wire contribution of a `state_policy`
/// to the `request_state` array of a submit body (§07 v1.0-rc.21, N62).
///
/// Per the §09 partition, contribution is measured in encoded JSON bytes:
/// for each `mode = request` entry, the fixed entry-shape envelope plus
/// the `namespace`, `key`, and worst-case `value` byte lengths, plus a
/// single array-delimiter comma between successive entries. Client-only
/// entries do not contribute.
fn aggregate_request_state_bytes(policy: &[StatePolicyEntry]) -> usize {
    let mut total: usize = 0;
    let mut request_entries: usize = 0;
    for e in policy {
        if e.mode != StateMode::Request {
            continue;
        }
        let entry_bytes = encoded_request_state_entry_bytes(
            e.namespace.as_str().len(),
            e.key.as_str().len(),
            e.max_size as usize,
        );
        total = total.saturating_add(entry_bytes);
        request_entries += 1;
    }
    if request_entries > 1 {
        total = total.saturating_add(request_entries - 1);
    }
    total
}

/// Standalone validation of a transaction's `state_updates` array (no
/// policy lookup).
///
/// Enforces the array cap and the absolute hard ranges on `value` length and
/// `ttl`. Cross-checks against the manifest's declared `state_policy` happen
/// in [`crate::validation::policy_check`].
///
/// # Errors
///
/// Returns the first applicable diagnostic
/// (`E_SCHEMA_FIELD_LENGTH`, `E_STATE_VALUE_SIZE`, or `E_STATE_TTL`).
pub fn validate_state_updates_standalone(updates: &[StateUpdateOp]) -> Result<(), Diagnostic> {
    if updates.len() > MAX_STATE_UPDATES {
        return Err(Diagnostic::new(
            DiagnosticCode::ESchemaFieldLength,
            DocumentKindLabel::Transaction,
            format!(
                "state_updates has {} entries, max is {MAX_STATE_UPDATES}",
                updates.len()
            ),
        ));
    }
    for op in updates {
        match op {
            StateUpdateOp::Set { value, ttl, .. } => {
                if value.len() > STATE_VALUE_MAX_BYTES {
                    return Err(Diagnostic::new(
                        DiagnosticCode::EStateValueSize,
                        DocumentKindLabel::Transaction,
                        format!(
                            "state set value of {} bytes exceeds hard ceiling of {STATE_VALUE_MAX_BYTES}",
                            value.len()
                        ),
                    ));
                }
                if !STATE_TTL_HARD_RANGE.contains(ttl) {
                    return Err(Diagnostic::new(
                        DiagnosticCode::EStateTtl,
                        DocumentKindLabel::Transaction,
                        format!(
                            "state set ttl {ttl} out of hard range {}..={}",
                            STATE_TTL_HARD_RANGE.start(),
                            STATE_TTL_HARD_RANGE.end()
                        ),
                    ));
                }
            }
            StateUpdateOp::Delete { .. } => {
                // Structural validation only; namespace/key already checked
                // by the Slug newtype during deserialization.
            }
        }
    }
    Ok(())
}
