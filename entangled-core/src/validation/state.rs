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
use crate::types::state::{StatePolicyEntry, StateUpdateOp};

use super::diagnostic::{Diagnostic, DiagnosticCode, DocumentKindLabel};
use super::limits::{
    MAX_STATE_POLICY_ENTRIES, MAX_STATE_UPDATES, STATE_MAX_LIFETIME_RANGE, STATE_MAX_SIZE_RANGE,
    STATE_PURPOSE_MAX_BYTES, STATE_TTL_HARD_RANGE, STATE_VALUE_MAX_BYTES,
};
use super::strings::{check_nfc, no_control_chars};

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
    Ok(())
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
