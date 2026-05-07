//! Policy-aware state update checks (§07).
//!
//! Stage 5 (`validate_state_updates_standalone`) covers the structural caps
//! that hold regardless of the manifest. This module is the cross-check
//! against the publisher's *current* `state_policy`: every `(namespace,
//! key)` referenced by an update must be declared, and `value`/`ttl` must
//! fit the per-entry caps in the manifest.

use std::collections::HashMap;

use crate::types::slug::Slug;
use crate::types::state::{StatePolicyEntry, StateUpdateOp};

use super::diagnostic::{Diagnostic, DiagnosticCode, DocumentKindLabel};
use super::limits::STATE_TTL_HARD_RANGE;

/// Cross-check `updates` against the manifest-declared `policy`.
///
/// Diagnostic codes (off-pipeline, §11):
/// - `E_STATE_UNDECLARED` — `(namespace, key)` not in `policy`.
/// - `E_STATE_VALUE_SIZE` — `value` exceeds policy `max_size`.
/// - `E_STATE_TTL` — `ttl` exceeds policy `max_lifetime`, or is outside
///   the absolute hard range `[300, 7_776_000]` reasserted here.
pub fn validate_state_updates_against_policy(
    updates: &[StateUpdateOp],
    policy: &[StatePolicyEntry],
) -> Result<(), Diagnostic> {
    // First-write-wins on duplicates. `validate_state_policy` already
    // rejects them at Stage 5; this reducer is defensive against a caller
    // that never ran the manifest validator.
    let mut policy_map: HashMap<(&Slug, &Slug), &StatePolicyEntry> =
        HashMap::with_capacity(policy.len());
    for e in policy {
        policy_map.entry((&e.namespace, &e.key)).or_insert(e);
    }

    for op in updates {
        match op {
            StateUpdateOp::Set {
                namespace,
                key,
                value,
                ttl,
            } => {
                let entry = policy_map.get(&(namespace, key)).ok_or_else(|| {
                    Diagnostic::new(
                        DiagnosticCode::EStateUndeclared,
                        DocumentKindLabel::Transaction,
                        format!(
                            "set on undeclared (namespace, key) = ({}, {})",
                            namespace.as_str(),
                            key.as_str()
                        ),
                    )
                })?;
                if value.len() > entry.max_size as usize {
                    return Err(Diagnostic::new(
                        DiagnosticCode::EStateValueSize,
                        DocumentKindLabel::Transaction,
                        format!(
                            "set value of {} bytes exceeds policy max_size {} for ({}, {})",
                            value.len(),
                            entry.max_size,
                            namespace.as_str(),
                            key.as_str()
                        ),
                    ));
                }
                if !STATE_TTL_HARD_RANGE.contains(ttl) {
                    return Err(Diagnostic::new(
                        DiagnosticCode::EStateTtl,
                        DocumentKindLabel::Transaction,
                        format!(
                            "set ttl {ttl} out of hard range {}..={}",
                            STATE_TTL_HARD_RANGE.start(),
                            STATE_TTL_HARD_RANGE.end()
                        ),
                    ));
                }
                if *ttl > entry.max_lifetime {
                    return Err(Diagnostic::new(
                        DiagnosticCode::EStateTtl,
                        DocumentKindLabel::Transaction,
                        format!(
                            "set ttl {} exceeds policy max_lifetime {} for ({}, {})",
                            ttl,
                            entry.max_lifetime,
                            namespace.as_str(),
                            key.as_str()
                        ),
                    ));
                }
            }
            StateUpdateOp::Delete { namespace, key } => {
                if !policy_map.contains_key(&(namespace, key)) {
                    return Err(Diagnostic::new(
                        DiagnosticCode::EStateUndeclared,
                        DocumentKindLabel::Transaction,
                        format!(
                            "delete on undeclared (namespace, key) = ({}, {})",
                            namespace.as_str(),
                            key.as_str()
                        ),
                    ));
                }
            }
        }
    }
    Ok(())
}
