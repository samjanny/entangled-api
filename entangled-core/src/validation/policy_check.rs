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

type PolicyMap<'a> = HashMap<(&'a Slug, &'a Slug), &'a StatePolicyEntry>;

fn build_policy_map(policy: &[StatePolicyEntry]) -> PolicyMap<'_> {
    // First-write-wins on duplicates. `validate_state_policy` already
    // rejects them at Stage 5; this reducer is defensive against a caller
    // that never ran the manifest validator.
    let mut policy_map: PolicyMap<'_> = HashMap::with_capacity(policy.len());
    for e in policy {
        policy_map.entry((&e.namespace, &e.key)).or_insert(e);
    }
    policy_map
}

fn check_op<'a>(
    op: &StateUpdateOp,
    policy_map: &PolicyMap<'a>,
) -> Result<&'a StatePolicyEntry, Diagnostic> {
    match op {
        StateUpdateOp::Set {
            namespace,
            key,
            value,
            ttl,
        } => {
            let entry = *policy_map.get(&(namespace, key)).ok_or_else(|| {
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
            Ok(entry)
        }
        StateUpdateOp::Delete { namespace, key } => {
            let entry = *policy_map.get(&(namespace, key)).ok_or_else(|| {
                Diagnostic::new(
                    DiagnosticCode::EStateUndeclared,
                    DocumentKindLabel::Transaction,
                    format!(
                        "delete on undeclared (namespace, key) = ({}, {})",
                        namespace.as_str(),
                        key.as_str()
                    ),
                )
            })?;
            Ok(entry)
        }
    }
}

/// Cross-check a single `op` against the manifest-declared `policy`, and
/// return the matched `StatePolicyEntry` borrowed from `policy`.
///
/// Returning the matched entry lets callers (e.g.
/// [`crate::state::StateStore::set_with_policy`]) read the entry's `mode`
/// without re-walking `policy`, and removes the otherwise-needed runtime
/// assertion that the entry exists.
///
/// Diagnostic codes are the same as
/// [`validate_state_updates_against_policy`].
pub fn validate_state_update_against_policy<'a>(
    op: &StateUpdateOp,
    policy: &'a [StatePolicyEntry],
) -> Result<&'a StatePolicyEntry, Diagnostic> {
    let policy_map = build_policy_map(policy);
    check_op(op, &policy_map)
}

/// Cross-check `updates` against the manifest-declared `policy`, returning
/// the matched `StatePolicyEntry` for each op (aligned 1:1 with `updates`,
/// borrowed from `policy`).
///
/// Diagnostic codes (off-pipeline, §11):
/// - `E_STATE_UNDECLARED` — `(namespace, key)` not in `policy`.
/// - `E_STATE_VALUE_SIZE` — `value` exceeds policy `max_size`.
/// - `E_STATE_TTL` — `ttl` exceeds policy `max_lifetime`, or is outside
///   the absolute hard range `[300, 7_776_000]` reasserted here.
pub fn validate_state_updates_against_policy<'a>(
    updates: &[StateUpdateOp],
    policy: &'a [StatePolicyEntry],
) -> Result<Vec<&'a StatePolicyEntry>, Diagnostic> {
    let policy_map = build_policy_map(policy);
    let mut out = Vec::with_capacity(updates.len());
    for op in updates {
        out.push(check_op(op, &policy_map)?);
    }
    Ok(out)
}
