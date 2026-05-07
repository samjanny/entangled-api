//! State policy entries and update operations (§07).

use serde::{Deserialize, Serialize};

use super::slug::Slug;

/// Whether a state-policy entry is client-only or also sent on submit (§07).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateMode {
    /// State stays on the client; never sent to the publisher.
    ClientOnly,
    /// State is included in submit-body requests when the publisher requests
    /// it.
    Request,
}

/// One entry in a manifest's `state_policy` (§07).
///
/// Each entry declares a `(namespace, key)` slot together with the mode,
/// per-value byte cap, lifetime cap, and a human-readable purpose string.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatePolicyEntry {
    /// Namespace slug. Combined with `key` to form the slot identity.
    pub namespace: Slug,
    /// Key slug within the namespace.
    pub key: Slug,
    /// Whether this slot may be sent on submit, or stays client-only.
    pub mode: StateMode,
    /// Maximum byte length of stored values.
    pub max_size: u32,
    /// Maximum lifetime in seconds (TTL ceiling).
    pub max_lifetime: u32,
    /// Human-readable purpose string shown in consent prompts.
    pub purpose: String,
}

/// State update operation requested by the publisher in a transaction (§07).
///
/// The wire form is tagged by `op` (not `kind`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum StateUpdateOp {
    /// Set or replace the value at `(namespace, key)` with TTL `ttl`.
    Set {
        /// Namespace slug.
        namespace: Slug,
        /// Key slug within the namespace.
        key: Slug,
        /// New value (must satisfy the policy `max_size`).
        value: String,
        /// Time-to-live in seconds (must satisfy the policy `max_lifetime`).
        ttl: u32,
    },
    /// Delete any existing value at `(namespace, key)`.
    Delete {
        /// Namespace slug.
        namespace: Slug,
        /// Key slug within the namespace.
        key: Slug,
    },
}
