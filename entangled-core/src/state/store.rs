//! Client-side state store (§07).
//!
//! Keys are `(K_publisher.pub, namespace, key)`. Per-publisher isolation,
//! mode preservation at commit time, lazy expiration, and a per-publisher
//! storage cap are enforced here. Consent UX is the client's
//! responsibility; this module accepts a [`ConsentDecision`] as input.

use std::collections::HashMap;

use time::Duration;

use crate::types::keys::{PublisherPubkey, RuntimePubkey};
use crate::types::slug::Slug;
use crate::types::state::{StateMode, StatePolicyEntry, StateUpdateOp};
use crate::types::timestamp::EntangledTimestamp;
use crate::validation::diagnostic::{Diagnostic, DiagnosticCode, DocumentKindLabel};
use crate::validation::limits::{SUBMIT_BODY_MAX_BYTES, SUBMIT_OVERHEAD_RESERVE_BYTES};
use crate::validation::policy_check::validate_state_update_against_policy;

/// One state entry, as stored client-side. The `mode` is preserved from the
/// time of commit and never silently rewritten when `state_policy` changes
/// (§07 "Mode change").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateEntry {
    /// Stored value as it was committed.
    pub value: String,
    /// Mode resolved from the manifest's `state_policy` at commit time.
    pub mode: StateMode,
    /// Wall-clock time at which this entry expires.
    pub expires_at: EntangledTimestamp,
    /// Wall-clock time at which the user gave consent for this entry.
    pub consent_at: EntangledTimestamp,
    /// Whether the user opted to remember this consent for future writes
    /// to the same `(publisher, namespace, key)` triple.
    pub remembered_consent: bool,
    /// `canary.runtime_pubkey` of the manifest that authorized this
    /// commit (§07 rc.19 N53). When the publisher subsequently rotates
    /// to a different `K_runtime`, [`StateStore::mark_runtime_superseded`]
    /// flips [`Self::runtime_superseded`] on every entry whose
    /// `authorizing_runtime_pubkey` does not match the new one.
    pub authorizing_runtime_pubkey: RuntimePubkey,
    /// `true` once the authorizing `K_runtime` has been superseded by a
    /// subsequent canary rotation (§07 rc.19 N53). A superseded
    /// request-mode entry MUST NOT be included in submit requests but
    /// MUST be retained until its natural `expires_at` for user
    /// inspection and deletion. The flag does not affect client-only
    /// entries, which are never transmitted.
    pub runtime_superseded: bool,
}

/// User decision delivered to the store. The store does not run the consent
/// UX; it only commits or refuses based on this input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsentDecision {
    /// Whether the user accepted the proposed write.
    pub accepted: bool,
    /// Whether to mark the resulting entry as having remembered consent.
    pub remembered: bool,
}

/// Per-publisher byte cap enforced before each set. §07 "Storage limits".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageCap {
    /// Maximum total bytes across all entries belonging to one publisher.
    pub bytes_per_publisher: usize,
}

impl Default for StorageCap {
    /// 256 KiB per publisher. §07 requires the cap be at least sufficient to
    /// hold the maximum allowed state for the current policy
    /// (`sum(max_size)` across all entries). The protocol-wide ceiling is
    /// 32 entries × 4096 bytes = 128 KiB of value bytes; this store also
    /// charges namespace and key bytes against the cap, so 256 KiB leaves
    /// headroom for that overhead while still satisfying the lower bound on
    /// any conforming policy. Callers that want a tighter or looser cap
    /// construct the store via [`StateStore::with_cap`].
    fn default() -> Self {
        Self {
            bytes_per_publisher: 256 * 1024,
        }
    }
}

/// Result of a `set` call. Storage failure is `Err`; user rejection is
/// `Ok(Rejected)` because a refused consent is not a protocol error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetOutcome {
    /// Set was committed.
    Committed {
        /// Whether the consent was recorded as "remembered".
        remembered: bool,
    },
    /// User declined to consent; nothing was written.
    Rejected,
}

#[derive(Clone, Hash, PartialEq, Eq)]
struct StoreKey {
    publisher: PublisherPubkey,
    namespace: Slug,
    key: Slug,
}

impl StoreKey {
    fn new(publisher: &PublisherPubkey, namespace: &Slug, key: &Slug) -> Self {
        Self {
            publisher: *publisher,
            namespace: namespace.clone(),
            key: key.clone(),
        }
    }
}

/// In-memory client-side state store.
///
/// Holds per-publisher entries with lazy expiration and a byte cap. A
/// "stateless" variant (constructed via [`StateStore::new_stateless`]) is
/// behaviorally identical for the purposes of this crate; the flag is
/// surfaced via [`StateStore::is_stateless`] so a higher-level UI can refuse
/// writes if the user opted out of state entirely.
pub struct StateStore {
    inner: HashMap<StoreKey, StateEntry>,
    cap: StorageCap,
    stateless: bool,
}

impl Default for StateStore {
    fn default() -> Self {
        Self::new()
    }
}

impl StateStore {
    /// Build an empty stateful store with the default storage cap.
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
            cap: StorageCap::default(),
            stateless: false,
        }
    }

    /// Build an empty store flagged as stateless (the UI surface uses this
    /// flag to refuse writes from publishers that demand request-mode
    /// state).
    pub fn new_stateless() -> Self {
        Self {
            inner: HashMap::new(),
            cap: StorageCap::default(),
            stateless: true,
        }
    }

    /// Build an empty stateful store with a custom per-publisher byte cap.
    pub fn with_cap(cap: StorageCap) -> Self {
        Self {
            inner: HashMap::new(),
            cap,
            stateless: false,
        }
    }

    /// Whether the store is flagged as stateless.
    pub fn is_stateless(&self) -> bool {
        self.stateless
    }

    /// The configured storage cap.
    pub fn cap(&self) -> StorageCap {
        self.cap
    }

    /// Lookup that treats expired entries as absent.
    ///
    /// Lazy: the entry stays in memory until [`Self::cleanup_expired`] is
    /// called or the slot is overwritten. §07 explicitly permits this.
    pub fn get(
        &mut self,
        publisher: &PublisherPubkey,
        namespace: &Slug,
        key: &Slug,
        now: &EntangledTimestamp,
    ) -> Option<&StateEntry> {
        let k = StoreKey::new(publisher, namespace, key);
        let entry = self.inner.get(&k)?;
        if is_expired(entry, now) {
            return None;
        }
        Some(entry)
    }

    /// Commit a set operation under the given consent decision.
    ///
    /// `mode` is the mode declared in the **current** `state_policy` for
    /// `(namespace, key)`. The caller looks up the policy and passes the
    /// resolved mode here; the store then preserves it on the entry for the
    /// lifetime of that entry, even if the policy later changes (§07
    /// "Mode change").
    ///
    /// `runtime_pubkey` is `canary.runtime_pubkey` of the manifest under
    /// which the authorizing transaction was verified (§07 rc.19 N53).
    /// The store records it on the new entry so that a later canary
    /// rotation can flag the entry as `runtime_superseded` via
    /// [`Self::mark_runtime_superseded`]; superseded entries are
    /// excluded from [`Self::get_request_state`] per the N53 MUST.
    pub fn set(
        &mut self,
        publisher: &PublisherPubkey,
        op: &StateUpdateOp,
        mode: StateMode,
        consent: ConsentDecision,
        runtime_pubkey: &RuntimePubkey,
        now: &EntangledTimestamp,
    ) -> Result<SetOutcome, Diagnostic> {
        let (ns, key, value, ttl) = match op {
            StateUpdateOp::Set {
                namespace,
                key,
                value,
                ttl,
            } => (namespace, key, value, *ttl),
            StateUpdateOp::Delete { .. } => {
                return Err(Diagnostic::new(
                    DiagnosticCode::EStateOp,
                    DocumentKindLabel::Transaction,
                    "expected a set operation but got delete",
                ));
            }
        };

        if !consent.accepted {
            return Ok(SetOutcome::Rejected);
        }

        let store_key = StoreKey::new(publisher, ns, key);
        let new_entry_size = entry_storage_bytes(&store_key.namespace, &store_key.key, value);
        let existing_size = self
            .inner
            .get(&store_key)
            .filter(|e| !is_expired(e, now))
            .map(|e| entry_storage_bytes(&store_key.namespace, &store_key.key, &e.value))
            .unwrap_or(0);
        let current_total = self.bytes_used_for_publisher(publisher, now);
        // Saturating subtract guards against rounding/double-counting; the
        // base case is: post = current - existing + new.
        let post_set = current_total
            .saturating_sub(existing_size)
            .saturating_add(new_entry_size);
        if post_set > self.cap.bytes_per_publisher {
            return Err(Diagnostic::new(
                DiagnosticCode::EStateStorageCap,
                DocumentKindLabel::Transaction,
                format!(
                    "set would put publisher storage at {} bytes, cap is {}",
                    post_set, self.cap.bytes_per_publisher
                ),
            ));
        }

        // §07:466-482 (rc.21) transmit-budget rule. The minimal submit
        // body is `envelope + request_state`; committing this set
        // operation MUST NOT make that minimal body overflow the 64 KiB
        // submit cap (§09). Compute the projected post-commit minimal
        // body and reject as E_STATE_TRANSMIT_BUDGET if it would
        // overflow. Distinct from `E_STATE_STORAGE_CAP` above
        // (per-publisher cap) and `E_SUBMIT_BUDGET` at Stage 5 (Stage 5
        // satisfiability invariant).
        //
        // Only request-mode entries contribute to the transmit budget
        // (client-only state is never transmitted). A client-only set
        // therefore cannot trigger this diagnostic.
        if mode == StateMode::Request {
            let projected =
                self.projected_minimal_submit_bytes(publisher, ns, key, value.len(), now);
            if projected > SUBMIT_BODY_MAX_BYTES {
                return Err(Diagnostic::new(
                    DiagnosticCode::EStateTransmitBudget,
                    DocumentKindLabel::Transaction,
                    format!(
                        "set would put the minimal submit body at {projected} bytes, \
                         submit cap is {SUBMIT_BODY_MAX_BYTES}",
                    ),
                )
                .with_details(serde_json::json!({
                    "namespace": ns.as_str(),
                    "key": key.as_str(),
                    "projected_bytes": projected,
                    "cap_bytes": SUBMIT_BODY_MAX_BYTES,
                })));
            }
        }

        let expires_at = *now + Duration::seconds(i64::from(ttl));
        let entry = StateEntry {
            value: value.clone(),
            mode,
            expires_at,
            consent_at: *now,
            remembered_consent: consent.remembered,
            authorizing_runtime_pubkey: *runtime_pubkey,
            // A fresh commit under the current K_runtime is by definition
            // not superseded; only a subsequent rotation can flip the flag.
            runtime_superseded: false,
        };
        self.inner.insert(store_key, entry);
        Ok(SetOutcome::Committed {
            remembered: consent.remembered,
        })
    }

    /// Atomic "validate against policy and commit".
    ///
    /// Performs the full §07 cross-check the bare [`Self::set`] entry point
    /// leaves to the caller — `(namespace, key)` declaration, per-entry
    /// `max_size`, and `ttl` against `max_lifetime` and the absolute
    /// `[300, 7_776_000]` hard range — and only then runs the
    /// consent-and-storage commit. The entry's mode is taken from the
    /// matching policy entry, eliminating the "caller passes the wrong
    /// mode" failure class.
    ///
    /// Diagnostic codes are the union of [`Self::set`] and
    /// [`crate::validation::policy_check::validate_state_updates_against_policy`].
    /// Use this in preference to `set` whenever you have the manifest's
    /// current `state_policy` available; reach for the lower-level `set`
    /// only when policy resolution is intentionally already done elsewhere.
    pub fn set_with_policy(
        &mut self,
        publisher: &PublisherPubkey,
        op: &StateUpdateOp,
        policy: &[StatePolicyEntry],
        consent: ConsentDecision,
        runtime_pubkey: &RuntimePubkey,
        now: &EntangledTimestamp,
    ) -> Result<SetOutcome, Diagnostic> {
        if matches!(op, StateUpdateOp::Delete { .. }) {
            return Err(Diagnostic::new(
                DiagnosticCode::EStateOp,
                DocumentKindLabel::Transaction,
                "expected a set operation but got delete",
            ));
        }
        let entry = validate_state_update_against_policy(op, policy)?;
        self.set(publisher, op, entry.mode, consent, runtime_pubkey, now)
    }

    /// Commit a delete. Returns `Ok(false)` if no entry was present (no-op,
    /// per §07 "Delete operation").
    ///
    /// This entry point does NOT check the `(namespace, key)` declaration
    /// against the current policy. §07:319 requires that the combination
    /// MUST be declared in the current manifest's `state_policy`; callers
    /// that have the current policy available SHOULD use
    /// [`Self::delete_with_policy`] instead, which folds the
    /// `E_STATE_UNDECLARED` check into the commit atomically.
    pub fn delete(
        &mut self,
        publisher: &PublisherPubkey,
        op: &StateUpdateOp,
    ) -> Result<bool, Diagnostic> {
        let (ns, key) = match op {
            StateUpdateOp::Delete { namespace, key } => (namespace, key),
            StateUpdateOp::Set { .. } => {
                return Err(Diagnostic::new(
                    DiagnosticCode::EStateOp,
                    DocumentKindLabel::Transaction,
                    "expected a delete operation but got set",
                ));
            }
        };
        let k = StoreKey::new(publisher, ns, key);
        Ok(self.inner.remove(&k).is_some())
    }

    /// Atomic "validate against policy and commit delete".
    ///
    /// §07:319 requires that the `(namespace, key)` combination MUST be
    /// declared in the current manifest's `state_policy` for the delete to
    /// be valid. This entry point performs the declaration check (via
    /// [`crate::validation::policy_check::validate_state_update_against_policy`])
    /// before invoking [`Self::delete`]. Reach for the lower-level
    /// [`Self::delete`] only when policy resolution is intentionally
    /// already done elsewhere.
    ///
    /// Returns `Ok(false)` if no entry was present (no-op), `Ok(true)` if
    /// an entry was removed, or `Err(E_STATE_UNDECLARED)` when the
    /// `(namespace, key)` is not in the current policy.
    pub fn delete_with_policy(
        &mut self,
        publisher: &PublisherPubkey,
        op: &StateUpdateOp,
        policy: &[StatePolicyEntry],
    ) -> Result<bool, Diagnostic> {
        if matches!(op, StateUpdateOp::Set { .. }) {
            return Err(Diagnostic::new(
                DiagnosticCode::EStateOp,
                DocumentKindLabel::Transaction,
                "expected a delete operation but got set",
            ));
        }
        // Drop the &policy_entry borrow before calling self.delete (which
        // takes &mut self). The declaration check is all we need from it.
        let _ = validate_state_update_against_policy(op, policy)?;
        self.delete(publisher, op)
    }

    /// All non-expired request-mode entries for `publisher` whose
    /// `(namespace, key)` is still declared in the current `state_policy`
    /// and whose authorizing `K_runtime` has not been superseded,
    /// formatted as `RequestStateItem`. Used by `build_submit_body`.
    ///
    /// §07: state for `(namespace, key)` combinations no longer declared in
    /// the current policy MUST NOT be included in submit requests, even if
    /// the entry has not yet expired and was committed in `Request` mode.
    /// The entry is retained for inspection/deletion but excluded here.
    ///
    /// §07 rc.19 N53: request-mode entries whose `runtime_superseded`
    /// flag is set (because the authorizing `K_runtime` has been rotated
    /// out) MUST NOT be transmitted either. Use
    /// [`Self::mark_runtime_superseded`] when a new manifest authorises a
    /// distinct `K_runtime` so the rotation actually bounds the exposure
    /// of request-state credentials.
    pub fn get_request_state(
        &mut self,
        publisher: &PublisherPubkey,
        current_policy: &[StatePolicyEntry],
        now: &EntangledTimestamp,
    ) -> Vec<super::submit::RequestStateItem> {
        let mut out = Vec::new();
        for (k, e) in &self.inner {
            if k.publisher != *publisher {
                continue;
            }
            if is_expired(e, now) {
                continue;
            }
            if e.mode != StateMode::Request {
                continue;
            }
            if e.runtime_superseded {
                continue;
            }
            if !policy_declares(current_policy, &k.namespace, &k.key) {
                continue;
            }
            out.push(super::submit::RequestStateItem {
                namespace: k.namespace.clone(),
                key: k.key.clone(),
                value: e.value.clone(),
            });
        }
        out
    }

    /// Mark every retained request-mode entry for `publisher` whose
    /// `authorizing_runtime_pubkey` does not match `current_runtime_pubkey`
    /// as `runtime_superseded` (§07 rc.19 N53).
    ///
    /// Callers invoke this when they observe a new manifest whose
    /// `canary.runtime_pubkey` differs from the previously authorising
    /// one. Per the §07:550-560 MUST set:
    ///
    /// * Superseded entries MUST NOT be transmitted in subsequent submit
    ///   requests ([`Self::get_request_state`] honours this).
    /// * Superseded entries MUST be retained for user inspection and
    ///   deletion until their natural `expires_at`. This function does
    ///   not remove them; it only flips the flag.
    /// * The client MUST display a chrome notice. Surfacing the notice
    ///   is the caller's responsibility; the return value reports how
    ///   many entries were just marked, so the caller can decide whether
    ///   to prompt.
    ///
    /// Client-only entries are not affected: they are never transmitted
    /// and the rotation rationale does not apply (§07:564).
    ///
    /// Returns the number of entries newly marked superseded by this
    /// call (entries already superseded are not counted).
    pub fn mark_runtime_superseded(
        &mut self,
        publisher: &PublisherPubkey,
        current_runtime_pubkey: &RuntimePubkey,
    ) -> usize {
        let mut marked = 0;
        for (k, e) in self.inner.iter_mut() {
            if k.publisher != *publisher {
                continue;
            }
            if e.mode != StateMode::Request {
                continue;
            }
            if e.runtime_superseded {
                continue;
            }
            if e.authorizing_runtime_pubkey != *current_runtime_pubkey {
                e.runtime_superseded = true;
                marked += 1;
            }
        }
        marked
    }

    /// Drop every expired entry across every publisher. Returns the count.
    pub fn cleanup_expired(&mut self, now: &EntangledTimestamp) -> usize {
        let before = self.inner.len();
        self.inner.retain(|_, e| !is_expired(e, now));
        before - self.inner.len()
    }

    /// "Forget this site": drop every entry for `publisher`.
    pub fn clear_publisher(&mut self, publisher: &PublisherPubkey) -> usize {
        let before = self.inner.len();
        self.inner.retain(|k, _| k.publisher != *publisher);
        before - self.inner.len()
    }

    /// "Session ended". For an in-memory store this drops everything.
    /// Persistent storage is out of scope for this phase.
    pub fn clear_session(&mut self) -> usize {
        let n = self.inner.len();
        self.inner.clear();
        n
    }

    /// Bytes occupied by the publisher's non-expired entries. Counts
    /// `value.len() + namespace.len() + key.len()`.
    pub fn bytes_used_for_publisher(
        &self,
        publisher: &PublisherPubkey,
        now: &EntangledTimestamp,
    ) -> usize {
        self.inner
            .iter()
            .filter(|(k, _)| k.publisher == *publisher)
            .filter(|(_, e)| !is_expired(e, now))
            .map(|(k, e)| entry_storage_bytes(&k.namespace, &k.key, &e.value))
            .sum()
    }

    /// Projected total bytes of the minimal submit body that would
    /// result if a request-mode `set` of `(set_ns, set_key) = set_value`
    /// were committed under `publisher` right now.
    ///
    /// The minimal submit body is `envelope_reserve + request_state` —
    /// no `fields` portion, no oversized envelope. `request_state`
    /// includes every currently-retained, non-expired, non-superseded
    /// request-mode entry for `publisher`, plus the proposed new entry
    /// (with `value.len() == set_value_len`) substituting any existing
    /// retained value at the same `(ns, key)`.
    ///
    /// Used by the transmit-budget check that fires
    /// `E_STATE_TRANSMIT_BUDGET` (§07:466-482) before commit.
    fn projected_minimal_submit_bytes(
        &self,
        publisher: &PublisherPubkey,
        set_ns: &Slug,
        set_key: &Slug,
        set_value_len: usize,
        now: &EntangledTimestamp,
    ) -> usize {
        let mut total = SUBMIT_OVERHEAD_RESERVE_BYTES;
        let mut included = 0usize;
        let mut found_overwrite = false;
        for (k, e) in &self.inner {
            if k.publisher != *publisher {
                continue;
            }
            if is_expired(e, now) {
                continue;
            }
            if e.mode != StateMode::Request {
                continue;
            }
            if e.runtime_superseded {
                continue;
            }
            let same_slot = &k.namespace == set_ns && &k.key == set_key;
            let value_len = if same_slot {
                found_overwrite = true;
                set_value_len
            } else {
                e.value.len()
            };
            total =
                total.saturating_add(crate::validation::state::encoded_request_state_entry_bytes(
                    k.namespace.as_str().len(),
                    k.key.as_str().len(),
                    value_len,
                ));
            included += 1;
        }
        if !found_overwrite {
            // The proposed entry is a fresh slot, not an overwrite.
            total =
                total.saturating_add(crate::validation::state::encoded_request_state_entry_bytes(
                    set_ns.as_str().len(),
                    set_key.as_str().len(),
                    set_value_len,
                ));
            included += 1;
        }
        // Inter-entry array commas (N - 1) when the request_state array
        // has at least one entry.
        if included > 1 {
            total = total.saturating_add(included - 1);
        }
        total
    }
}

fn is_expired(entry: &StateEntry, now: &EntangledTimestamp) -> bool {
    *now >= entry.expires_at
}

fn entry_storage_bytes(namespace: &Slug, key: &Slug, value: &str) -> usize {
    namespace.as_str().len() + key.as_str().len() + value.len()
}

fn policy_declares(policy: &[StatePolicyEntry], namespace: &Slug, key: &Slug) -> bool {
    policy
        .iter()
        .any(|p| p.namespace == *namespace && p.key == *key)
}
