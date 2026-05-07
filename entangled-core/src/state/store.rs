//! Client-side state store (§07).
//!
//! Keys are `(K_publisher.pub, namespace, key)`. Per-publisher isolation,
//! mode preservation at commit time, lazy expiration, and a per-publisher
//! storage cap are enforced here. Consent UX is the client's
//! responsibility; this module accepts a [`ConsentDecision`] as input.

use std::collections::HashMap;

use time::Duration;

use crate::types::keys::PublisherPubkey;
use crate::types::slug::Slug;
use crate::types::state::{StateMode, StateUpdateOp};
use crate::types::timestamp::EntangledTimestamp;
use crate::validation::diagnostic::{Diagnostic, DiagnosticCode, DocumentKindLabel};

/// One state entry, as stored client-side. The `mode` is preserved from the
/// time of commit and never silently rewritten when `state_policy` changes
/// (§07 "Mode change").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateEntry {
    pub value: String,
    pub mode: StateMode,
    pub expires_at: EntangledTimestamp,
    pub consent_at: EntangledTimestamp,
    pub remembered_consent: bool,
}

/// User decision delivered to the store. The store does not run the consent
/// UX; it only commits or refuses based on this input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsentDecision {
    pub accepted: bool,
    pub remembered: bool,
}

/// Per-publisher byte cap enforced before each set. §07 "Storage limits".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageCap {
    pub bytes_per_publisher: usize,
}

impl Default for StorageCap {
    /// 64 KiB per publisher. §07 only requires that the cap be at least
    /// sufficient to hold the maximum allowed state for the current policy
    /// (`sum(max_size)` across all entries). 64 KiB is below the absolute
    /// upper bound of 32 entries × 4096 bytes = 128 KiB, so this default is
    /// restrictive relative to the maximum policy-allowed total. A caller
    /// that needs more headroom constructs the store via
    /// [`StateStore::with_cap`].
    fn default() -> Self {
        Self {
            bytes_per_publisher: 64 * 1024,
        }
    }
}

/// Result of a `set` call. Storage failure is `Err`; user rejection is
/// `Ok(Rejected)` because a refused consent is not a protocol error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetOutcome {
    Committed { remembered: bool },
    Rejected,
}

#[derive(Clone, Hash, PartialEq, Eq)]
struct StoreKey {
    publisher: PublisherPubkey,
    namespace: String,
    key: String,
}

impl StoreKey {
    fn new(publisher: &PublisherPubkey, namespace: &Slug, key: &Slug) -> Self {
        Self {
            publisher: *publisher,
            namespace: namespace.as_str().to_owned(),
            key: key.as_str().to_owned(),
        }
    }
}

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
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
            cap: StorageCap::default(),
            stateless: false,
        }
    }

    pub fn new_stateless() -> Self {
        Self {
            inner: HashMap::new(),
            cap: StorageCap::default(),
            stateless: true,
        }
    }

    pub fn with_cap(cap: StorageCap) -> Self {
        Self {
            inner: HashMap::new(),
            cap,
            stateless: false,
        }
    }

    pub fn is_stateless(&self) -> bool {
        self.stateless
    }

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
    pub fn set(
        &mut self,
        publisher: &PublisherPubkey,
        op: &StateUpdateOp,
        mode: StateMode,
        consent: ConsentDecision,
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

        let expires_at = *now + Duration::seconds(i64::from(ttl));
        let entry = StateEntry {
            value: value.clone(),
            mode,
            expires_at,
            consent_at: *now,
            remembered_consent: consent.remembered,
        };
        self.inner.insert(store_key, entry);
        Ok(SetOutcome::Committed {
            remembered: consent.remembered,
        })
    }

    /// Commit a delete. Returns `Ok(false)` if no entry was present (no-op,
    /// per §07 "Delete operation").
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

    /// All non-expired request-mode entries for a publisher, formatted as
    /// `RequestStateItem`. Used by `build_submit_body`.
    pub fn get_request_state(
        &mut self,
        publisher: &PublisherPubkey,
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
            // Slug syntax was validated when the entry was inserted (the
            // public API only accepts `&Slug`), so this conversion cannot
            // fail.
            let namespace =
                Slug::try_from(k.namespace.as_str()).expect("namespace stored only via &Slug");
            let key = Slug::try_from(k.key.as_str()).expect("key stored only via &Slug");
            out.push(super::submit::RequestStateItem {
                namespace,
                key,
                value: e.value.clone(),
            });
        }
        out
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
}

fn is_expired(entry: &StateEntry, now: &EntangledTimestamp) -> bool {
    *now >= entry.expires_at
}

fn entry_storage_bytes(namespace: &str, key: &str, value: &str) -> usize {
    namespace.len() + key.len() + value.len()
}
