//! Submit body wire format (§09).
//!
//! `SubmitBody` is the JSON object posted to a transaction endpoint. The
//! schema is closed: exactly three top-level fields — `fields`,
//! `request_state`, and `request_id` (§09). `build_submit_body` composes
//! the body from the caller-supplied user input, the publisher-scoped
//! request state held by [`StateStore`], and a freshly generated
//! `request_id`.
//!
//! Validation is deliberately separate (`validation::submit`) so that a
//! caller can build, inspect, and rebuild without first hitting an error.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::types::keys::{PublisherPubkey, RequestId};
use crate::types::slug::Slug;
use crate::types::state::StatePolicyEntry;
use crate::types::timestamp::EntangledTimestamp;

use super::store::StateStore;

/// Wire form of the submit body. `BTreeMap` is used for `fields` so that
/// JSON serialization is deterministic across runs (handy for tests and
/// canonical golden files); on the wire the spec does not impose any order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitBody {
    /// User-input form values keyed by field name (slug syntax enforced at
    /// validation, not by the type).
    pub fields: BTreeMap<String, String>,
    /// Request-mode state items being transmitted with the submit.
    pub request_state: Vec<RequestStateItem>,
    /// Fresh 128-bit `request_id` (§09) drawn for this submit. Echoed
    /// byte-for-byte by the publisher into the corresponding transaction
    /// document (§02) under the runtime signature; the client compares it
    /// at Stage 9 binding (§10) and rejects on mismatch with
    /// `E_BIND_REQUEST_ID` (§11). MUST be freshly generated for every
    /// submit, including retries.
    pub request_id: RequestId,
}

/// One request-mode state item the client is transmitting with this
/// submit. §09: "each entry has exactly three fields".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestStateItem {
    /// Namespace slug.
    pub namespace: Slug,
    /// Key slug within the namespace.
    pub key: Slug,
    /// Stored value at the time of submit.
    pub value: String,
}

/// Compose a submit body for `publisher` by reading the request-mode
/// entries from `store` and pairing them with `user_input_fields`. Only
/// entries whose `(namespace, key)` is still declared in `current_policy`
/// are included, per §07 ("state entries for `(namespace, key)` combinations
/// no longer declared in the new policy ... MUST NOT be included in submit
/// requests").
///
/// `request_id` MUST be a fresh 128-bit value drawn from a cryptographically
/// secure random source (§09); reuse across submits is forbidden. The
/// caller draws it because `entangled-core` does not depend on a CSPRNG.
///
/// Does not validate; pass the result through
/// `validation::submit::validate_submit_body` before transmission.
pub fn build_submit_body(
    user_input_fields: BTreeMap<String, String>,
    store: &mut StateStore,
    publisher: &PublisherPubkey,
    current_policy: &[StatePolicyEntry],
    now: &EntangledTimestamp,
    request_id: RequestId,
) -> SubmitBody {
    let request_state = store.get_request_state(publisher, current_policy, now);
    SubmitBody {
        fields: user_input_fields,
        request_state,
        request_id,
    }
}
