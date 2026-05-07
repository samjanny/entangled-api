//! Submit body wire format (§09).
//!
//! `SubmitBody` is the JSON object posted to a transaction endpoint. The
//! schema is closed: exactly two top-level fields, `fields` and
//! `request_state`. `build_submit_body` composes the body from the
//! caller-supplied user input plus the publisher-scoped request state held
//! by [`StateStore`](super::store::StateStore).
//!
//! Validation is deliberately separate (`validation::submit`) so that a
//! caller can build, inspect, and rebuild without first hitting an error.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::types::keys::PublisherPubkey;
use crate::types::slug::Slug;
use crate::types::timestamp::EntangledTimestamp;

use super::store::StateStore;

/// Wire form of the submit body. `BTreeMap` is used for `fields` so that
/// JSON serialization is deterministic across runs (handy for tests and
/// canonical golden files); on the wire the spec does not impose any order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitBody {
    pub fields: BTreeMap<String, String>,
    pub request_state: Vec<RequestStateItem>,
}

/// One request-mode state item the client is transmitting with this
/// submit. §09: "each entry has exactly three fields".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestStateItem {
    pub namespace: Slug,
    pub key: Slug,
    pub value: String,
}

/// Compose a submit body for `publisher` by reading the request-mode
/// entries from `store` and pairing them with `user_input_fields`. Does
/// not validate; pass the result through
/// `validation::submit::validate_submit_body` before transmission.
pub fn build_submit_body(
    user_input_fields: BTreeMap<String, String>,
    store: &mut StateStore,
    publisher: &PublisherPubkey,
    now: &EntangledTimestamp,
) -> SubmitBody {
    let request_state = store.get_request_state(publisher, now);
    SubmitBody {
        fields: user_input_fields,
        request_state,
    }
}
