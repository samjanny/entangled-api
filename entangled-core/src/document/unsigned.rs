//! Unsigned counterparts to [`crate::types::Manifest`],
//! [`crate::types::ContentDocument`], and [`crate::types::TransactionDocument`].
//!
//! The signed structs carry `sig` as a non-optional field — they represent a
//! complete envelope. To express the "before signing" state we mirror them as
//! `Unsigned*` structs that omit `sig`. The builder takes an `Unsigned*`,
//! signs the canonicalized payload, and produces the corresponding signed
//! struct plus its serialized bytes.
//!
//! ## Why not `serde_json::Value`?
//!
//! `Value` would lose the type safety the rest of the crate relies on
//! (e.g. `EntangledTimestamp`, `Slug`, `Signature` newtypes).
//!
//! ## Why not `sig: Option<Signature>`?
//!
//! `Option::None` serializes as a missing field, which would change the wire
//! format of partially-built objects in surprising ways. `sig` is also
//! mandatory in §02 — there is no normative "envelope without sig" shape on
//! the wire.
//!
//! ## Why not a dummy sig that the builder overwrites?
//!
//! The semantics would be confusing under code review: a struct with a sig
//! that is "not really" a sig, mutated mid-pipeline. Two distinct types make
//! the state explicit.
//!
//! ## The `kind` discriminator
//!
//! In the signed types the discriminator (`kind: "manifest"` etc.) lives at
//! the [`crate::types::Document`] enum tag, so it is added by serde when —
//! and only when — a value is serialized through the enum. The `Unsigned*`
//! structs are not enum variants, so [`UnsignedManifest::to_signed_payload`]
//! adds the `kind` field manually before returning the `Value`. This keeps
//! `to_signed_payload` byte-equivalent (after JCS) to
//! `serde_json::to_value(&signed_struct) + add kind + remove sig`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::types::blocks::Block;
use crate::types::canary::Canary;
use crate::types::keys::{PublisherPubkey, RequestHash, RequestId, SpecVersion};
use crate::types::manifest::{MigrationPointer, NavEntry, Origin};
use crate::types::meta::Meta;
use crate::types::path::EntangledPath;
use crate::types::state::{StatePolicyEntry, StateUpdateOp};
use crate::types::timestamp::EntangledTimestamp;

const MANIFEST_KIND: &str = "manifest";
const CONTENT_KIND: &str = "content";
const TRANSACTION_KIND: &str = "transaction";

/// Unsigned counterpart of [`crate::types::Manifest`] (every field except
/// `sig`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedManifest {
    /// Protocol version literal.
    pub spec_version: SpecVersion,
    /// Publisher long-term Ed25519 public key.
    pub publisher_pubkey: PublisherPubkey,
    /// Transport-carrier binding for this manifest.
    pub origin: Origin,
    /// Liveness/anti-downgrade canary.
    pub canary: Canary,
    /// Closed list of state-policy entries.
    pub state_policy: Vec<StatePolicyEntry>,
    /// Navigation entries.
    pub navigation: Vec<NavEntry>,
    /// Minimum interval (seconds) between manifest re-fetches.
    pub min_refresh_interval: u32,
    /// Time at which the manifest was last updated.
    pub updated: EntangledTimestamp,
    /// Optional publisher-initiated origin-migration announcement (§06
    /// rc.13). Absent for the steady-state case; encoded by omission per
    /// §04 closed-schema discipline.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub migration_pointer: Option<MigrationPointer>,
}

/// Unsigned counterpart of [`crate::types::ContentDocument`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedContent {
    /// Protocol version literal.
    pub spec_version: SpecVersion,
    /// Path at which this document is served.
    pub path: EntangledPath,
    /// Publication metadata.
    pub meta: Meta,
    /// Ordered block list.
    pub blocks: Vec<Block>,
}

/// Unsigned counterpart of [`crate::types::TransactionDocument`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedTransaction {
    /// Protocol version literal.
    pub spec_version: SpecVersion,
    /// Path of the form whose submission this transaction answers.
    pub in_response_to: EntangledPath,
    /// Echo of the `request_id` the client placed in the originating submit
    /// body (§02 / §09).
    pub request_id: RequestId,
    /// SHA-256 digest of the JCS-canonical submit body bytes the publisher
    /// received, encoded as `sha-256:<base64url>` (§02).
    pub request_hash: RequestHash,
    /// State update operations to apply.
    pub state_updates: Vec<StateUpdateOp>,
    /// Ordered block list rendered as the response.
    pub blocks: Vec<Block>,
}

impl UnsignedManifest {
    /// Convert into the §05 signed payload: a JSON object containing every
    /// field of the manifest envelope except `sig`, with the `kind`
    /// discriminator added back in.
    ///
    /// # Errors
    ///
    /// Forwards any [`serde_json::Error`] produced while serializing the
    /// struct (unreachable in practice given the closed schema).
    pub fn to_signed_payload(&self) -> Result<Value, serde_json::Error> {
        let mut value = serde_json::to_value(self)?;
        attach_kind(&mut value, MANIFEST_KIND);
        Ok(value)
    }
}

impl UnsignedContent {
    /// Convert into the §05 signed payload for a content document.
    ///
    /// # Errors
    ///
    /// See [`UnsignedManifest::to_signed_payload`].
    pub fn to_signed_payload(&self) -> Result<Value, serde_json::Error> {
        let mut value = serde_json::to_value(self)?;
        attach_kind(&mut value, CONTENT_KIND);
        Ok(value)
    }
}

impl UnsignedTransaction {
    /// Convert into the §05 signed payload for a transaction document.
    ///
    /// # Errors
    ///
    /// See [`UnsignedManifest::to_signed_payload`].
    pub fn to_signed_payload(&self) -> Result<Value, serde_json::Error> {
        let mut value = serde_json::to_value(self)?;
        attach_kind(&mut value, TRANSACTION_KIND);
        Ok(value)
    }
}

fn attach_kind(value: &mut Value, kind: &'static str) {
    if let Value::Object(map) = value {
        map.insert("kind".to_owned(), Value::String(kind.to_owned()));
    }
}
