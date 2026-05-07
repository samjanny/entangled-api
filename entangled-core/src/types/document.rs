//! Top-level document types: `Manifest`, `ContentDocument`,
//! `TransactionDocument`, plus the tagged `Document` union (§02).

use serde::{Deserialize, Serialize};

use super::blocks::Block;
use super::keys::{Signature, SpecVersion};
use super::manifest::Manifest;
use super::meta::Meta;
use super::path::EntangledPath;
use super::state::StateUpdateOp;

/// A signed Content document (§02): the unit served at a path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentDocument {
    /// Protocol version literal.
    pub spec_version: SpecVersion,
    /// Path at which this document is served.
    pub path: EntangledPath,
    /// Publication metadata (title, timestamps).
    pub meta: Meta,
    /// Ordered block list (§03).
    pub blocks: Vec<Block>,
    /// Ed25519 signature by the publisher key over the content signature
    /// input (§04).
    pub sig: Signature,
}

/// A signed Transaction document (§02): a publisher's response to a form
/// submit, optionally carrying state updates and rendered blocks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionDocument {
    /// Protocol version literal.
    pub spec_version: SpecVersion,
    /// Path of the form whose submission this transaction answers.
    pub in_response_to: EntangledPath,
    /// State update operations to apply (Set/Delete) per §07.
    pub state_updates: Vec<StateUpdateOp>,
    /// Ordered block list rendered as the transaction response.
    pub blocks: Vec<Block>,
    /// Ed25519 signature by the publisher key over the transaction signature
    /// input (§04).
    pub sig: Signature,
}

/// Tagged enum over the three signed document kinds.
///
/// Wire form: a JSON object with a `kind` discriminator (`"manifest"`,
/// `"content"`, `"transaction"`) plus the kind-specific fields inlined.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Document {
    /// `kind: "manifest"`.
    Manifest(Manifest),
    /// `kind: "content"`.
    Content(ContentDocument),
    /// `kind: "transaction"`.
    Transaction(TransactionDocument),
}
