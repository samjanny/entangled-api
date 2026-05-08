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
    /// Ed25519 signature over the content signature input as defined in §05.
    ///
    /// Computed by signing
    /// `"ENTANGLED-v1 content" || 0x00 || JCS(content_without_sig)`
    /// with the runtime private key (`K_runtime`) authorized by the
    /// manifest's canary for the current publication cycle. Verification
    /// uses the `runtime_pubkey` declared in the manifest's canary.
    ///
    /// Encoded as 86 ASCII characters of base64url (no padding).
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
    /// Ed25519 signature over the transaction signature input as defined
    /// in §05.
    ///
    /// Computed by signing
    /// `"ENTANGLED-v1 transaction" || 0x00 || JCS(transaction_without_sig)`
    /// with the runtime private key (`K_runtime`) authorized by the
    /// manifest's canary for the current publication cycle. Verification
    /// uses the `runtime_pubkey` declared in the manifest's canary.
    ///
    /// Encoded as 86 ASCII characters of base64url (no padding).
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
