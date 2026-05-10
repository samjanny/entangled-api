//! Top-level document types: `Manifest`, `ContentDocument`,
//! `TransactionDocument`, plus the tagged `Document` union (§02).

use serde::{Deserialize, Serialize};

use super::blocks::Block;
use super::keys::{RequestHash, RequestId, Signature, SpecVersion};
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
/// submit, carrying the originating submit's `request_id`/`request_hash`
/// binding fields, optional state updates, and rendered blocks.
///
/// All eight top-level fields are required (§02). The `request_id` and
/// `request_hash` fields bind the transaction to the specific submit body
/// the client sent: the publisher echoes the client's `request_id`
/// byte-for-byte and computes `request_hash` over the JCS-canonical submit
/// body bytes it received. The client verifies both at Stage 9 binding
/// (§10) and rejects with `E_BIND_REQUEST_ID` or `E_BIND_REQUEST_HASH` on
/// mismatch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionDocument {
    /// Protocol version literal.
    pub spec_version: SpecVersion,
    /// Path of the form whose submission this transaction answers.
    pub in_response_to: EntangledPath,
    /// Echo of the `request_id` the client placed in the originating submit
    /// body (§09); the publisher copies this byte-for-byte. The client
    /// compares it byte-exact against the `RequestId` it generated for the
    /// submit and rejects mismatches with `E_BIND_REQUEST_ID` (§11).
    pub request_id: RequestId,
    /// SHA-256 digest of the JCS-canonical submit body bytes the publisher
    /// received, encoded as `sha-256:<base64url>` (§02). The client compares
    /// it byte-exact against the digest it computed locally over the submit
    /// body it sent and rejects mismatches with `E_BIND_REQUEST_HASH`
    /// (§11).
    pub request_hash: RequestHash,
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
///
/// `Manifest` is the largest variant — `Manifest` itself is ~400 bytes
/// because of the optional `migration_pointer` (an inlined `Origin` plus a
/// timestamp). We deliberately do not box it: this enum is only
/// constructed transiently during deserialization, immediately
/// destructured back into the typed Manifest/Content/Transaction value,
/// and never stored long-term, so boxing would only add an allocation
/// for the common path with no end-state benefit.
#[allow(clippy::large_enum_variant)]
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
