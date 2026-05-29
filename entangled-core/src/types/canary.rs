//! Canary object embedded in a manifest (§02 schema, §08 anti-downgrade
//! rules).

use serde::{Deserialize, Serialize};

use super::keys::RuntimePubkey;
use super::timestamp::MaybeTimestamp;

/// Liveness canary embedded in a manifest (§02 schema, §08 anti-downgrade).
///
/// The canary advertises the runtime key currently authorized to issue
/// liveness statements, when this canary was issued, and the latest time at
/// which the next canary is expected. Clients enforce monotonic
/// `next_expected` per publisher to detect downgrade attacks (§08).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Canary {
    /// Runtime Ed25519 public key for canary statements.
    pub runtime_pubkey: RuntimePubkey,
    /// Time at which this canary was issued by the publisher.
    pub issued_at: MaybeTimestamp,
    /// Latest time at which the next canary should be observed; clients
    /// reject manifests whose `next_expected` regresses.
    pub next_expected: MaybeTimestamp,
    /// Free-form publisher statement of liveness/control.
    pub statement: String,
    /// Optional out-of-band freshness proof (e.g., a recent block hash).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub freshness_proof: Option<String>,
}
