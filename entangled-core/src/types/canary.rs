use serde::{Deserialize, Serialize};

use super::keys::RuntimePubkey;
use super::timestamp::EntangledTimestamp;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Canary {
    pub runtime_pubkey: RuntimePubkey,
    pub issued_at: EntangledTimestamp,
    pub next_expected: EntangledTimestamp,
    pub statement: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub freshness_proof: Option<String>,
}
