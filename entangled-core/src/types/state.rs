use serde::{Deserialize, Serialize};

use super::slug::Slug;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateMode {
    ClientOnly,
    Request,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatePolicyEntry {
    pub namespace: Slug,
    pub key: Slug,
    pub mode: StateMode,
    pub max_size: u32,
    pub max_lifetime: u32,
    pub purpose: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum StateUpdateOp {
    Set {
        namespace: Slug,
        key: Slug,
        value: String,
        ttl: u32,
    },
    Delete {
        namespace: Slug,
        key: Slug,
    },
}
