use serde::{Deserialize, Serialize};

use super::timestamp::EntangledTimestamp;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Meta {
    pub title: String,
    pub published_at: EntangledTimestamp,
}
