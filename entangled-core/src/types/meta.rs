//! `Meta` object embedded in a content document (§02).

use serde::{Deserialize, Serialize};

use super::timestamp::EntangledTimestamp;

/// Publication metadata embedded in a content document (§02).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Meta {
    /// Display title.
    pub title: String,
    /// Time of original publication.
    pub published_at: EntangledTimestamp,
}
