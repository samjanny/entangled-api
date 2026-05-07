use serde::{Deserialize, Serialize};

use super::keys::PublisherPubkey;
use super::manifest::{Carrier, OnionAddress};
use super::path::EntangledPath;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LinkTarget {
    SameSite {
        path: EntangledPath,
    },
    Entangled {
        carrier: Carrier,
        address: OnionAddress,
        path: EntangledPath,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        expected_publisher_pubkey: Option<PublisherPubkey>,
    },
    Citation {
        url: String,
    },
}
