//! `LinkTarget` enum (same-site, entangled cross-origin, citation) (§03).

use serde::{Deserialize, Serialize};

use super::keys::PublisherPubkey;
use super::manifest::{Carrier, OnionAddress};
use super::path::EntangledPath;

/// Closed enumeration of link target kinds (§03).
///
/// The wire form is a JSON object tagged by `kind`. Unknown `kind` values or
/// sibling fields are rejected at parse time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LinkTarget {
    /// A path on the same publisher's site.
    SameSite {
        /// Same-site path.
        path: EntangledPath,
    },
    /// A path on another Entangled publisher (cross-origin).
    Entangled {
        /// Transport carrier of the remote origin.
        carrier: Carrier,
        /// `.onion` address of the remote origin.
        address: OnionAddress,
        /// Path on the remote publisher.
        path: EntangledPath,
        /// Optional pinned publisher pubkey; if present, the client must
        /// verify the remote manifest is signed by exactly this key.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        expected_publisher_pubkey: Option<PublisherPubkey>,
    },
    /// A non-Entangled citation URL (informational; never followed
    /// transparently by the client).
    Citation {
        /// Free-form URL string.
        url: String,
    },
}
