//! `LinkTarget` enum (same-site, entangled cross-origin, citation) (§03).

use serde::{Deserialize, Serialize};

use super::keys::PublisherPubkey;
use super::manifest::{Carrier, OnionAddress};
use super::path::EntangledPath;

/// Closed enumeration of link target kinds (§03).
///
/// The wire form is a JSON object tagged by `kind`. Unknown `kind` values or
/// sibling fields are rejected at parse time. Four kinds in increasing
/// distance from the current publisher's trust context: `same_site`,
/// `entangled`, `carrier`, `citation`.
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
    /// A carrier-native, non-Entangled service reachable through a carrier
    /// the client already supports (e.g. a non-Entangled Tor v3 onion
    /// service). The destination is **not** an Entangled site: no
    /// `expected_publisher_pubkey`, no manifest, no Entangled trust state,
    /// no request state. The client MUST NOT auto-navigate and MUST NOT
    /// hand the URL to a component that would resolve the host through
    /// public DNS (§03 / §09).
    Carrier {
        /// Carrier profile identifier — only `tor-v3` in v1.
        carrier: Carrier,
        /// `http://`-scheme URL whose host is a valid carrier address for
        /// `carrier`. Validated by
        /// [`crate::validation::inline::validate_link_target`].
        url: String,
    },
    /// A non-Entangled citation URL (informational; never followed
    /// transparently by the client). For non-clearnet destinations
    /// reachable via a carrier (e.g. a non-Entangled onion service), use
    /// `Carrier` instead (§03).
    Citation {
        /// Free-form URL string.
        url: String,
    },
}
