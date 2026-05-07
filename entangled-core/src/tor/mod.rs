//! Tor v3 onion-address handling and Stage 9 fetch-origin binding.
//!
//! See [`address`] for the byte-level decoding/strict verification of a
//! `.onion` v3 address per `rend-spec-v3.txt` (cited verbatim in §05), and
//! [`binding`] for the `OnionAddress` ↔ `manifest.origin` consistency check
//! that closes Pillar B end-to-end.

pub mod address;
pub mod binding;
pub mod error;

pub use address::{DecodedOnionAddress, TOR_V3_VERSION};
pub use binding::verify_origin_binding;
pub use error::TorError;
