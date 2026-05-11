//! Manifest, Origin, Carrier, NavEntry, and the `OnionAddress` lexical
//! newtype (§02, §05).

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use super::canary::Canary;
use super::keys::{OriginPubkey, PublisherPubkey, Signature, SpecVersion};
use super::path::EntangledPath;
use super::state::StatePolicyEntry;
use super::timestamp::EntangledTimestamp;

const ONION_BODY_LEN: usize = 56;
const ONION_SUFFIX: &str = ".onion";
const ONION_TOTAL_LEN: usize = ONION_BODY_LEN + 6;

/// A Tor v3 `.onion` address as it appears on the wire (§02 origin schema).
///
/// 62 ASCII characters total: 56 lowercase RFC 4648 base32 characters in
/// `[a-z2-7]` followed by the literal suffix `.onion`. This newtype only
/// enforces the lexical syntax; the full Tor v3 checksum and version-byte
/// verification lives in [`crate::tor::address`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OnionAddress(String);

/// Reasons a string fails to parse as an [`OnionAddress`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum OnionAddressError {
    /// The string is not exactly 62 ASCII characters.
    #[error("onion address must be exactly {ONION_TOTAL_LEN} ASCII characters")]
    InvalidLength,
    /// The string does not end with the `.onion` suffix.
    #[error("onion address must end with \".onion\"")]
    MissingSuffix,
    /// The 56-character body contains a non-base32 character.
    #[error("onion address body must be lowercase RFC 4648 base32 [a-z2-7]")]
    InvalidBase32,
}

impl OnionAddress {
    /// Borrow the underlying string (always 62 ASCII characters).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'a> TryFrom<&'a str> for OnionAddress {
    type Error = OnionAddressError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        if value.len() != ONION_TOTAL_LEN {
            return Err(OnionAddressError::InvalidLength);
        }
        if !value.ends_with(ONION_SUFFIX) {
            return Err(OnionAddressError::MissingSuffix);
        }
        let body = &value[..ONION_BODY_LEN];
        for &b in body.as_bytes() {
            let ok = b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b);
            if !ok {
                return Err(OnionAddressError::InvalidBase32);
            }
        }
        Ok(Self(value.to_owned()))
    }
}

impl TryFrom<String> for OnionAddress {
    type Error = OnionAddressError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl fmt::Display for OnionAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for OnionAddress {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for OnionAddress {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::try_from(raw).map_err(serde::de::Error::custom)
    }
}

/// Transport carrier for an origin (§02). Exactly one variant is defined in
/// v1.0; the closed enum guarantees forward-compatible rejection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Carrier {
    /// Tor v3 onion service per `rend-spec-v3.txt`.
    #[serde(rename = "tor-v3")]
    TorV3,
}

/// Origin object inside a manifest (§02 origin schema; `not_after` added in
/// §06 v1.0-rc.14).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Origin {
    /// Transport carrier — only `tor-v3` in v1.0.
    pub carrier: Carrier,
    /// `.onion` address of the origin.
    pub address: OnionAddress,
    /// Ed25519 origin public key. Must equal the key encoded in `address`
    /// (§05 binding); the binding is verified by [`crate::tor::binding`].
    pub origin_pubkey: OriginPubkey,
    /// Optional publisher-declared UTC instant after which this carrier
    /// endpoint is no longer authoritative for the site under `K_publisher`
    /// (§06 v1.0-rc.14). When present, Stage 5 enforces the semantic
    /// constraints (strictly after `canary.issued_at`, within a 5-year
    /// ceiling) and Stage 9 rejects the manifest as `E_ORIGIN_EXPIRED`
    /// once `now` reaches the declared instant (subject to clock-skew
    /// tolerance). Absent when no publisher-side expiration is declared;
    /// per §04 no-`null` discipline, absent is encoded by omitting the
    /// field, never by `null`.
    ///
    /// `not_after` is intentionally absent from the `successor_origin`
    /// object inside [`MigrationPointer`]: the successor manifest
    /// independently declares its own `origin.not_after` (if any) once
    /// fetched at Stage 9 per §06.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub not_after: Option<EntangledTimestamp>,
}

/// One entry in the manifest's `navigation` array (§02).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NavEntry {
    /// Display label (free-form Unicode string).
    pub label: String,
    /// Path on the same site to navigate to.
    pub path: EntangledPath,
}

/// Optional `migration_pointer` block (§06 v1.0-rc.13).
///
/// Publisher-initiated, in-band announcement of a successor carrier
/// endpoint operated under the same `K_publisher`. A client supporting
/// publisher profiles uses this to discover the new origin authentically.
///
/// Schema constraints enforced at Stage 5 by
/// [`crate::validation::schema::validate_migration_pointer`]:
///
/// - `successor_origin.address` MUST differ from the announcing manifest's
///   `origin.address`.
/// - `successor_origin.carrier` MUST equal the announcing
///   `origin.carrier` (v1.0 has only `tor-v3`, so this is automatic for
///   well-formed manifests but the rule is normative).
/// - `announced_at` MUST NOT be later than the announcing manifest's
///   `updated`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationPointer {
    /// Successor carrier endpoint, mirroring the [`Origin`] schema.
    pub successor_origin: Origin,
    /// Time at which the publisher signed this announcement. Per §06
    /// v1.0-rc.13, MUST NOT be later than the announcing manifest's
    /// `updated`.
    pub announced_at: EntangledTimestamp,
}

/// Top-level manifest object (§02).
///
/// The manifest is the root of trust for a publisher: it carries the
/// publisher pubkey, origin binding, canary, state policy, and navigation,
/// signed by the publisher's long-term Ed25519 key.
///
/// `migration_pointer` (rc.13) is optional: absent for the steady-state
/// case, present only when the publisher is announcing an origin migration.
/// Per §04 / §02 closed-schema discipline, absent is encoded by omitting
/// the field, never by `null`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Protocol version literal (`"1.0"`).
    pub spec_version: SpecVersion,
    /// Publisher long-term Ed25519 public key.
    pub publisher_pubkey: PublisherPubkey,
    /// Transport-carrier binding for this manifest.
    pub origin: Origin,
    /// Liveness/anti-downgrade canary (§08).
    pub canary: Canary,
    /// Closed list of state-policy entries the publisher exposes (§07).
    pub state_policy: Vec<StatePolicyEntry>,
    /// Navigation entries surfaced in client UI.
    pub navigation: Vec<NavEntry>,
    /// Minimum interval (seconds) between manifest re-fetches the client
    /// should observe.
    pub min_refresh_interval: u32,
    /// Time at which the manifest was last updated.
    pub updated: EntangledTimestamp,
    /// Optional publisher-initiated origin-migration announcement (§06
    /// rc.13). Absent when no migration is announced.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub migration_pointer: Option<MigrationPointer>,
    /// Ed25519 signature by `publisher_pubkey` over the manifest signature
    /// input (§04).
    pub sig: Signature,
}
