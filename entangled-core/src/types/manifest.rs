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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OnionAddress(String);

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OnionAddressError {
    #[error("onion address must be exactly {ONION_TOTAL_LEN} ASCII characters")]
    InvalidLength,
    #[error("onion address must end with \".onion\"")]
    MissingSuffix,
    #[error("onion address body must be lowercase RFC 4648 base32 [a-z2-7]")]
    InvalidBase32,
}

impl OnionAddress {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Carrier {
    #[serde(rename = "tor-v3")]
    TorV3,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Origin {
    pub carrier: Carrier,
    pub address: OnionAddress,
    pub origin_pubkey: OriginPubkey,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NavEntry {
    pub label: String,
    pub path: EntangledPath,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub spec_version: SpecVersion,
    pub publisher_pubkey: PublisherPubkey,
    pub origin: Origin,
    pub canary: Canary,
    pub state_policy: Vec<StatePolicyEntry>,
    pub navigation: Vec<NavEntry>,
    pub min_refresh_interval: u32,
    pub updated: EntangledTimestamp,
    pub sig: Signature,
}
