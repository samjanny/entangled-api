use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

const SLUG_MAX_LEN: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Slug(String);

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SlugError {
    #[error("slug must not be empty")]
    Empty,
    #[error("slug exceeds maximum length of {SLUG_MAX_LEN} bytes")]
    TooLong,
    #[error("slug must start with [a-z0-9]")]
    InvalidFirstChar,
    #[error("slug contains invalid character (allowed: [a-z0-9_-])")]
    InvalidChar,
}

impl Slug {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'a> TryFrom<&'a str> for Slug {
    type Error = SlugError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(SlugError::Empty);
        }
        if value.len() > SLUG_MAX_LEN {
            return Err(SlugError::TooLong);
        }
        let bytes = value.as_bytes();
        let first = bytes[0];
        if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
            return Err(SlugError::InvalidFirstChar);
        }
        for &b in &bytes[1..] {
            let ok = b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-';
            if !ok {
                return Err(SlugError::InvalidChar);
            }
        }
        Ok(Self(value.to_owned()))
    }
}

impl TryFrom<String> for Slug {
    type Error = SlugError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl fmt::Display for Slug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for Slug {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Slug {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::try_from(raw).map_err(serde::de::Error::custom)
    }
}
