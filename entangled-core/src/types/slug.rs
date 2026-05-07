//! `Slug`: lowercase alphanumeric identifier used for namespaces, keys,
//! language tags, form field names, and select-option values (§02).

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

const SLUG_MAX_LEN: usize = 64;

/// A lowercase alphanumeric identifier used for namespaces, keys, language
/// tags, form field names, and select-option values.
///
/// Syntax: `[a-z0-9][a-z0-9_-]{0,63}` (1..=64 bytes, ASCII only). The first
/// character must be `[a-z0-9]`; subsequent characters may also include `_`
/// and `-`. See §02 for the field-level grammar.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Slug(String);

/// Reasons a string fails to parse as a [`Slug`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SlugError {
    /// Empty input. Slugs must contain at least one character.
    #[error("slug must not be empty")]
    Empty,
    /// Input exceeds the 64-byte maximum.
    #[error("slug exceeds maximum length of {SLUG_MAX_LEN} bytes")]
    TooLong,
    /// First character is not in `[a-z0-9]`.
    #[error("slug must start with [a-z0-9]")]
    InvalidFirstChar,
    /// A non-first character is not in `[a-z0-9_-]`.
    #[error("slug contains invalid character (allowed: [a-z0-9_-])")]
    InvalidChar,
}

impl Slug {
    /// Borrow the underlying string.
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
