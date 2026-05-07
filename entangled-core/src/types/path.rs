//! `EntangledPath`: absolute, normalized path with whitelisted characters
//! (§02).

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

const PATH_MAX_LEN: usize = 256;

/// An absolute, normalized Entangled path (§02).
///
/// Syntax: starts with `/`, length 1..=256 bytes, characters drawn from
/// `[A-Za-z0-9._~/-]`, no consecutive `/`, no `.` or `..` segments. The root
/// path `"/"` is the only single-character form.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EntangledPath(String);

/// Reasons a string fails to parse as an [`EntangledPath`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PathError {
    /// Path is empty or does not start with `/`.
    #[error("path must not be empty and must begin with '/'")]
    NotAbsolute,
    /// Path exceeds 256 bytes.
    #[error("path exceeds maximum length of {PATH_MAX_LEN} bytes")]
    TooLong,
    /// Path contains a character outside `[A-Za-z0-9._~/-]`.
    #[error("path contains invalid character (allowed: [A-Za-z0-9._~/-])")]
    InvalidChar,
    /// Path contains two adjacent `/` characters.
    #[error("path contains consecutive '/' characters")]
    ConsecutiveSlash,
    /// A path segment equals `.` or `..`.
    #[error("path contains '.' or '..' segment")]
    DotSegment,
}

impl EntangledPath {
    /// Borrow the underlying string (always starts with `/`).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'a> TryFrom<&'a str> for EntangledPath {
    type Error = PathError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        if value.is_empty() || !value.starts_with('/') {
            return Err(PathError::NotAbsolute);
        }
        if value.len() > PATH_MAX_LEN {
            return Err(PathError::TooLong);
        }

        let bytes = value.as_bytes();
        for &b in bytes {
            let ok = b.is_ascii_alphanumeric()
                || b == b'/'
                || b == b'.'
                || b == b'_'
                || b == b'~'
                || b == b'-';
            if !ok {
                return Err(PathError::InvalidChar);
            }
        }

        // No consecutive slashes; no `.` or `..` segments.
        // Skip the leading slash, then split on `/`. The root path "/" yields a
        // single empty segment after the leading slash, which we explicitly allow.
        if value == "/" {
            return Ok(Self(value.to_owned()));
        }

        let mut prev_slash = false;
        for (i, &b) in bytes.iter().enumerate() {
            if b == b'/' {
                if prev_slash {
                    return Err(PathError::ConsecutiveSlash);
                }
                prev_slash = true;
                // Trailing slash on a non-root path is acceptable per the syntax;
                // the spec doesn't forbid it. It only forbids `//`, `.`, `..`.
                let _ = i;
            } else {
                prev_slash = false;
            }
        }

        for segment in value[1..].split('/') {
            if segment == "." || segment == ".." {
                return Err(PathError::DotSegment);
            }
        }

        Ok(Self(value.to_owned()))
    }
}

impl TryFrom<String> for EntangledPath {
    type Error = PathError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl fmt::Display for EntangledPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for EntangledPath {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for EntangledPath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::try_from(raw).map_err(serde::de::Error::custom)
    }
}
