//! Ed25519 public-key, signature, and SHA-256 newtypes plus `SpecVersion`
//! (§02).

use std::fmt;

use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

const KEY_BYTES: usize = 32;
const KEY_BASE64URL_LEN: usize = 43;
const SIG_BYTES: usize = 64;
const SIG_BASE64URL_LEN: usize = 86;

/// Reasons a string fails to decode as a 32-byte public-key newtype.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyDecodeError {
    /// Input is not exactly 43 base64url characters.
    #[error("expected {KEY_BASE64URL_LEN} base64url characters (no padding), got {0}")]
    InvalidLength(usize),
    /// Input is not valid unpadded base64url.
    #[error("input is not valid unpadded base64url")]
    InvalidEncoding,
    /// Decoded bytes are not exactly 32 in length.
    #[error("decoded byte length is not {KEY_BYTES}")]
    InvalidByteLength,
}

/// Reasons a string fails to decode as a 64-byte [`Signature`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SignatureDecodeError {
    /// Input is not exactly 86 base64url characters.
    #[error("expected {SIG_BASE64URL_LEN} base64url characters (no padding), got {0}")]
    InvalidLength(usize),
    /// Input is not valid unpadded base64url.
    #[error("input is not valid unpadded base64url")]
    InvalidEncoding,
    /// Decoded bytes are not exactly 64 in length.
    #[error("decoded byte length is not {SIG_BYTES}")]
    InvalidByteLength,
}

fn decode_key_b64(input: &str) -> Result<[u8; KEY_BYTES], KeyDecodeError> {
    if input.len() != KEY_BASE64URL_LEN {
        return Err(KeyDecodeError::InvalidLength(input.len()));
    }
    let decoded = BASE64URL_NOPAD
        .decode(input.as_bytes())
        .map_err(|_| KeyDecodeError::InvalidEncoding)?;
    if decoded.len() != KEY_BYTES {
        return Err(KeyDecodeError::InvalidByteLength);
    }
    let mut out = [0u8; KEY_BYTES];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn decode_sig_b64(input: &str) -> Result<[u8; SIG_BYTES], SignatureDecodeError> {
    if input.len() != SIG_BASE64URL_LEN {
        return Err(SignatureDecodeError::InvalidLength(input.len()));
    }
    let decoded = BASE64URL_NOPAD
        .decode(input.as_bytes())
        .map_err(|_| SignatureDecodeError::InvalidEncoding)?;
    if decoded.len() != SIG_BYTES {
        return Err(SignatureDecodeError::InvalidByteLength);
    }
    let mut out = [0u8; SIG_BYTES];
    out.copy_from_slice(&decoded);
    Ok(out)
}

macro_rules! key32_newtype {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        ///
        /// On the wire: 43 unpadded base64url characters decoding to 32 bytes.
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; KEY_BYTES]);

        impl $name {
            /// Borrow the raw 32 bytes.
            pub fn as_bytes(&self) -> &[u8; KEY_BYTES] {
                &self.0
            }

            /// Build from raw 32 bytes (no validation).
            pub fn from_bytes(bytes: [u8; KEY_BYTES]) -> Self {
                Self(bytes)
            }
        }

        impl<'a> TryFrom<&'a str> for $name {
            type Error = KeyDecodeError;

            fn try_from(value: &'a str) -> Result<Self, Self::Error> {
                Ok(Self(decode_key_b64(value)?))
            }
        }

        impl TryFrom<String> for $name {
            type Error = KeyDecodeError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::try_from(value.as_str())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&BASE64URL_NOPAD.encode(&self.0))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let raw = String::deserialize(deserializer)?;
                Self::try_from(raw).map_err(serde::de::Error::custom)
            }
        }
    };
}

key32_newtype!(
    PublisherPubkey,
    "Publisher long-term Ed25519 public key (§02)."
);
key32_newtype!(
    OriginPubkey,
    "Origin Ed25519 public key bound to a Tor v3 onion address (§05)."
);
key32_newtype!(
    RuntimePubkey,
    "Runtime Ed25519 public key used to sign canary statements (§02 canary, §08)."
);
key32_newtype!(
    ImageSha256,
    "SHA-256 digest of an image's encoded bytes (§03 image block)."
);

/// An Ed25519 signature: 64 bytes, encoded on the wire as 86 unpadded
/// base64url characters.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signature([u8; SIG_BYTES]);

impl Signature {
    /// Borrow the raw 64 bytes.
    pub fn as_bytes(&self) -> &[u8; SIG_BYTES] {
        &self.0
    }

    /// Build from raw 64 bytes (no validation).
    pub fn from_bytes(bytes: [u8; SIG_BYTES]) -> Self {
        Self(bytes)
    }
}

impl<'a> TryFrom<&'a str> for Signature {
    type Error = SignatureDecodeError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        Ok(Self(decode_sig_b64(value)?))
    }
}

impl TryFrom<String> for Signature {
    type Error = SignatureDecodeError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&BASE64URL_NOPAD.encode(&self.0))
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({self})")
    }
}

impl Serialize for Signature {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::try_from(raw).map_err(serde::de::Error::custom)
    }
}

const SPEC_VERSION_LITERAL: &str = "1.0";

/// Marker for the protocol version literal `"1.0"`.
///
/// The wire form is the JSON string `"1.0"`. Any other value is rejected at
/// deserialization with [`SpecVersionError::Mismatch`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct SpecVersion;

/// Error produced when a `spec_version` field is not exactly `"1.0"`.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SpecVersionError {
    /// The wire `spec_version` value did not equal `"1.0"`.
    #[error("spec_version must be exactly \"1.0\"")]
    Mismatch,
}

impl fmt::Display for SpecVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(SPEC_VERSION_LITERAL)
    }
}

impl Serialize for SpecVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(SPEC_VERSION_LITERAL)
    }
}

impl<'de> Deserialize<'de> for SpecVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        if raw == SPEC_VERSION_LITERAL {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(SpecVersionError::Mismatch))
        }
    }
}
