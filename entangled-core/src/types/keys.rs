use std::fmt;

use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

const KEY_BYTES: usize = 32;
const KEY_BASE64URL_LEN: usize = 43;
const SIG_BYTES: usize = 64;
const SIG_BASE64URL_LEN: usize = 86;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyDecodeError {
    #[error("expected {KEY_BASE64URL_LEN} base64url characters (no padding), got {0}")]
    InvalidLength(usize),
    #[error("input is not valid unpadded base64url")]
    InvalidEncoding,
    #[error("decoded byte length is not {KEY_BYTES}")]
    InvalidByteLength,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SignatureDecodeError {
    #[error("expected {SIG_BASE64URL_LEN} base64url characters (no padding), got {0}")]
    InvalidLength(usize),
    #[error("input is not valid unpadded base64url")]
    InvalidEncoding,
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
    ($name:ident) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; KEY_BYTES]);

        impl $name {
            pub fn as_bytes(&self) -> &[u8; KEY_BYTES] {
                &self.0
            }

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

key32_newtype!(PublisherPubkey);
key32_newtype!(OriginPubkey);
key32_newtype!(RuntimePubkey);
key32_newtype!(ImageSha256);

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signature([u8; SIG_BYTES]);

impl Signature {
    pub fn as_bytes(&self) -> &[u8; SIG_BYTES] {
        &self.0
    }

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct SpecVersion;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SpecVersionError {
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
