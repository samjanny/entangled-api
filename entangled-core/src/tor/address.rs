//! Tor v3 onion-address decoding and strict verification.
//!
//! The on-the-wire form is normative per `rend-spec-v3.txt` (Tor Rendezvous
//! Specification, Version 3) cited verbatim in §05 of the Entangled spec:
//!
//! > The address is base32-encoded, contains the 32-byte Ed25519 service
//! > public key, a 2-byte checksum, and a 1-byte version field, with the
//! > lowercase `.onion` suffix appended.
//!
//! And:
//!
//! ```text
//! CHECKSUM = H(".onion checksum" || PUBKEY || VERSION)[:2]
//! ```
//!
//! where `H` is SHA3-256, `".onion checksum"` is a 15-byte ASCII literal,
//! `PUBKEY` is the 32-byte Ed25519 service key, and `VERSION` is the single
//! byte `0x03`.
//!
//! The address body is base32(RFC 4648) of `PUBKEY || CHECKSUM || VERSION`,
//! 35 bytes → 56 base32 chars, all lowercase for the canonical Tor v3 form.

use data_encoding::BASE32;
use sha3::{Digest, Sha3_256};

use crate::types::keys::OriginPubkey;
use crate::types::manifest::OnionAddress;

use super::error::TorError;

/// 15-byte ASCII string `".onion checksum"` (with the leading dot).
const CHECKSUM_PREFIX: &[u8] = b".onion checksum";

/// Tor v3 version byte.
pub const TOR_V3_VERSION: u8 = 0x03;

/// Length of the base32 body (before `.onion`): 35 bytes encode to 56 chars.
const ONION_BODY_LEN: usize = 56;

/// Decoded byte components of a Tor v3 onion address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedOnionAddress {
    /// 32-byte Ed25519 service public key.
    pub pubkey: [u8; 32],
    /// 2 bytes of `SHA3-256(".onion checksum" || pubkey || version)`.
    pub checksum: [u8; 2],
    /// Tor onion-service version byte; always `0x03` for v3.
    pub version: u8,
}

impl OnionAddress {
    /// Decode the 56-char base32 body into the 35 raw bytes
    /// (pubkey 32 + checksum 2 + version 1).
    ///
    /// Performs structural checks only: the lowercase RFC 4648 alphabet and
    /// the 35-byte length. Does **not** verify the checksum or the version —
    /// use [`OnionAddress::verify_strict`] for that.
    pub fn decode(&self) -> Result<DecodedOnionAddress, TorError> {
        let s = self.as_str();
        // Suffix and length are already enforced at construction time; the
        // length check is structurally redundant but defensive.
        if !s.ends_with(".onion") {
            return Err(TorError::MissingOnionSuffix);
        }
        let body = &s[..ONION_BODY_LEN];
        if body.len() != ONION_BODY_LEN {
            return Err(TorError::WrongLength);
        }

        for &b in body.as_bytes() {
            let is_lower_letter = b.is_ascii_lowercase();
            let is_digit_2_to_7 = (b'2'..=b'7').contains(&b);
            if is_lower_letter || is_digit_2_to_7 {
                continue;
            }
            if b.is_ascii_uppercase() {
                return Err(TorError::NotLowercase);
            }
            return Err(TorError::InvalidBase32);
        }

        // RFC 4648 BASE32 in `data-encoding` accepts uppercase. Convert for
        // decoding only; the canonical lowercase form is preserved on `self`.
        let upper = body.to_ascii_uppercase();
        let decoded = BASE32
            .decode(upper.as_bytes())
            .map_err(|_| TorError::InvalidBase32)?;
        if decoded.len() != 35 {
            return Err(TorError::InvalidBase32);
        }

        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&decoded[0..32]);
        let mut checksum = [0u8; 2];
        checksum.copy_from_slice(&decoded[32..34]);
        let version = decoded[34];

        Ok(DecodedOnionAddress {
            pubkey,
            checksum,
            version,
        })
    }

    /// Extract the embedded Ed25519 service pubkey. Fast-path: does **not**
    /// verify the checksum or the version byte — callers that want the full
    /// integrity guarantee should call [`OnionAddress::verify_strict`] first.
    pub fn pubkey(&self) -> Result<OriginPubkey, TorError> {
        let decoded = self.decode()?;
        Ok(OriginPubkey::from_bytes(decoded.pubkey))
    }

    /// Strict verification per §05: decode, then check `version == 0x03` and
    /// recompute the SHA3-256 checksum, comparing byte-exact against the
    /// embedded prefix.
    pub fn verify_strict(&self) -> Result<DecodedOnionAddress, TorError> {
        let decoded = self.decode()?;
        if decoded.version != TOR_V3_VERSION {
            return Err(TorError::WrongVersion(decoded.version));
        }
        let mut hasher = Sha3_256::new();
        hasher.update(CHECKSUM_PREFIX);
        hasher.update(decoded.pubkey);
        hasher.update([decoded.version]);
        let digest = hasher.finalize();
        let expected = [digest[0], digest[1]];
        if expected != decoded.checksum {
            return Err(TorError::BadChecksum);
        }
        Ok(decoded)
    }
}

// Compile-time assertion that the SHA3-256 input prefix is exactly the 15
// bytes spelled out in `rend-spec-v3.txt`.
const _: () = assert!(CHECKSUM_PREFIX.len() == 15);
