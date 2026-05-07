//! PIP (Publisher Identity Phrase) — 24-word BIP-39 representation of a
//! 32-byte `PublisherPubkey`, per §05.
//!
//! Uses the BIP-39 English wordlist (2048 words) embedded as
//! `wordlist_english.txt`. The wordlist file is the canonical version from
//! `https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt` with
//! Unix `\n` line endings. To re-fetch:
//!
//! ```text
//! curl -sSL https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt \
//!   -o entangled-core/src/crypto/wordlist_english.txt
//! ```
//!
//! Entropy/checksum layout: a 32-byte pubkey followed by an 8-bit checksum
//! (the first byte of `SHA-256(pubkey)`) yields 264 bits = 24 × 11 bits.
//! Each 11-bit group selects a wordlist entry. The bit-packing is big-endian
//! (the most significant 11 bits of the bit stream become the first word).

use std::sync::OnceLock;

use thiserror::Error;

use crate::types::PublisherPubkey;

const WORDLIST_RAW: &str = include_str!("wordlist_english.txt");

static WORDLIST: OnceLock<Vec<&'static str>> = OnceLock::new();

fn wordlist() -> &'static [&'static str] {
    WORDLIST.get_or_init(|| {
        let v: Vec<&str> = WORDLIST_RAW.lines().collect();
        debug_assert_eq!(
            v.len(),
            2048,
            "BIP-39 English wordlist must contain 2048 words"
        );
        v
    })
}

/// Errors produced when parsing a PIP back into a [`PublisherPubkey`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PipError {
    /// The whitespace-split phrase did not contain exactly 24 words.
    #[error("PIP must contain exactly 24 words, got {0}")]
    WrongWordCount(usize),
    /// One of the words is not in the BIP-39 English wordlist.
    #[error("PIP word not in BIP-39 English wordlist: {0}")]
    UnknownWord(String),
    /// The 8-bit checksum did not match `SHA-256(pubkey)[0]`.
    #[error("PIP checksum verification failed")]
    InvalidChecksum,
}

/// Derive the 24-word PIP from a publisher pubkey.
pub fn derive_pip(pubkey: &PublisherPubkey) -> String {
    let entropy: &[u8; 32] = pubkey.as_bytes();
    let checksum_full = super::sha256::sha256(entropy);
    let mut bits = [0u8; 33];
    bits[..32].copy_from_slice(entropy);
    bits[32] = checksum_full[0];
    let indices = extract_11bit_groups(&bits);
    let words = wordlist();
    let mut out = String::with_capacity(24 * 9);
    for (i, &idx) in indices.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(words[idx as usize]);
    }
    out
}

/// Recover the publisher pubkey from a 24-word PIP, validating the checksum.
///
/// Words are separated by ASCII whitespace (any number of any whitespace
/// characters).
///
/// # Errors
///
/// - [`PipError::WrongWordCount`] if the input does not contain exactly 24
///   whitespace-separated words.
/// - [`PipError::UnknownWord`] if a word is not in the BIP-39 English
///   wordlist.
/// - [`PipError::InvalidChecksum`] if the embedded 8-bit checksum does not
///   match `SHA-256(pubkey)[0]`.
pub fn pip_to_pubkey(pip: &str) -> Result<PublisherPubkey, PipError> {
    let words: Vec<&str> = pip.split_whitespace().collect();
    if words.len() != 24 {
        return Err(PipError::WrongWordCount(words.len()));
    }
    let lookup = wordlist();
    let mut indices = [0u16; 24];
    for (i, w) in words.iter().enumerate() {
        let idx = lookup
            .binary_search(w)
            .map_err(|_| PipError::UnknownWord((*w).to_string()))?;
        indices[i] = idx as u16;
    }
    let bits = pack_11bit_groups(&indices);
    let mut entropy = [0u8; 32];
    entropy.copy_from_slice(&bits[..32]);
    let checksum_byte = bits[32];
    let computed = super::sha256::sha256(&entropy);
    if computed[0] != checksum_byte {
        return Err(PipError::InvalidChecksum);
    }
    Ok(PublisherPubkey::from_bytes(entropy))
}

/// Extract 24 × 11-bit groups from a 33-byte buffer in big-endian order.
///
/// Bit numbering: bit 0 is the most significant bit of byte 0; bit 263 is the
/// least significant bit of byte 32. Group `i` covers bits `[11i, 11i + 11)`.
pub(crate) fn extract_11bit_groups(bytes: &[u8; 33]) -> [u16; 24] {
    let mut out = [0u16; 24];
    for (i, slot) in out.iter_mut().enumerate() {
        let bit_pos = i * 11;
        let byte_pos = bit_pos / 8;
        let bit_offset = bit_pos % 8;
        // Combine up to three consecutive bytes into a 24-bit big-endian window.
        let b0 = bytes[byte_pos] as u32;
        let b1 = if byte_pos + 1 < 33 {
            bytes[byte_pos + 1] as u32
        } else {
            0
        };
        let b2 = if byte_pos + 2 < 33 {
            bytes[byte_pos + 2] as u32
        } else {
            0
        };
        let combined = (b0 << 16) | (b1 << 8) | b2;
        let value = (combined >> (13 - bit_offset)) & 0x7FF;
        *slot = value as u16;
    }
    out
}

/// Inverse of [`extract_11bit_groups`].
fn pack_11bit_groups(indices: &[u16; 24]) -> [u8; 33] {
    let mut out = [0u8; 33];
    for (i, &idx) in indices.iter().enumerate() {
        let bit_pos = i * 11;
        let byte_pos = bit_pos / 8;
        let bit_offset = bit_pos % 8;
        let combined: u32 = (idx as u32) << (13 - bit_offset);
        out[byte_pos] |= ((combined >> 16) & 0xFF) as u8;
        if byte_pos + 1 < 33 {
            out[byte_pos + 1] |= ((combined >> 8) & 0xFF) as u8;
        }
        if byte_pos + 2 < 33 {
            out[byte_pos + 2] |= (combined & 0xFF) as u8;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_zero_input_yields_zero_indices() {
        let bytes = [0u8; 33];
        let indices = extract_11bit_groups(&bytes);
        assert_eq!(indices, [0u16; 24]);
    }

    #[test]
    fn extract_then_pack_roundtrip() {
        // Pseudo-random pattern with valid checksum-shaped layout (just bytes).
        let mut bytes = [0u8; 33];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
        let indices = extract_11bit_groups(&bytes);
        let recovered = pack_11bit_groups(&indices);
        assert_eq!(recovered, bytes);
    }

    #[test]
    fn extract_high_bit_pattern_first_index() {
        // First byte = 0xFF, rest 0. First 11 bits = 0b1111_1111_000 = 0x7F8.
        let mut bytes = [0u8; 33];
        bytes[0] = 0xFF;
        let indices = extract_11bit_groups(&bytes);
        assert_eq!(indices[0], 0x7F8);
    }
}
