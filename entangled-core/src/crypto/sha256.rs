//! Thin wrappers around `sha2::Sha256` for the byte and base64url forms used
//! across Entangled.

use data_encoding::BASE64URL_NOPAD;
use sha2::{Digest, Sha256};

use crate::types::ImageSha256;

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// SHA-256 digest as 43-character unpadded base64url ASCII.
pub fn sha256_base64url(data: &[u8]) -> String {
    BASE64URL_NOPAD.encode(&sha256(data))
}

/// Compute a SHA-256 digest and wrap it in the typed [`ImageSha256`] newtype
/// for use in image blocks (§02 / §03).
pub fn sha256_image(data: &[u8]) -> ImageSha256 {
    ImageSha256::from_bytes(sha256(data))
}
