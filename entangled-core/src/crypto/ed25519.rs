//! Minimal Ed25519 wrapper around `ed25519_dalek`.
//!
//! Operates on the 32-byte/64-byte newtypes from [`crate::types`] rather than
//! raw byte arrays. Signing is infallible (RFC 8032 makes Ed25519 signing total
//! over arbitrary input). Verification reduces every internal failure to
//! [`CryptoError::VerificationFailed`] — the call site uses the strongly-typed
//! `Signature` and `*Pubkey` newtypes for syntactic validity, so any
//! cryptographic mismatch reaching this layer is by definition a verification
//! failure.
//!
//! The crate-private `SigningKey` is not exposed to downstream callers.
//! Two role-tagged newtypes — [`PublisherSigningKey`] and
//! [`RuntimeSigningKey`] — wrap it and gate the high-level
//! [`crate::crypto::sign_manifest_payload`],
//! [`crate::crypto::sign_content_payload`], and
//! [`crate::crypto::sign_transaction_payload`] helpers, so a content
//! document cannot be signed by a manifest-role key (and vice versa) at
//! compile time.

use ed25519_dalek::Signer as _;
use thiserror::Error;

use crate::types::{OriginPubkey, PublisherPubkey, RuntimePubkey, Signature};

/// Errors produced by Ed25519 verification.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    /// The 32-byte public key fails the §05 strict profile: either it does
    /// not decode to a canonical Ed25519 curve point, or it decodes to a
    /// small-order point (order divides the cofactor 8).
    ///
    /// Per §05, both rejection causes mean "the document being verified
    /// under that key is rejected as a signature failure". Higher-level
    /// callers therefore map this variant to `E_SIG_VERIFICATION` (§11),
    /// not `E_SIG_INVALID_KEY` — the latter is reserved for "the expected
    /// verification key is not available" (e.g. no manifest from which to
    /// resolve `runtime_pubkey`).
    #[error("Ed25519 public key fails the §05 strict profile (non-canonical or small-order)")]
    InvalidPublicKey,
    /// Strict signature verification failed (forged, tampered, or
    /// wrong-key signature).
    #[error("Ed25519 signature verification failed")]
    VerificationFailed,
}

/// Edwards25519 field prime `p = 2^255 - 19`, encoded as the 32 little-
/// endian bytes of `y` in a canonical Ed25519 public key. A canonical
/// encoding has `y < p` after masking off the high bit (which holds the
/// sign of `x`, per RFC 8032 §5.1.2). Values `y >= p` are non-canonical
/// even though `curve25519_dalek::FieldElement::from_bytes` silently
/// reduces them under ZIP-215 acceptance.
const ED25519_FIELD_PRIME_LE: [u8; 32] = [
    0xED, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,
];

/// Compare two little-endian 32-byte unsigned integers: returns `true`
/// when `a < b`. Constant-ish (early-exit on first differing byte from
/// MSB); we only call this on attacker-controllable public material and
/// the comparison result is itself the security boundary, so timing
/// leakage is not in scope here.
#[inline]
fn lt_le_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        match a[i].cmp(&b[i]) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => {}
        }
    }
    false
}

/// Reject Ed25519 public keys whose `y`-coordinate encoding is non-canonical
/// (i.e. `y >= p` where `p = 2^255 - 19`).
///
/// `ed25519_dalek::VerifyingKey::from_bytes` follows ZIP-215 (see
/// `curve25519-dalek#626`), under which `curve25519_dalek::FieldElement`
/// silently reduces `y mod p`. Two byte-distinct encodings of the same
/// underlying point would therefore both decode successfully — a
/// closed-grammar violation under §05's "non-canonical encodings are
/// rejected" rule. This function closes that gap by rejecting any
/// 32-byte encoding whose low 255 bits exceed the field prime.
fn validate_pubkey_canonical_encoding(bytes: &[u8; 32]) -> Result<(), CryptoError> {
    // Mask off the high bit at byte 31 (sign of x), leaving the 255-bit
    // `y` value little-endian.
    let mut y = *bytes;
    y[31] &= 0x7F;
    if !lt_le_32(&y, &ED25519_FIELD_PRIME_LE) {
        return Err(CryptoError::InvalidPublicKey);
    }
    Ok(())
}

/// Strict §05 public-key validation: canonical encoding **and** non-small-order.
///
/// Three checks, in order:
///
/// 1. Canonical encoding: the 32-byte `y`-coordinate (masked of its sign
///    bit) MUST be strictly less than the field prime `p = 2^255 - 19`.
///    Closes the ZIP-215 gap left by
///    `ed25519_dalek::VerifyingKey::from_bytes`, which accepts
///    non-canonical encodings (`y >= p` silently reduced).
/// 2. Decompression to a valid curve point.
/// 3. Non-small-order: the point's order must not divide the cofactor 8,
///    enforced via `VerifyingKey::is_weak`.
///
/// Use this helper when the strict profile must hold at a pipeline stage
/// other than ordinary signature verification — for example, validating
/// `canary.runtime_pubkey` at Stage 8 or `origin.origin_pubkey` at
/// Stage 9. For ordinary signature verification, [`VerifyingKey::verify`]
/// also invokes this helper indirectly via [`Self::from_pubkey_bytes`].
pub fn validate_pubkey_strict(bytes: &[u8; 32]) -> Result<(), CryptoError> {
    validate_pubkey_canonical_encoding(bytes)?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(bytes)
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    if vk.is_weak() {
        return Err(CryptoError::InvalidPublicKey);
    }
    Ok(())
}

/// Strict-profile validation specialized for [`PublisherPubkey`].
///
/// See [`validate_pubkey_strict`] for the contract.
pub fn validate_publisher_pubkey_strict(pk: &PublisherPubkey) -> Result<(), CryptoError> {
    validate_pubkey_strict(pk.as_bytes())
}

/// Strict-profile validation specialized for [`RuntimePubkey`].
///
/// See [`validate_pubkey_strict`] for the contract.
pub fn validate_runtime_pubkey_strict(pk: &RuntimePubkey) -> Result<(), CryptoError> {
    validate_pubkey_strict(pk.as_bytes())
}

/// Strict-profile validation specialized for [`OriginPubkey`].
///
/// See [`validate_pubkey_strict`] for the contract.
pub fn validate_origin_pubkey_strict(pk: &OriginPubkey) -> Result<(), CryptoError> {
    validate_pubkey_strict(pk.as_bytes())
}

/// An Ed25519 signing key (private key + cached verifying key).
///
/// Crate-private: external callers must use the role-tagged
/// [`PublisherSigningKey`] / [`RuntimeSigningKey`] newtypes to obtain
/// signing capability.
pub(crate) struct SigningKey(ed25519_dalek::SigningKey);

/// An Ed25519 verifying key (public key) suitable for `verify_strict`.
pub struct VerifyingKey(ed25519_dalek::VerifyingKey);

impl SigningKey {
    /// Generate a fresh keypair from operating-system entropy.
    ///
    /// Test-only: gated behind `#[cfg(test)]` and the `test-utils` feature so
    /// that production code paths never accidentally generate keys this way.
    /// Uses `getrandom` for cross-platform OS RNG access (Linux `getrandom(2)`,
    /// `BCryptGenRandom` on Windows, `arc4random_buf` on the BSDs, etc.) —
    /// this is the de-facto standard for OS-level entropy in Rust.
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn generate() -> Self {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("OS RNG unavailable");
        Self::from_seed(&seed)
    }

    /// Build a `SigningKey` from a 32-byte seed (the RFC 8032 secret key).
    pub(crate) fn from_seed(seed: &[u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(seed))
    }

    /// Return the [`VerifyingKey`] (public key) for this signing key.
    pub(crate) fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key())
    }

    /// Sign an arbitrary input. Infallible per RFC 8032.
    pub(crate) fn sign(&self, input: &[u8]) -> Signature {
        let sig: ed25519_dalek::Signature = self.0.sign(input);
        Signature::from_bytes(sig.to_bytes())
    }
}

/// Publisher identity signing key. Used to sign manifests only.
///
/// `K_publisher` (§05) is the publisher's long-term identity key: it is
/// generated offline and used only during publisher ceremonies to sign
/// manifests authorizing operational keys. The newtype is deliberately
/// distinct from [`RuntimeSigningKey`] and not interconvertible with it
/// at the public API level: this prevents accidental cross-role signing
/// (e.g. signing a content document with the publisher key and
/// verifying it against `runtime_pubkey` after a coercion bug).
///
/// ```compile_fail
/// // Cross-role bypass attempt: build_content expects a RuntimeSigningKey,
/// // not a PublisherSigningKey. This must not compile.
/// use entangled_core::crypto::PublisherSigningKey;
/// use entangled_core::document::{build_content, UnsignedContent};
/// fn _no_compile(unsigned: &UnsignedContent) {
///     let key = PublisherSigningKey::from_seed(&[0x42; 32]);
///     let _ = build_content(unsigned, &key);
/// }
/// ```
pub struct PublisherSigningKey(SigningKey);

/// Runtime operational signing key. Used to sign content and transaction
/// documents within an authorized publication cycle.
///
/// `K_runtime` (§05, §08) is rotated per publication cycle; the
/// corresponding public key is declared in the manifest's canary. The
/// newtype is deliberately distinct from [`PublisherSigningKey`] and
/// not interconvertible with it at the public API level.
pub struct RuntimeSigningKey(SigningKey);

impl PublisherSigningKey {
    /// Generate a fresh publisher keypair from OS entropy.
    ///
    /// Test-only: gated behind `#[cfg(test)]` and the `test-utils`
    /// feature. Production publisher ceremonies generate `K_publisher`
    /// offline through their own procedures, not through this function.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn generate() -> Self {
        Self(SigningKey::generate())
    }

    /// Build a [`PublisherSigningKey`] from a 32-byte seed
    /// (the RFC 8032 secret key).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_seed(seed))
    }

    /// Return the [`PublisherPubkey`] derived from this signing key.
    pub fn verifying_key(&self) -> PublisherPubkey {
        self.0.verifying_key().to_publisher_pubkey()
    }

    /// Sign an arbitrary byte string under this key. Crate-private: high-level
    /// callers must go through the role-typed
    /// [`crate::crypto::sign_manifest_payload`] helper (or, for unit-test
    /// access, the crate's internal sign primitives).
    pub(crate) fn sign(&self, input: &[u8]) -> Signature {
        self.0.sign(input)
    }
}

impl RuntimeSigningKey {
    /// Generate a fresh runtime keypair from OS entropy.
    ///
    /// Test-only: gated behind `#[cfg(test)]` and the `test-utils`
    /// feature.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn generate() -> Self {
        Self(SigningKey::generate())
    }

    /// Build a [`RuntimeSigningKey`] from a 32-byte seed
    /// (the RFC 8032 secret key).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_seed(seed))
    }

    /// Return the [`RuntimePubkey`] derived from this signing key.
    pub fn verifying_key(&self) -> RuntimePubkey {
        self.0.verifying_key().to_runtime_pubkey()
    }

    /// Sign an arbitrary byte string under this key. Crate-private: high-level
    /// callers must go through the role-typed
    /// [`crate::crypto::sign_content_payload`] /
    /// [`crate::crypto::sign_transaction_payload`] helpers.
    pub(crate) fn sign(&self, input: &[u8]) -> Signature {
        self.0.sign(input)
    }
}

impl VerifyingKey {
    /// Parse a [`PublisherPubkey`] into a [`VerifyingKey`].
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidPublicKey`] if the 32 bytes do not
    /// decode to a valid Ed25519 point.
    pub fn from_publisher_pubkey(pk: &PublisherPubkey) -> Result<Self, CryptoError> {
        Self::from_pubkey_bytes(pk.as_bytes())
    }

    /// Parse an [`OriginPubkey`] into a [`VerifyingKey`].
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidPublicKey`] on a malformed key.
    pub fn from_origin_pubkey(pk: &OriginPubkey) -> Result<Self, CryptoError> {
        Self::from_pubkey_bytes(pk.as_bytes())
    }

    /// Parse a [`RuntimePubkey`] into a [`VerifyingKey`].
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidPublicKey`] on a malformed key.
    pub fn from_runtime_pubkey(pk: &RuntimePubkey) -> Result<Self, CryptoError> {
        Self::from_pubkey_bytes(pk.as_bytes())
    }

    fn from_pubkey_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        // Canonical-encoding check before delegating to dalek's
        // ZIP-215-accepting decoder. See `validate_pubkey_strict` for
        // the full rationale.
        validate_pubkey_canonical_encoding(bytes)?;
        let vk = ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        if vk.is_weak() {
            return Err(CryptoError::InvalidPublicKey);
        }
        Ok(VerifyingKey(vk))
    }

    /// Verify a signature on an arbitrary input.
    ///
    /// Implements the §05 Ed25519 verification profile (v1.0-rc.4): public
    /// keys MUST be in canonical encoding and MUST NOT be small-order;
    /// signatures MUST use canonical `R` and canonical `S` (`0 ≤ S < L`);
    /// verification uses the cofactorless equation `[S]B = R + [k]A`.
    /// The canonical-encoding check on the public key is performed by
    /// `from_pubkey_bytes` before this method runs (closing the ZIP-215
    /// gap in `ed25519_dalek::VerifyingKey::from_bytes`); `verify_strict`
    /// then enforces canonical `R` / canonical `S` / cofactorless
    /// verification per RFC 8032 §5.1.7.
    pub fn verify(&self, input: &[u8], sig: &Signature) -> Result<(), CryptoError> {
        let parsed = ed25519_dalek::Signature::from_bytes(sig.as_bytes());
        self.0
            .verify_strict(input, &parsed)
            .map_err(|_| CryptoError::VerificationFailed)
    }

    /// Encode the underlying 32 bytes as a [`PublisherPubkey`].
    pub fn to_publisher_pubkey(&self) -> PublisherPubkey {
        PublisherPubkey::from_bytes(self.0.to_bytes())
    }

    /// Encode the underlying 32 bytes as an [`OriginPubkey`].
    pub fn to_origin_pubkey(&self) -> OriginPubkey {
        OriginPubkey::from_bytes(self.0.to_bytes())
    }

    /// Encode the underlying 32 bytes as a [`RuntimePubkey`].
    pub fn to_runtime_pubkey(&self) -> RuntimePubkey {
        RuntimePubkey::from_bytes(self.0.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    //! Crate-internal Ed25519 wrapper sanity, including the RFC 8032 §7.1
    //! TEST 1 vector. These tests exercise the crate-private [`SigningKey`]
    //! primitive directly; integration tests in `tests/` go through the
    //! role-tagged [`PublisherSigningKey`] / [`RuntimeSigningKey`] API.

    use super::*;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2));
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn rfc8032_section_7_1_test_1() {
        // RFC 8032 §7.1 TEST 1 — the canonical Ed25519 test vector.
        let seed_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        let pubkey_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let sig_hex = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&hex_to_bytes(seed_hex));
        let signing = SigningKey::from_seed(&seed);

        // Pubkey derivation matches the spec.
        let derived: [u8; 32] = *signing.verifying_key().to_publisher_pubkey().as_bytes();
        let mut expected_pk = [0u8; 32];
        expected_pk.copy_from_slice(&hex_to_bytes(pubkey_hex));
        assert_eq!(
            derived, expected_pk,
            "RFC 8032 §7.1 TEST 1: derived public key must match"
        );

        // Signature on empty message matches the spec, byte-for-byte.
        let sig: Signature = signing.sign(b"");
        let mut expected_sig = [0u8; 64];
        expected_sig.copy_from_slice(&hex_to_bytes(sig_hex));
        assert_eq!(
            *sig.as_bytes(),
            expected_sig,
            "RFC 8032 §7.1 TEST 1: signature must be byte-exact"
        );

        // And it verifies.
        let pk = PublisherPubkey::from_bytes(expected_pk);
        let vk = VerifyingKey::from_publisher_pubkey(&pk).expect("valid pubkey");
        vk.verify(b"", &sig).expect("verify must succeed");
    }

    #[test]
    fn deterministic_keypair_round_trip_signs_and_verifies() {
        let signing = SigningKey::from_seed(&[0x11; 32]);
        let pk = signing.verifying_key().to_publisher_pubkey();
        let msg = b"hello entangled";
        let sig = signing.sign(msg);

        let vk = VerifyingKey::from_publisher_pubkey(&pk).unwrap();
        vk.verify(msg, &sig).expect("verify ok");
    }

    #[test]
    fn verify_fails_with_wrong_key() {
        let a = SigningKey::from_seed(&[0x21; 32]);
        let b = SigningKey::from_seed(&[0x22; 32]);
        let msg = b"some message";
        let sig = a.sign(msg);

        let vk_b =
            VerifyingKey::from_publisher_pubkey(&b.verifying_key().to_publisher_pubkey()).unwrap();
        assert_eq!(vk_b.verify(msg, &sig), Err(CryptoError::VerificationFailed));
    }

    #[test]
    fn verify_fails_with_modified_message() {
        let signing = SigningKey::from_seed(&[0x31; 32]);
        let pk = signing.verifying_key().to_publisher_pubkey();
        let mut msg = *b"hello world";
        let sig = signing.sign(&msg);

        msg[0] ^= 0x01;
        let vk = VerifyingKey::from_publisher_pubkey(&pk).unwrap();
        assert_eq!(vk.verify(&msg, &sig), Err(CryptoError::VerificationFailed));
    }

    #[test]
    fn malformed_pubkey_rejected_at_construction() {
        // 32-byte sequence whose Edwards-Y compressed form does not decompress
        // to a valid curve point. Empirically determined: not every 32-byte
        // string is rejected by ed25519-dalek's `from_bytes` (e.g. all-0xFF and
        // y=p both round-trip), but this incrementing pattern fails
        // decompression.
        let bad_bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];
        let bad = PublisherPubkey::from_bytes(bad_bytes);
        assert_eq!(
            VerifyingKey::from_publisher_pubkey(&bad).err(),
            Some(CryptoError::InvalidPublicKey)
        );
    }
}
