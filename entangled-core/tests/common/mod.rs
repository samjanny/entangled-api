//! Shared fixtures for tests. Not a `#[cfg(test)]` module; integration tests
//! pick this up via `mod common;`.

#![allow(dead_code)]

use entangled_core::types::{
    blocks::{Block, FeedbackVariant},
    canary::Canary,
    document::{ContentDocument, TransactionDocument},
    inline::{InlineElement, TextMark},
    keys::{
        ImageSha256, OriginPubkey, PublisherPubkey, RequestHash, RequestId, RuntimePubkey,
        Signature, SpecVersion,
    },
    manifest::{Carrier, Manifest, OnionAddress, Origin},
    meta::Meta,
    path::EntangledPath,
    timestamp::EntangledTimestamp,
};

/// 43 zero base64url chars → 32 zero bytes.
pub const KEY_ZEROS: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// 51 ASCII chars: `sha-256:` + 43 zero base64url chars → 32 zero bytes.
pub const SHA256_PREFIXED_ZEROS: &str = "sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// 22 zero base64url chars → 16 zero bytes (submit `request_id`).
pub const REQUEST_ID_ZEROS: &str = "AAAAAAAAAAAAAAAAAAAAAA";

/// 86 zero base64url chars → 64 zero bytes.
pub const SIG_ZEROS: &str =
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

pub const ONION_ADDR: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";

pub fn pubkey_zero() -> PublisherPubkey {
    PublisherPubkey::try_from(KEY_ZEROS).unwrap()
}

pub fn origin_key_zero() -> OriginPubkey {
    OriginPubkey::try_from(KEY_ZEROS).unwrap()
}

pub fn runtime_key_zero() -> RuntimePubkey {
    RuntimePubkey::try_from(KEY_ZEROS).unwrap()
}

pub fn signature_zero() -> Signature {
    Signature::try_from(SIG_ZEROS).unwrap()
}

pub fn image_sha_zero() -> ImageSha256 {
    ImageSha256::try_from(SHA256_PREFIXED_ZEROS).unwrap()
}

pub fn request_id_zero() -> RequestId {
    RequestId::try_from(REQUEST_ID_ZEROS).unwrap()
}

pub fn request_hash_zero() -> RequestHash {
    RequestHash::try_from(SHA256_PREFIXED_ZEROS).unwrap()
}

pub fn ts(s: &str) -> EntangledTimestamp {
    EntangledTimestamp::try_from(s).unwrap()
}

/// Deterministic "now" used as the wall-clock argument for the public
/// manifest pipeline (`parse_and_verify_manifest`, `build_manifest`, etc.).
/// Aligned with [`minimal_manifest`]'s `updated` so existing fixtures pass
/// the §06 clock-skew check unchanged.
pub fn fixed_now() -> EntangledTimestamp {
    ts("2026-05-07T00:00:00Z")
}

pub fn path(s: &str) -> EntangledPath {
    EntangledPath::try_from(s).unwrap()
}

pub fn onion() -> OnionAddress {
    OnionAddress::try_from(ONION_ADDR).unwrap()
}

pub fn minimal_canary() -> Canary {
    Canary {
        runtime_pubkey: runtime_key_zero(),
        issued_at: ts("2026-05-07T00:00:00Z"),
        next_expected: ts("2026-06-07T00:00:00Z"),
        statement: "All clear.".to_owned(),
        freshness_proof: None,
    }
}

pub fn minimal_manifest() -> Manifest {
    Manifest {
        spec_version: SpecVersion,
        publisher_pubkey: pubkey_zero(),
        origin: Origin {
            carrier: Carrier::TorV3,
            address: onion(),
            origin_pubkey: origin_key_zero(),
        },
        canary: minimal_canary(),
        state_policy: vec![],
        navigation: vec![],
        min_refresh_interval: 86_400,
        updated: ts("2026-05-07T00:00:00Z"),
        sig: signature_zero(),
    }
}

pub fn minimal_paragraph() -> Block {
    Block::Paragraph {
        content: vec![InlineElement::Text {
            value: "Hello.".to_owned(),
            marks: Vec::<TextMark>::new(),
        }],
    }
}

pub fn minimal_content_doc() -> ContentDocument {
    ContentDocument {
        spec_version: SpecVersion,
        path: path("/articles/first"),
        meta: Meta {
            title: "First post".to_owned(),
            published_at: ts("2026-05-07T00:00:00Z"),
        },
        blocks: vec![minimal_paragraph()],
        sig: signature_zero(),
    }
}

pub fn minimal_transaction_doc() -> TransactionDocument {
    TransactionDocument {
        spec_version: SpecVersion,
        in_response_to: path("/contact"),
        request_id: request_id_zero(),
        request_hash: request_hash_zero(),
        state_updates: vec![],
        blocks: vec![Block::Feedback {
            variant: FeedbackVariant::Success,
            content: vec![InlineElement::Text {
                value: "Received.".to_owned(),
                marks: Vec::<TextMark>::new(),
            }],
        }],
        sig: signature_zero(),
    }
}
