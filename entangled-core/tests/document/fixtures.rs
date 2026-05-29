//! Shared fixtures for `document/` tests.

use entangled_core::document::{UnsignedContent, UnsignedManifest, UnsignedTransaction};
use entangled_core::types::{
    blocks::{Block, FeedbackVariant},
    canary::Canary,
    inline::{InlineElement, TextMark},
    keys::SpecVersion,
    manifest::{Carrier, Origin},
    meta::Meta,
};

use super::common::{
    onion, origin_key_zero, path, request_hash_zero, request_id_zero, runtime_key_zero,
    signature_zero, ts,
};

pub fn unsigned_manifest_with_publisher(
    publisher_pubkey: entangled_core::types::keys::PublisherPubkey,
) -> UnsignedManifest {
    UnsignedManifest {
        spec_version: SpecVersion,
        publisher_pubkey,
        origin: Origin {
            carrier: Carrier::TorV3,
            address: onion(),
            origin_pubkey: origin_key_zero(),
            not_after: None,
        },
        canary: Canary {
            runtime_pubkey: runtime_key_zero(),
            issued_at: ts("2026-05-07T00:00:00Z").into(),
            next_expected: ts("2026-06-06T00:00:00Z").into(),
            statement: "All clear.".to_owned(),
            freshness_proof: None,
        },
        state_policy: vec![],
        navigation: vec![],
        min_refresh_interval: 86_400,
        updated: ts("2026-05-07T00:00:00Z"),
        migration_pointer: None,
        content_root: None,
    }
}

pub fn unsigned_content() -> UnsignedContent {
    UnsignedContent {
        spec_version: SpecVersion,
        path: path("/articles/first"),
        meta: Meta {
            title: "First post".to_owned(),
            published_at: ts("2026-05-07T00:00:00Z"),
        },
        blocks: vec![Block::Paragraph {
            content: vec![InlineElement::Text {
                value: "Hello.".to_owned(),
                marks: Vec::<TextMark>::new(),
            }],
        }],
        seq: None,
    }
}

pub fn unsigned_transaction() -> UnsignedTransaction {
    UnsignedTransaction {
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
    }
}

/// Marker so an unused-import warning surfaces when `signature_zero` is
/// dropped from common in a future refactor.
#[allow(dead_code)]
pub fn _force_signature_zero_link() -> entangled_core::types::keys::Signature {
    signature_zero()
}
