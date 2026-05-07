//! Shared helpers for the state test bundle.

use entangled_core::crypto::ed25519::SigningKey;
use entangled_core::types::{
    keys::PublisherPubkey,
    slug::Slug,
    state::{StateMode, StatePolicyEntry, StateUpdateOp},
    timestamp::EntangledTimestamp,
};

pub fn pub_from_seed(byte: u8) -> PublisherPubkey {
    let seed = [byte; 32];
    SigningKey::from_seed(&seed)
        .verifying_key()
        .to_publisher_pubkey()
}

pub fn slug(s: &str) -> Slug {
    Slug::try_from(s).unwrap()
}

pub fn ts(s: &str) -> EntangledTimestamp {
    EntangledTimestamp::try_from(s).unwrap()
}

pub fn set_op(namespace: &str, key: &str, value: &str, ttl: u32) -> StateUpdateOp {
    StateUpdateOp::Set {
        namespace: slug(namespace),
        key: slug(key),
        value: value.to_owned(),
        ttl,
    }
}

pub fn delete_op(namespace: &str, key: &str) -> StateUpdateOp {
    StateUpdateOp::Delete {
        namespace: slug(namespace),
        key: slug(key),
    }
}

pub fn policy_entry(
    namespace: &str,
    key: &str,
    mode: StateMode,
    max_size: u32,
    max_lifetime: u32,
) -> StatePolicyEntry {
    StatePolicyEntry {
        namespace: slug(namespace),
        key: slug(key),
        mode,
        max_size,
        max_lifetime,
        purpose: "test purpose".to_owned(),
    }
}
