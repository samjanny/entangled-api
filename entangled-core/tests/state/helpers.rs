//! Shared helpers for the state test bundle.

use entangled_core::crypto::{PublisherSigningKey, RuntimeSigningKey};
use entangled_core::types::{
    keys::{PublisherPubkey, RuntimePubkey},
    slug::Slug,
    state::{StateMode, StatePolicyEntry, StateUpdateOp},
    timestamp::EntangledTimestamp,
};

pub fn pub_from_seed(byte: u8) -> PublisherPubkey {
    let seed = [byte; 32];
    PublisherSigningKey::from_seed(&seed).verifying_key()
}

pub fn rt_from_seed(byte: u8) -> RuntimePubkey {
    let seed = [byte; 32];
    RuntimeSigningKey::from_seed(&seed).verifying_key()
}

/// Single fixed RuntimePubkey to thread through tests that don't care about
/// rotation. Tests targeting §07 N53 specifically use distinct seeds.
pub fn default_runtime() -> RuntimePubkey {
    rt_from_seed(0xAA)
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
