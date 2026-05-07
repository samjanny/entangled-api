//! Policy-aware state update validation (`E_STATE_UNDECLARED`,
//! `E_STATE_VALUE_SIZE`, `E_STATE_TTL`).

use entangled_core::types::slug::Slug;
use entangled_core::types::state::{StateMode, StatePolicyEntry, StateUpdateOp};
use entangled_core::validation::policy_check::validate_state_updates_against_policy;
use entangled_core::validation::DiagnosticCode;

fn slug(s: &str) -> Slug {
    Slug::try_from(s).unwrap()
}

fn policy(max_size: u32, max_lifetime: u32) -> Vec<StatePolicyEntry> {
    vec![StatePolicyEntry {
        namespace: slug("session"),
        key: slug("auth"),
        mode: StateMode::Request,
        max_size,
        max_lifetime,
        purpose: "test".to_owned(),
    }]
}

fn set_op(namespace: &str, key: &str, value_len: usize, ttl: u32) -> StateUpdateOp {
    StateUpdateOp::Set {
        namespace: slug(namespace),
        key: slug(key),
        value: "x".repeat(value_len),
        ttl,
    }
}

fn delete_op(namespace: &str, key: &str) -> StateUpdateOp {
    StateUpdateOp::Delete {
        namespace: slug(namespace),
        key: slug(key),
    }
}

#[test]
fn declared_set_within_caps_ok() {
    let p = policy(4096, 86_400);
    let ops = vec![set_op("session", "auth", 100, 3600)];
    validate_state_updates_against_policy(&ops, &p).unwrap();
}

#[test]
fn undeclared_namespace_key_rejected() {
    let p = policy(4096, 86_400);
    let ops = vec![set_op("nope", "missing", 100, 3600)];
    let err = validate_state_updates_against_policy(&ops, &p).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::EStateUndeclared);
}

#[test]
fn value_oversize_vs_policy_rejected() {
    let p = policy(4096, 86_400);
    let ops = vec![set_op("session", "auth", 5000, 3600)];
    let err = validate_state_updates_against_policy(&ops, &p).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::EStateValueSize);
}

#[test]
fn value_within_policy_max_size_ok() {
    let p = policy(4096, 86_400);
    let ops = vec![set_op("session", "auth", 4000, 3600)];
    validate_state_updates_against_policy(&ops, &p).unwrap();
}

#[test]
fn ttl_above_max_lifetime_rejected() {
    let p = policy(4096, 86_400);
    // 100_000 > 86_400, but still within absolute hard range.
    let ops = vec![set_op("session", "auth", 10, 100_000)];
    let err = validate_state_updates_against_policy(&ops, &p).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::EStateTtl);
}

#[test]
fn ttl_below_absolute_minimum_rejected() {
    let p = policy(4096, 86_400);
    let ops = vec![set_op("session", "auth", 10, 100)];
    let err = validate_state_updates_against_policy(&ops, &p).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::EStateTtl);
}

#[test]
fn delete_declared_ok() {
    let p = policy(4096, 86_400);
    let ops = vec![delete_op("session", "auth")];
    validate_state_updates_against_policy(&ops, &p).unwrap();
}

#[test]
fn delete_undeclared_rejected() {
    let p = policy(4096, 86_400);
    let ops = vec![delete_op("nope", "missing")];
    let err = validate_state_updates_against_policy(&ops, &p).unwrap_err();
    assert_eq!(err.code, DiagnosticCode::EStateUndeclared);
}
