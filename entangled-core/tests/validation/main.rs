//! Integration test bundle for the `entangled-core::validation` module.
//!
//! Submodules are organized per-stage for parity with §10 of the spec.

#[path = "../common/mod.rs"]
mod common;

mod array_boundaries;
mod diagnostic_codes;
mod error_precedence;
mod limits;
mod manifest_clock_skew;
mod migration;
mod origin_not_after;
mod policy_check;
mod stage2_input;
mod stage3_parse;
mod stage4_kind;
mod stage5_schema;
mod submit_body_validate;
