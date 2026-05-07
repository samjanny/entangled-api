//! Integration test bundle for the `entangled-core::validation` module.
//!
//! Submodules are organized per-stage for parity with §10 of the spec.

#[path = "../common/mod.rs"]
mod common;

mod diagnostic_codes;
mod error_precedence;
mod limits;
mod stage2_input;
mod stage3_parse;
mod stage4_kind;
mod stage5_schema;
