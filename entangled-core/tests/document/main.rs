//! Integration test bundle for the `entangled-core::document` module.

#[path = "../common/mod.rs"]
mod common;

mod build_parse_roundtrip;
mod cross_kind_rejection;
mod envelope_helpers;
mod fixtures;
mod integration_pip_to_verify;
mod parse_pipeline_errors;
mod payload_consistency;
mod tampering_rejected;
