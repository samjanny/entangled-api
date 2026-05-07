//! Integration test bundle for the `entangled-core::canon` module.
//!
//! Submodules cover the §04 normative test vector, JCS property ordering by
//! UTF-16 code units, integer serialization, string escaping, structural
//! cases, null rejection, and the §05 signature-input envelope.

#[path = "../common/mod.rs"]
mod common;

mod integration_with_types;
mod null_rejection;
mod numbers;
mod property_ordering;
mod signature_input;
mod spec_test_vector;
mod strings;
mod structure;
