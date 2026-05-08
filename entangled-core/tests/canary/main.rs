//! Integration test bundle for canary validation (`entangled-core::validation::canary`).

#[path = "../common/mod.rs"]
mod common;

mod anti_downgrade;
mod conflict;
mod state;
mod structure;
