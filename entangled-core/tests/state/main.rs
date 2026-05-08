//! Integration test bundle for `entangled-core::state` and the
//! state-related validators in `entangled-core::validation`.

#[path = "../common/mod.rs"]
mod common;

mod helpers;

mod integration_full;
mod stateless_mode;
mod store_basic;
mod store_cleanup;
mod store_consent;
mod store_mode_preservation;
mod store_request_state;
mod store_set_with_policy;
mod store_storage_cap;
mod submit_body_build;
