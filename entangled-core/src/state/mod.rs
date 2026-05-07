//! Client-side state machinery: the per-publisher store (§07) and the
//! submit body wire format (§09).
//!
//! Wire-form types — `StateMode`, `StatePolicyEntry`, `StateUpdateOp` —
//! continue to live under [`crate::types::state`]; this module hosts the
//! runtime/client-side structures that build on them.

pub mod store;
pub mod submit;

pub use store::{ConsentDecision, SetOutcome, StateEntry, StateStore, StorageCap};
pub use submit::{build_submit_body, RequestStateItem, SubmitBody};
