//! Validation pipeline for Entangled v1.0 documents.
//!
//! Stages 2 through 5 of the §10 validation pipeline are implemented here,
//! plus the off-pipeline canary state machine (Stage 8), policy-aware state
//! checks (§07), submit body validation (§09), and the clock-skew helper
//! (§10).
//!
//! Stage 1 (transport) and the user-facing trust-state machine (Stage 7)
//! are out of scope for this crate.

pub mod blocks;
pub mod canary;
pub mod clock;
pub mod diagnostic;
pub mod inline;
pub mod input;
pub mod kind;
pub mod limits;
pub mod migration;
pub mod parse;
pub mod policy_check;
pub mod schema;
pub mod state;
pub mod strings;
pub mod submit;

pub use clock::{check_future_timestamp, check_manifest_clock_skew};
pub use diagnostic::{Diagnostic, DiagnosticCode, DocumentKindLabel, Severity};
pub use input::{check_input, InputKind};
pub use kind::{discriminate_kind, DocumentKind};
pub use migration::verify_migration_announcement;
pub use parse::parse_with_limits;
pub use schema::{
    parse_and_validate_content, parse_and_validate_manifest, parse_and_validate_transaction,
    validate_content, validate_manifest, validate_migration_pointer, validate_transaction,
};
