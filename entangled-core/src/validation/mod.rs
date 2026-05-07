//! Validation pipeline for Entangled v1.0 documents.
//!
//! Stages 2 through 5 of the §10 validation pipeline are implemented here.
//! Stage 1 (transport), Stage 6 (signature), and later stages will be
//! delivered in subsequent phases.

pub mod blocks;
pub mod canary;
pub mod clock;
pub mod diagnostic;
pub mod inline;
pub mod input;
pub mod kind;
pub mod limits;
pub mod parse;
pub mod policy_check;
pub mod schema;
pub mod state;
pub mod strings;
pub mod submit;

pub use diagnostic::{Diagnostic, DiagnosticCode, DocumentKindLabel, Severity};
pub use input::{check_input, InputKind};
pub use kind::{discriminate_kind, DocumentKind};
pub use parse::parse_with_limits;
pub use schema::{
    parse_and_validate_content, parse_and_validate_manifest, parse_and_validate_transaction,
    validate_content, validate_manifest, validate_transaction,
};
