//! Error type returned by the canonicalizer and the signature-input
//! constructor.
//!
//! `CanonError` is *not* automatically convertible into a
//! [`crate::validation::Diagnostic`]. The canonicalizer is a self-defensive
//! component that does not know which `DocumentKindLabel` should accompany a
//! diagnostic. Callers translate at the call site:
//!
//! - [`CanonError::NullNotPermitted`] → `E_SCHEMA_NULL_VALUE`
//! - [`CanonError::NonIntegerNumber`] → `E_SCHEMA_NON_INTEGER`
//! - [`CanonError::NumberOutOfRange`] → `E_SCHEMA_NON_INTEGER`
//! - [`CanonError::MalformedSurrogate`] → `E_SCHEMA_MALFORMED_UNICODE`
//! - [`CanonError::UnknownContext`] is internal: callers control the
//!   context string and should never trigger this in production code paths.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CanonError {
    #[error("null values are not permitted in Entangled canonical form")]
    NullNotPermitted,

    #[error("non-integer numbers are not permitted in Entangled canonical form")]
    NonIntegerNumber,

    #[error("number out of i64/u64 range")]
    NumberOutOfRange,

    #[error("malformed UTF-16 surrogate pair in string")]
    MalformedSurrogate,

    #[error("unknown context string for signature input")]
    UnknownContext,
}
