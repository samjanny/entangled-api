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

/// Errors produced by the canonicalizer or by signature-input construction.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CanonError {
    /// A `null` value was encountered. Maps to `E_SCHEMA_NULL_VALUE` at
    /// validation-pipeline call sites.
    #[error("null values are not permitted in Entangled canonical form")]
    NullNotPermitted,

    /// A `Number` value was a float (not representable as `i64`/`u64`).
    /// Maps to `E_SCHEMA_NON_INTEGER`.
    #[error("non-integer numbers are not permitted in Entangled canonical form")]
    NonIntegerNumber,

    /// A `Number` value was outside the union of `i64` and `u64`. Maps to
    /// `E_SCHEMA_NON_INTEGER`.
    #[error("number out of i64/u64 range")]
    NumberOutOfRange,

    /// A string contained a malformed UTF-16 surrogate pair. Maps to
    /// `E_SCHEMA_MALFORMED_UNICODE`.
    #[error("malformed UTF-16 surrogate pair in string")]
    MalformedSurrogate,

    /// `build_signature_input` was called with a context string that is not
    /// one of the three normative values. Internal: callers control the
    /// context string and should never trigger this in production.
    #[error("unknown context string for signature input")]
    UnknownContext,
}
