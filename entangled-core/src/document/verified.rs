//! Type-state wrappers for the manifest verification pipeline.
//!
//! [`crate::document::parse_and_verify_manifest`] returns
//! [`ManifestSigVerified`], not a bare [`Manifest`]. To extract the bare
//! `Manifest`, the caller must traverse the pipeline explicitly via
//! [`ManifestSigVerified::verify_canary`] and
//! [`ManifestCanaryChecked::verify_origin`], or opt out of further stages
//! explicitly via [`ManifestSigVerified::skip_canary_check`] or
//! [`ManifestCanaryChecked::skip_origin_check`].
//!
//! This pattern enforces structurally — at compile time — that every
//! caller has considered every applicable stage of §10. It does not
//! introduce trust storage, UI, or transport concerns into this crate;
//! Stage 7 (trust state machine) remains entirely the caller's
//! responsibility, after the chain has been completed.
//!
//! For callers who already hold a [`Manifest`] obtained from a source
//! other than `parse_and_verify_manifest` (test harnesses, conformance
//! corpus runners, mock servers), the standalone helpers
//! [`crate::validation::canary::validate_canary_structure`],
//! [`crate::validation::canary::compute_canary_state`], and
//! [`crate::tor::verify_origin_binding`] remain public as the explicit
//! escape hatch.

use crate::tor::verify_origin_binding;
use crate::types::{EntangledTimestamp, Manifest, OnionAddress};
use crate::validation::canary::{compute_canary_state, validate_canary_structure, CanaryState};
use crate::validation::diagnostic::Diagnostic;

/// Manifest after Stage 6 (signature verification) succeeded.
///
/// The caller MUST proceed to Stage 8 via [`Self::verify_canary`] or
/// MUST opt out via [`Self::skip_canary_check`].
///
/// # Must-use canary
///
/// `#[must_use]` makes the wrapper a compile-time canary against the
/// "forgot Stage 8" foot-gun: dropping the result of
/// [`crate::document::parse_and_verify_manifest`] without traversing the
/// chain (or explicitly opting out via `skip_canary_check`) is a hard
/// error under `-D warnings` (which CI enforces).
///
/// ```compile_fail
/// #![deny(unused_must_use)]
/// use entangled_core::document::parse_and_verify_manifest;
/// use entangled_core::types::EntangledTimestamp;
///
/// fn callsite_that_forgot_stage_8(bytes: &[u8], now: &EntangledTimestamp) {
///     // Unwrapping the `Result` exposes a `ManifestSigVerified` that is
///     // then dropped without being either advanced or explicitly skipped —
///     // a must_use error when the unused_must_use lint is denied.
///     parse_and_verify_manifest(bytes, now).unwrap();
/// }
/// ```
#[derive(Debug)]
#[must_use = "manifest verification is incomplete; call verify_canary or skip_canary_check"]
pub struct ManifestSigVerified {
    inner: Manifest,
}

impl ManifestSigVerified {
    /// Crate-internal constructor. Public callers obtain instances only
    /// from [`crate::document::parse_and_verify_manifest`].
    pub(crate) fn new(inner: Manifest) -> Self {
        Self { inner }
    }

    /// Read-only access to the verified manifest fields.
    ///
    /// This does not consume the wrapper. Use it to read
    /// `publisher_pubkey`, `state_policy`, etc. while the chain is still
    /// in progress (e.g. to initialize a state store with the policy
    /// before completing canary and origin checks).
    pub fn manifest(&self) -> &Manifest {
        &self.inner
    }

    /// Stage 8: structural canary validation and state classification.
    ///
    /// Returns [`ManifestCanaryChecked`] carrying the computed
    /// [`CanaryState`] (Fresh, NearExpiration, or Expired) for the
    /// caller to act on.
    ///
    /// Fails with `E_CANARY_INVALID` if the canary structure is invalid
    /// (issued_at far in the future, interval out of bounds, etc.). An
    /// `Expired` canary is a *state*, not a structural error: this
    /// method returns `Ok` with `CanaryState::Expired`.
    pub fn verify_canary(
        self,
        now: &EntangledTimestamp,
    ) -> Result<ManifestCanaryChecked, Diagnostic> {
        validate_canary_structure(&self.inner.canary, now)?;
        let canary_state = compute_canary_state(&self.inner.canary, now);
        Ok(ManifestCanaryChecked {
            inner: self.inner,
            canary_state,
        })
    }

    /// Explicit opt-out from Stage 8. Returns the bare manifest.
    ///
    /// Suitable for offline validators, batch tools, and test harnesses
    /// where canary state is not used to decide rendering currency. NOT
    /// suitable for client implementations that present the manifest to
    /// a user as currently authoritative.
    pub fn skip_canary_check(self) -> Manifest {
        self.inner
    }
}

/// Manifest after Stages 6 and 8 succeeded.
///
/// The caller MUST proceed to Stage 9 via [`Self::verify_origin`] or
/// MUST opt out via [`Self::skip_origin_check`].
#[derive(Debug)]
#[must_use = "manifest verification is incomplete; call verify_origin or skip_origin_check"]
pub struct ManifestCanaryChecked {
    inner: Manifest,
    canary_state: CanaryState,
}

impl ManifestCanaryChecked {
    /// Read-only access to the verified manifest fields.
    pub fn manifest(&self) -> &Manifest {
        &self.inner
    }

    /// Computed canary state (Fresh, NearExpiration, or Expired).
    pub fn canary_state(&self) -> CanaryState {
        self.canary_state
    }

    /// Stage 9: bind to the .onion address from which the manifest was
    /// fetched.
    ///
    /// `fetched_address` MUST be the carrier address of the actual
    /// transport-layer fetch, byte-exact lowercase canonical form.
    /// Caller obtains it from the transport layer.
    pub fn verify_origin(
        self,
        fetched_address: &OnionAddress,
    ) -> Result<ManifestOriginBound, Diagnostic> {
        verify_origin_binding(fetched_address, &self.inner.origin)?;
        Ok(ManifestOriginBound {
            inner: self.inner,
            canary_state: self.canary_state,
        })
    }

    /// Explicit opt-out from Stage 9. Returns the bare manifest.
    ///
    /// Suitable when origin binding is enforced at a different layer
    /// (e.g. the transport layer rejected mismatched addresses before
    /// surfacing the bytes), or when origin binding is irrelevant
    /// (offline tooling).
    pub fn skip_origin_check(self) -> Manifest {
        self.inner
    }
}

/// Manifest after Stages 6, 8, and 9 succeeded.
///
/// This is the fully verified state. Stage 7 (trust state machine) and
/// Stage 10 (rendering) remain the caller's responsibility, with this
/// crate offering no further enforcement.
#[derive(Debug)]
pub struct ManifestOriginBound {
    inner: Manifest,
    canary_state: CanaryState,
}

impl ManifestOriginBound {
    /// Read-only access to the verified manifest fields.
    pub fn manifest(&self) -> &Manifest {
        &self.inner
    }

    /// Computed canary state (Fresh, NearExpiration, or Expired).
    pub fn canary_state(&self) -> CanaryState {
        self.canary_state
    }

    /// Consume the wrapper and return the bare manifest plus the
    /// canary state for downstream Stage 7 / Stage 10 handling.
    pub fn into_parts(self) -> (Manifest, CanaryState) {
        (self.inner, self.canary_state)
    }
}
