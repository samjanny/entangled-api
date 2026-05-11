//! Type-state wrappers for the manifest verification pipeline.
//!
//! [`crate::document::parse_and_verify_manifest`] returns
//! [`ManifestSigVerified`], not a bare [`Manifest`]. To extract the bare
//! `Manifest`, the caller may complete the pipeline explicitly via
//! [`ManifestSigVerified::verify_canary`] and
//! [`ManifestCanaryChecked::verify_origin`], or opt out of further stages
//! explicitly via [`ManifestSigVerified::skip_canary_check`] or
//! [`ManifestCanaryChecked::skip_origin_check`].
//!
//! This pattern structurally prevents extraction of a bare `Manifest` from
//! incomplete-stage states. A caller obtains a `Manifest` value only by
//! completing the chain via `into_parts` or by an explicit
//! `skip_canary_check` / `skip_origin_check` opt-out. Per-field reads
//! through `ManifestRead` remain available on incomplete states because
//! Stage 7 (trust state lookup, §10) precedes Stage 8 and may need them.
//! It does not
//! introduce trust storage, UI, or transport concerns into this crate;
//! Stage 7 (trust state machine) remains entirely the caller's
//! responsibility, after the chain has been completed.
//!
//! The [`Manifest`] type itself is not accessible through the wrappers;
//! only field-level accessors are exposed via the [`ManifestRead`] trait
//! pre-canary, with [`Canary`] access available post-canary. To obtain a
//! `Manifest` value, callers must complete the chain via
//! [`ManifestOriginBound::into_parts`] or explicitly opt out of further
//! stages via [`ManifestSigVerified::skip_canary_check`] /
//! [`ManifestCanaryChecked::skip_origin_check`]. This closes the
//! `manifest().clone()` bypass that an earlier draft of the wrappers
//! permitted.
//!
//! For callers who already hold a [`Manifest`] obtained from a source
//! other than `parse_and_verify_manifest` (test harnesses, conformance
//! corpus runners, mock servers), the standalone helpers
//! [`crate::validation::canary::validate_canary_structure`],
//! [`crate::validation::canary::compute_canary_state`], and
//! [`crate::tor::verify_origin_binding`] remain public as the explicit
//! escape hatch.

use crate::tor::verify_origin_binding;
use crate::types::canary::Canary;
use crate::types::keys::PublisherPubkey;
use crate::types::manifest::{NavEntry, Origin};
use crate::types::state::StatePolicyEntry;
use crate::types::{EntangledTimestamp, Manifest, OnionAddress};
use crate::validation::canary::{compute_canary_state, validate_canary_structure, CanaryState};
use crate::validation::diagnostic::Diagnostic;

mod sealed {
    use crate::types::Manifest;

    /// Sealed supertrait for [`super::ManifestRead`]: only types declared
    /// in this module can implement it, so third-party crates cannot widen
    /// the trait surface or smuggle out a bare `&Manifest`.
    pub trait HasManifest {
        fn manifest_ref(&self) -> &Manifest;
    }
}

/// Field-level read access shared by the three manifest type-state
/// wrappers. The trait is sealed: it cannot be implemented outside this
/// crate, and it deliberately does not expose a `&Manifest` accessor —
/// callers obtain a bare [`Manifest`] only by completing the chain via
/// [`ManifestOriginBound::into_parts`] or by explicitly opting out via
/// [`ManifestSigVerified::skip_canary_check`] /
/// [`ManifestCanaryChecked::skip_origin_check`].
///
/// # `manifest().clone()` bypass is structurally impossible
///
/// The wrappers used to expose a `manifest(&self) -> &Manifest`
/// accessor; combined with `Manifest: Clone`, that allowed a caller to
/// short-circuit the chain via
/// `parse_and_verify_manifest(...)?.manifest().clone()` and obtain a
/// bare `Manifest` without ever running Stage 8 / Stage 9. The accessor
/// is gone. The three doctests below assert that each wrapper rejects
/// the call at compile time:
///
/// ```compile_fail
/// use entangled_core::document::parse_and_verify_manifest;
/// use entangled_core::types::{EntangledTimestamp, Manifest};
/// # fn _f(bytes: &[u8], now: &EntangledTimestamp) {
/// let v = parse_and_verify_manifest(bytes, now).unwrap();
/// let _: &Manifest = v.manifest(); // ERROR: no method named `manifest`
/// # }
/// ```
///
/// ```compile_fail
/// use entangled_core::document::parse_and_verify_manifest;
/// use entangled_core::types::{EntangledTimestamp, Manifest};
/// # fn _f(bytes: &[u8], now: &EntangledTimestamp) {
/// let v = parse_and_verify_manifest(bytes, now)
///     .unwrap()
///     .verify_canary(now)
///     .unwrap();
/// let _: &Manifest = v.manifest(); // ERROR: no method named `manifest`
/// # }
/// ```
///
/// ```compile_fail
/// use entangled_core::document::parse_and_verify_manifest;
/// use entangled_core::types::{EntangledTimestamp, Manifest, OnionAddress};
/// # fn _f(bytes: &[u8], now: &EntangledTimestamp, addr: &OnionAddress) {
/// let v = parse_and_verify_manifest(bytes, now)
///     .unwrap()
///     .verify_canary(now)
///     .unwrap()
///     .verify_origin(addr)
///     .unwrap();
/// let _: &Manifest = v.manifest(); // ERROR: no method named `manifest`
/// # }
/// ```
pub trait ManifestRead: sealed::HasManifest {
    /// Publisher long-term Ed25519 public key (§02 / §05).
    fn publisher_pubkey(&self) -> &PublisherPubkey {
        &self.manifest_ref().publisher_pubkey
    }
    /// Transport-carrier binding for this manifest (§02 / §05).
    fn origin(&self) -> &Origin {
        &self.manifest_ref().origin
    }
    /// Closed list of state-policy entries the publisher exposes (§07).
    fn state_policy(&self) -> &[StatePolicyEntry] {
        &self.manifest_ref().state_policy
    }
    /// Navigation entries surfaced in client UI (§02).
    fn navigation(&self) -> &[NavEntry] {
        &self.manifest_ref().navigation
    }
    /// Minimum interval (seconds) between manifest re-fetches the client
    /// should observe (§02).
    fn min_refresh_interval(&self) -> u32 {
        self.manifest_ref().min_refresh_interval
    }
    /// Time at which the manifest was last updated (§02).
    fn updated(&self) -> &EntangledTimestamp {
        &self.manifest_ref().updated
    }
    /// SHA-256 of the JCS-canonical signed payload — the input to the
    /// publisher's Ed25519 signature, suitable for use as
    /// `RetainedManifestRecord::manifest_payload_hash` in the §08
    /// anti-conflict check.
    ///
    /// Available at every stage of the type-state chain so that
    /// callers can record the hash for trust-state persistence
    /// without having to call `skip_*` or `into_parts` first.
    /// See [`Manifest::canonical_payload_hash`].
    #[must_use]
    fn canonical_payload_hash(&self) -> [u8; 32] {
        self.manifest_ref().canonical_payload_hash()
    }
}

/// Manifest after Stage 6 (signature verification) succeeded.
///
/// The caller MUST proceed to Stage 8 via [`Self::verify_canary`] or
/// MUST opt out via [`Self::skip_canary_check`].
///
/// Field-level reads are available via the [`ManifestRead`] trait. The
/// bare [`Manifest`] is intentionally unreachable at this stage.
///
/// # Must-use canary
///
/// `#[must_use]` warns when a wrapper is silently dropped without being
/// used, catching the trivial "called but ignored" case. It does not
/// prevent reading fields via `ManifestRead` and then dropping the
/// wrapper — that flow is permitted by design.
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

impl sealed::HasManifest for ManifestSigVerified {
    fn manifest_ref(&self) -> &Manifest {
        &self.inner
    }
}
impl ManifestRead for ManifestSigVerified {}

/// Manifest after Stages 6 and 8 succeeded.
///
/// The caller MUST proceed to Stage 9 via [`Self::verify_origin`] or
/// MUST opt out via [`Self::skip_origin_check`].
///
/// Field-level reads are available via the [`ManifestRead`] trait; the
/// canary is additionally exposed via [`Self::canary`]. The bare
/// [`Manifest`] remains unreachable until the chain completes (or is
/// explicitly opted out of).
#[derive(Debug)]
#[must_use = "manifest verification is incomplete; call verify_origin or skip_origin_check"]
pub struct ManifestCanaryChecked {
    inner: Manifest,
    canary_state: CanaryState,
}

impl ManifestCanaryChecked {
    /// Borrow the validated canary block.
    pub fn canary(&self) -> &Canary {
        &self.inner.canary
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

impl sealed::HasManifest for ManifestCanaryChecked {
    fn manifest_ref(&self) -> &Manifest {
        &self.inner
    }
}
impl ManifestRead for ManifestCanaryChecked {}

/// Manifest after Stages 6, 8, and 9 succeeded.
///
/// This is the fully verified state. Stage 7 (trust state machine) and
/// Stage 10 (rendering) remain the caller's responsibility, with this
/// crate offering no further enforcement.
///
/// Field-level reads are available via the [`ManifestRead`] trait, plus
/// [`Self::canary`] and [`Self::canary_state`]. To obtain the bare
/// [`Manifest`] for downstream Stage 7 / Stage 10 handling, consume the
/// wrapper via [`Self::into_parts`].
#[derive(Debug)]
pub struct ManifestOriginBound {
    inner: Manifest,
    canary_state: CanaryState,
}

impl ManifestOriginBound {
    /// Borrow the validated canary block.
    pub fn canary(&self) -> &Canary {
        &self.inner.canary
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

impl sealed::HasManifest for ManifestOriginBound {
    fn manifest_ref(&self) -> &Manifest {
        &self.inner
    }
}
impl ManifestRead for ManifestOriginBound {}
