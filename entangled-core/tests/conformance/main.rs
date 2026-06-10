//! Conformance harness driven by the upstream
//! `docs-spec/corpus/` test corpus.
//!
//! The harness loads `corpus.json`, mocks the implementation clock to its
//! top-level `clock_now` field (required by §11 / corpus rc.9 because canary
//! diagnostics depend on `now`), and runs every vector through the pipeline
//! the corpus expects (`parse_and_verify_*` plus, where context dictates,
//! Stage 8 canary checks and Stage 9 binding).
//!
//! The single integration test below - `corpus_vectors_match_spec` - fails
//! on the first divergence with a message naming the vector id.
//!
//! The corpus is distributed separately from this crate (see top-level
//! `.gitignore`). When it is not present on disk the test is skipped with
//! a printed notice rather than failing, so a checkout without the spec
//! repository alongside still produces a green test run. Set
//! `ENTANGLED_CORPUS_PATH` to point at an alternative location.

mod corpus;
mod runner;

use corpus::Corpus;
use runner::{run_vector, VectorOutcome};

/// Vectors that exercise functionality this crate documents as out of scope
/// at the crate root: the Stage 7 trust-state machine, the section 03
/// image resource layer (fetching, decoding, and the per-image W_IMAGE_*
/// outcomes), and the Stage 1 transport layer (the rc.54/rc.55 family 250-271,
/// whose vectors carry HTTP response metadata in
/// `context.transport_response` / `context.content_index_response` and are
/// exercised by mock-response harnesses in implementations that own a
/// fetch surface). All of these belong to a client built on top of this
/// verifier. They are reported as skipped with a printed count rather than
/// counted as failures, so the coverage gap is visible and never silently
/// passes. Each entry is `(vector_id, reason)`. Remove an id here when the
/// corresponding capability lands in the crate. The image vectors are
/// exercised by the entangled-client corpus harness.
const OUT_OF_SCOPE: &[(&str, &str)] = &[
    (
        "210-trust-publisher-key-mismatch",
        "Stage 7 trust-state machine is out of scope for this crate",
    ),
    (
        "211-trust-user-rejected-new-identity",
        "Stage 7 trust-state machine is out of scope for this crate",
    ),
    (
        "215-trust-observed-mismatch",
        "Stage 7 trust-state machine is out of scope for this crate",
    ),
    (
        "240-image-valid-png",
        "section 03 image resource layer is out of scope for this crate",
    ),
    (
        "241-image-apng-animated",
        "section 03 image resource layer is out of scope for this crate",
    ),
    (
        "242-image-dimension-mismatch",
        "section 03 image resource layer is out of scope for this crate",
    ),
    (
        "243-image-hash-mismatch",
        "section 03 image resource layer is out of scope for this crate",
    ),
    (
        "244-image-content-type-mismatch",
        "section 03 image resource layer is out of scope for this crate",
    ),
    (
        "245-image-decode-failed",
        "section 03 image resource layer is out of scope for this crate",
    ),
    (
        "250-transport-accept-ignored-headers",
        "Stage 1 transport layer is out of scope for this crate",
    ),
    (
        "251-transport-status-unlisted",
        "Stage 1 transport layer is out of scope for this crate",
    ),
    (
        "252-transport-status-unlisted-2xx",
        "Stage 1 transport layer is out of scope for this crate",
    ),
    (
        "253-transport-redirect",
        "Stage 1 transport layer is out of scope for this crate",
    ),
    (
        "254-transport-content-type-missing",
        "Stage 1 transport layer is out of scope for this crate",
    ),
    (
        "255-transport-content-type-parameter",
        "Stage 1 transport layer is out of scope for this crate",
    ),
    (
        "256-transport-content-length-missing",
        "Stage 1 transport layer is out of scope for this crate",
    ),
    (
        "257-transport-content-length-inconsistent",
        "Stage 1 transport layer is out of scope for this crate",
    ),
    (
        "258-transport-body-failure",
        "Stage 1 transport layer is out of scope for this crate",
    ),
    (
        "259-transport-rate-limited",
        "Stage 1 transport layer is out of scope for this crate",
    ),
    (
        "260-transport-not-found",
        "Stage 1 transport layer is out of scope for this crate",
    ),
    (
        "261-transport-method-not-allowed",
        "Stage 1 transport layer is out of scope for this crate",
    ),
    (
        "262-transport-unavailable",
        "Stage 1 transport layer is out of scope for this crate",
    ),
    (
        "263-transport-content-encoding",
        "Stage 1 transport layer is out of scope for this crate",
    ),
    (
        "264-transport-transfer-encoding",
        "Stage 1 transport layer is out of scope for this crate",
    ),
    (
        "265-transport-submit-payload-too-large",
        "Stage 1 transport layer is out of scope for this crate",
    ),
    (
        "266-transport-submit-bad-request",
        "Stage 1 transport layer is out of scope for this crate",
    ),
    (
        "267-content-index-fetch-encoding",
        "Stage 1 transport layer is out of scope for this crate",
    ),
    (
        "268-content-index-fetch-status",
        "Stage 1 transport layer is out of scope for this crate",
    ),
    (
        "270-transport-status-bad-request-on-get",
        "Stage 1 transport layer is out of scope for this crate",
    ),
    (
        "271-transport-status-payload-too-large-on-get",
        "Stage 1 transport layer is out of scope for this crate",
    ),
    (
        "269-image-fetch-failed",
        "section 03 image resource layer is out of scope for this crate",
    ),
];

#[test]
fn corpus_vectors_match_spec() {
    let Some(corpus) = Corpus::try_load() else {
        eprintln!(
            "conformance corpus not found at docs-spec/corpus/ \
             (set ENTANGLED_CORPUS_PATH to override); skipping."
        );
        return;
    };

    assert_eq!(
        corpus.spec_version_target, "1.0",
        "harness only knows v1.0; corpus targets {}",
        corpus.spec_version_target
    );
    assert_eq!(
        corpus.rc_target,
        entangled_core::SPEC_REVISION,
        "corpus rc_target {} drifted from crate SPEC_REVISION {}; bump \
         either the CI corpus pin (.github/workflows/ci.yml) or the \
         SPEC_REVISION constant (entangled-core/src/lib.rs) so they match",
        corpus.rc_target,
        entangled_core::SPEC_REVISION,
    );

    let mut failures: Vec<String> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    for vector in &corpus.vectors {
        if let Some((_, reason)) = OUT_OF_SCOPE.iter().find(|(id, _)| *id == vector.id) {
            skipped.push(format!("[{}] {}", vector.id, reason));
            continue;
        }
        match run_vector(vector, &corpus) {
            Ok(VectorOutcome::Match) => {}
            Ok(VectorOutcome::Mismatch { detail }) => {
                failures.push(format!(
                    "[{}] {}: {}",
                    vector.id, vector.description, detail
                ));
            }
            Err(harness_err) => {
                failures.push(format!("[{}] harness error: {}", vector.id, harness_err));
            }
        }
    }

    if !skipped.is_empty() {
        eprintln!(
            "{} of {} vectors skipped as out of scope:\n  - {}",
            skipped.len(),
            corpus.vectors.len(),
            skipped.join("\n  - ")
        );
    }

    assert!(
        failures.is_empty(),
        "{} of {} vectors failed:\n  - {}",
        failures.len(),
        corpus.vectors.len(),
        failures.join("\n  - ")
    );
}
