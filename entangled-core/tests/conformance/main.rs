//! Conformance harness driven by the upstream
//! `docs-spec/corpus/` test corpus.
//!
//! The harness loads `corpus.json`, mocks the implementation clock to its
//! top-level `clock_now` field (required by §11 / corpus rc.9 because canary
//! diagnostics depend on `now`), and runs every vector through the pipeline
//! the corpus expects (`parse_and_verify_*` plus, where context dictates,
//! Stage 8 canary checks and Stage 9 binding).
//!
//! The single integration test below — `corpus_vectors_match_spec` — fails
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

    let mut failures: Vec<String> = Vec::new();
    for vector in &corpus.vectors {
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

    assert!(
        failures.is_empty(),
        "{} of {} vectors failed:\n  - {}",
        failures.len(),
        corpus.vectors.len(),
        failures.join("\n  - ")
    );
}
