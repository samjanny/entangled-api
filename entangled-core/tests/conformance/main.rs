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

mod corpus;
mod runner;

use corpus::Corpus;
use runner::{run_vector, VectorOutcome};

#[test]
fn corpus_vectors_match_spec() {
    let corpus = Corpus::load();

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
