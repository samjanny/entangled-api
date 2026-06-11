//! Deterministic differential replay over the conformance corpus.
//!
//! Runs every corpus vector's input document through both entangled-core and the
//! Java reference (the same warm-JVM diff-server the fuzz target uses) and
//! asserts the two normalized verdicts agree. This is the pre-fuzz gate (it
//! proves the harness itself is wired correctly and the fixed context is
//! mirrored byte-for-byte across the two implementations) and the regression
//! check a CI job can run.
//!
//! It does not assert agreement with the corpus's recorded verdict: the fixed
//! context intentionally differs from each vector's own context, so the goal is
//! Rust-vs-Java agreement, not corpus conformance (the per-implementation
//! conformance suites already cover that).
//!
//! ```text
//! export ENTANGLED_CORPUS_PATH=/path/to/entangled/corpus
//! export ENTANGLED_DIFF_CLASSPATH=/path/to/entangled-api-java/target/classes:.../target/test-classes
//! cargo +nightly run --bin replay
//! ```
//!
//! Exits 0 when every vector agrees, 1 on the first batch of divergences (all
//! are printed), and 2 on a harness error.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use entangled_core_fuzz::{verdicts_conform, JavaDiffServer, RustEval};
use serde_json::Value;

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("replay harness error: {e}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<bool, String> {
    let corpus_root = env::var_os("ENTANGLED_CORPUS_PATH")
        .map(PathBuf::from)
        .ok_or_else(|| "ENTANGLED_CORPUS_PATH must be set".to_owned())?;

    let eval = RustEval::new(&corpus_root)?;
    let mut java = JavaDiffServer::spawn()?;

    let index_raw = fs::read_to_string(corpus_root.join("corpus.json"))
        .map_err(|e| format!("failed to read corpus.json: {e}"))?;
    let index: Value =
        serde_json::from_str(&index_raw).map_err(|e| format!("corpus.json is not JSON: {e}"))?;
    let vectors = index
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| "corpus.json has no vectors array".to_owned())?;

    let mut checked = 0usize;
    let mut divergences: Vec<String> = Vec::new();
    for v in vectors {
        let id = v.get("id").and_then(Value::as_str).unwrap_or("<no id>");
        let input_rel = v
            .get("input")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("vector {id} has no input path"))?;
        let body = fs::read(corpus_root.join(input_rel))
            .map_err(|e| format!("failed to read input for {id}: {e}"))?;

        let rust = eval.verify(&body);
        let java_verdict = java.ask(&body)?;
        checked += 1;
        if !verdicts_conform(&rust, &java_verdict) {
            divergences.push(format!("[{id}] rust={rust} java={java_verdict}"));
        }
    }

    if divergences.is_empty() {
        println!("replay: {checked} vectors, Rust and Java agree on every verdict");
        Ok(true)
    } else {
        println!(
            "replay: {} of {checked} vectors diverge:\n  - {}",
            divergences.len(),
            divergences.join("\n  - ")
        );
        Ok(false)
    }
}
