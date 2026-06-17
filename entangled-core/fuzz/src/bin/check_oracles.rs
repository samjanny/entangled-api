//! Deterministic oracle check over the conformance corpus.
//!
//! Runs every corpus vector's input document through all five Rust-only oracles
//! in [`entangled_core_fuzz::oracles`] and reports any violations. No Java
//! diff-server is required.
//!
//! ```text
//! export ENTANGLED_CORPUS_PATH=/path/to/entangled/corpus
//! cargo +nightly run --bin check_oracles
//! ```
//!
//! Exits 0 when every vector passes every oracle, 1 on the first batch of
//! violations (all are printed), and 2 on a harness error.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use entangled_core_fuzz::oracles::check_all;
use entangled_core_fuzz::RustEval;
use serde_json::Value;

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("check_oracles harness error: {e}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<bool, String> {
    let corpus_root = env::var_os("ENTANGLED_CORPUS_PATH")
        .map(PathBuf::from)
        .ok_or_else(|| "ENTANGLED_CORPUS_PATH must be set".to_owned())?;

    let eval = RustEval::new(&corpus_root)?;

    let index_raw = fs::read_to_string(corpus_root.join("corpus.json"))
        .map_err(|e| format!("failed to read corpus.json: {e}"))?;
    let index: Value =
        serde_json::from_str(&index_raw).map_err(|e| format!("corpus.json is not JSON: {e}"))?;
    let vectors = index
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| "corpus.json has no vectors array".to_owned())?;

    let mut checked = 0usize;
    let mut violations: Vec<String> = Vec::new();

    for v in vectors {
        let id = v.get("id").and_then(Value::as_str).unwrap_or("<no id>");
        let input_rel = v
            .get("input")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("vector {id} has no input path"))?;
        let body = fs::read(corpus_root.join(input_rel))
            .map_err(|e| format!("failed to read input for {id}: {e}"))?;

        let failures = check_all(&eval, &body);
        checked += 1;
        for msg in failures {
            violations.push(format!("[{id}] {msg}"));
        }
    }

    if violations.is_empty() {
        println!("check_oracles: {checked} vectors, all oracles pass");
        Ok(true)
    } else {
        println!(
            "check_oracles: {} violation(s) across {checked} vectors:\n  - {}",
            violations.len(),
            violations.join("\n  - ")
        );
        Ok(false)
    }
}
