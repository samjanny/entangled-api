//! Property-based fuzz target: runs all Rust-only oracles on every input.
//!
//! No Java diff-server is needed; this target is self-contained and can run
//! without any environment configuration beyond `ENTANGLED_CORPUS_PATH`.
//!
//! All five oracles in [`entangled_core_fuzz::oracles`] are exercised on every
//! input. The first violation panics, producing a libFuzzer crash artifact.
//!
//! ```text
//! export ENTANGLED_CORPUS_PATH=/path/to/entangled/corpus
//! cargo +nightly fuzz run oracles -- -max_len=70000
//! ```

#![no_main]

use std::cell::RefCell;

use entangled_core_fuzz::oracles::check_all;
use entangled_core_fuzz::RustEval;
use libfuzzer_sys::fuzz_target;

thread_local! {
    static EVAL: RefCell<RustEval> =
        RefCell::new(RustEval::from_env().unwrap_or_else(|e| panic!("oracle harness init failed: {e}")));
}

fuzz_target!(|data: &[u8]| {
    EVAL.with(|cell| {
        let eval = cell.borrow();
        let failures = check_all(&eval, data);
        if !failures.is_empty() {
            panic!(
                "oracle violation(s) on {} bytes:\n  {}",
                data.len(),
                failures.join("\n  ")
            );
        }
    });
});
