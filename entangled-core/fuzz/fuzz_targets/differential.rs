//! Differential fuzz target: every input is verified by both entangled-core
//! (in-process) and the Java reference (a warm JVM subprocess), and any verdict
//! disagreement is a finding.
//!
//! Two modes:
//!
//! * **strict** (default): the first divergence panics, producing a libFuzzer
//!   crash artifact carrying the reproducing input. This is the CI-gate
//!   behavior.
//! * **discovery** (set `ENTANGLED_DIFF_LOG=<path>`): a divergence is recorded
//!   and the run continues, so one campaign enumerates every distinct divergence
//!   *class* rather than halting on the first. Each new `(rust, java)` verdict
//!   pair is appended once as `rust<TAB>java<TAB>hex(input)`; repeats of an
//!   already-seen pair are suppressed so the log lists one representative per
//!   class.
//!
//! Run with the conformance corpus as the seed set:
//!
//! ```text
//! ( cd ../../../entangled-api-java && JAVA_HOME=... mvn test-compile )
//! export ENTANGLED_CORPUS_PATH=/path/to/entangled/corpus
//! export ENTANGLED_DIFF_CLASSPATH=/path/to/entangled-api-java/target/classes:/path/to/entangled-api-java/target/test-classes
//! cargo +nightly fuzz run differential -- -max_len=70000
//! ```

#![no_main]

use std::cell::RefCell;
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::Write;

use entangled_core_fuzz::{verdicts_conform, JavaDiffServer, RustEval};
use libfuzzer_sys::fuzz_target;

struct Harness {
    eval: RustEval,
    java: JavaDiffServer,
    /// Discovery-mode log sink and the set of `(rust, java)` pairs already
    /// recorded (so each class is logged once). `None` in strict mode.
    log: Option<(File, HashSet<(String, String)>)>,
}

thread_local! {
    // One harness per fuzzing worker thread, initialized on first input. A
    // failure to initialize is a harness misconfiguration (missing env / unbuilt
    // Java classes), so panicking is the right signal - it is not a finding.
    static HARNESS: RefCell<Harness> =
        RefCell::new(init().unwrap_or_else(|e| panic!("differential harness init failed: {e}")));
}

fn init() -> Result<Harness, String> {
    let log = match std::env::var("ENTANGLED_DIFF_LOG") {
        Ok(path) if !path.is_empty() => {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .map_err(|e| format!("cannot open ENTANGLED_DIFF_LOG {path}: {e}"))?;
            Some((file, HashSet::new()))
        }
        _ => None,
    };
    Ok(Harness {
        eval: RustEval::from_env()?,
        java: JavaDiffServer::spawn()?,
        log,
    })
}

fuzz_target!(|data: &[u8]| {
    HARNESS.with(|cell| {
        let mut h = cell.borrow_mut();
        let rust = h.eval.verify(data);
        let java = h
            .java
            .ask(data)
            .unwrap_or_else(|e| panic!("java diff-server communication failed: {e}"));

        if verdicts_conform(&rust, &java) {
            return;
        }

        match h.log.as_mut() {
            // Discovery mode: record one representative per (rust, java) class
            // and keep going.
            Some((file, seen)) => {
                let key = (rust.clone(), java.clone());
                if seen.insert(key) {
                    let _ = writeln!(file, "{rust}\t{java}\t{}", hex(data));
                    let _ = file.flush();
                    eprintln!("[divergence] rust={rust} java={java} ({} bytes)", data.len());
                }
            }
            // Strict mode: first divergence is a crash.
            None => panic!(
                "differential divergence:\n  rust = {rust}\n  java = {java}\n  input ({} bytes) = {}",
                data.len(),
                hex(data),
            ),
        }
    });
});

fn hex(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
