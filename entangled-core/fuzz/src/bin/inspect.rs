//! Print the Rust and Java verdicts for a single document file, for triaging a
//! divergence the fuzzer found.
//!
//! ```text
//! cargo +nightly run --bin inspect -- artifacts/differential/crash-<hash>
//! ```

use std::env;
use std::fs;
use std::process::ExitCode;

use entangled_core_fuzz::{JavaDiffServer, RustEval};

fn main() -> ExitCode {
    let path = match env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: inspect <file>");
            return ExitCode::from(2);
        }
    };
    let body = match fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("failed to read {path}: {e}");
            return ExitCode::from(2);
        }
    };

    let eval = RustEval::from_env().expect("RustEval init");
    let mut java = JavaDiffServer::spawn().expect("java diff-server");

    let rust = eval.verify(&body);
    let java_verdict = java.ask(&body).expect("java verdict");

    println!(
        "input ({} bytes): {:?}",
        body.len(),
        String::from_utf8_lossy(&body)
    );
    println!("rust : {rust}");
    println!("java : {java_verdict}");
    if rust == java_verdict {
        println!("=> agree");
        ExitCode::SUCCESS
    } else {
        println!("=> DIVERGE");
        ExitCode::from(1)
    }
}
