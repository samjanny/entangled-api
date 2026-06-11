//! Differential-fuzzing support shared by the libFuzzer target
//! (`fuzz_targets/differential.rs`) and the deterministic replay binary
//! (`src/bin/replay.rs`).
//!
//! Two pieces:
//!
//! * [`RustEval`] - run a single document body through entangled-core and reduce
//!   the outcome to a normalized verdict string (`"A"` or `"R:<CODE>"`), modeling
//!   the same self-discriminating verifier surface the Java `DiffEval` server
//!   exposes.
//! * [`JavaDiffServer`] - a warm JVM subprocess that answers the same query over
//!   a length-prefixed stdin/stdout protocol, so the two implementations can be
//!   compared on every input.
//!
//! Both sides pin an identical fixed context (the corpus's canonical origin,
//! runtime key, paths, and clock). The harness compares Rust against Java, not
//! against the corpus's recorded verdict: a document for which both reject with
//! the same code is agreement, regardless of whether that code is what a fully
//! contextualized client would report.

use std::env;
use std::fs;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use entangled_core::document::{
    parse_and_verify_content, parse_and_verify_manifest, parse_and_verify_transaction,
    verify_transaction_binding,
};
use entangled_core::state::SubmitBody;
use entangled_core::types::keys::RuntimePubkey;
use entangled_core::types::manifest::OnionAddress;
use entangled_core::types::path::EntangledPath;
use entangled_core::types::timestamp::EntangledTimestamp;
use entangled_core::validation::{
    check_input, discriminate_kind, parse_with_limits, DocumentKind, InputKind,
};

// Canonical corpus context. These MUST stay byte-identical to the constants the
// Java `DiffEval` pins, or the two sides diverge spuriously.
const CLOCK_NOW: &str = "2026-05-07T00:01:00Z";
const ORIGIN_ADDRESS: &str = "dkptfyethnbfsj7qsxscia4w6lg4yssjca2gdrqlk457qav2lkna4xqd.onion";
const RUNTIME_PUBKEY: &str = "jzFtziEJkbIdjI15I4u3ni3bBa6IFElyyjEmMVSGF7o";
const CONTENT_PATH: &str = "/articles/first-post";
const SUBMIT_PATH: &str = "/contact";
const SUBMIT_BODY_VECTOR: &str = "vectors/005-transaction-valid-minimal/submit_body.json";

/// The fixed evaluation context, parsed once. All the typed fixtures are
/// known-valid corpus constants, so constructing this never depends on fuzz
/// input and a failure here is a harness misconfiguration, not a finding.
pub struct RustEval {
    now: EntangledTimestamp,
    origin: OnionAddress,
    runtime_pubkey: RuntimePubkey,
    content_path: EntangledPath,
    submit_path: EntangledPath,
    submit_body: SubmitBody,
}

impl RustEval {
    /// Build the evaluator, resolving the corpus root from
    /// `ENTANGLED_CORPUS_PATH` (the same variable the conformance harness and
    /// the Java server use) to load the fixed submit body.
    pub fn from_env() -> Result<Self, String> {
        let corpus_root = env::var_os("ENTANGLED_CORPUS_PATH")
            .map(PathBuf::from)
            .ok_or_else(|| {
                "ENTANGLED_CORPUS_PATH must point at the conformance corpus directory".to_owned()
            })?;
        Self::new(&corpus_root)
    }

    /// Build the evaluator against an explicit corpus root.
    pub fn new(corpus_root: &Path) -> Result<Self, String> {
        let submit_bytes = fs::read(corpus_root.join(SUBMIT_BODY_VECTOR))
            .map_err(|e| format!("failed to read fixed submit body: {e}"))?;
        let submit_body: SubmitBody = serde_json::from_slice(&submit_bytes)
            .map_err(|e| format!("fixed submit body is not a valid SubmitBody: {e}"))?;
        Ok(Self {
            now: EntangledTimestamp::try_from(CLOCK_NOW)
                .map_err(|e| format!("bad CLOCK_NOW: {e}"))?,
            origin: OnionAddress::try_from(ORIGIN_ADDRESS)
                .map_err(|e| format!("bad ORIGIN_ADDRESS: {e}"))?,
            runtime_pubkey: RuntimePubkey::try_from(RUNTIME_PUBKEY)
                .map_err(|e| format!("bad RUNTIME_PUBKEY: {e}"))?,
            content_path: EntangledPath::try_from(CONTENT_PATH)
                .map_err(|e| format!("bad CONTENT_PATH: {e}"))?,
            submit_path: EntangledPath::try_from(SUBMIT_PATH)
                .map_err(|e| format!("bad SUBMIT_PATH: {e}"))?,
            submit_body,
        })
    }

    /// Evaluate one document body to its normalized verdict string.
    ///
    /// Mirrors `DiffEval.evaluate`: probe-discriminate the kind at the most
    /// permissive cap, then run the discriminated kind's full pipeline under its
    /// own cap with the fixed context.
    pub fn verify(&self, body: &[u8]) -> String {
        match self.probe_kind(body) {
            Ok(DocumentKind::Manifest) => self.run_manifest(body),
            Ok(DocumentKind::Content) => self.run_content(body),
            Ok(DocumentKind::Transaction) => self.run_transaction(body),
            // A probe-stage rejection (Stage 2 byte/UTF-8/BOM, Stage 3 parse,
            // Stage 4 kind) is itself the verdict.
            Err(code) => format!("R:{code}"),
        }
    }

    /// Stage 2-4 probe purely to learn the kind, at the 1 MiB content cap so it
    /// never caps a manifest early; the per-kind pipeline below re-validates
    /// under the correct cap.
    fn probe_kind(&self, body: &[u8]) -> Result<DocumentKind, String> {
        let s = check_input(body, InputKind::ContentDocument).map_err(|d| d.code.to_string())?;
        let value = parse_with_limits(s).map_err(|d| d.code.to_string())?;
        discriminate_kind(&value).map_err(|d| d.code.to_string())
    }

    fn run_manifest(&self, body: &[u8]) -> String {
        let sig = match parse_and_verify_manifest(body, &self.now) {
            Ok(v) => v,
            Err(d) => return reject(&d.code.to_string()),
        };
        let canary = match sig.verify_canary(&self.now) {
            Ok(c) => c,
            Err(d) => return reject(&d.code.to_string()),
        };
        let bound = match canary.verify_origin(&self.origin, &self.now) {
            Ok(b) => b,
            Err(d) => return reject(&d.code.to_string()),
        };
        // Stage 9b: the fixed context supplies no content-index bytes, mirroring
        // the Java side's `verifyManifestIndex(doc, null)`. A manifest that
        // declares content_root therefore rejects E_CONTENT_INDEX_FETCH_FAILED on
        // both sides; one with no content_root succeeds.
        match bound.verify_content_index(None) {
            Ok(_) => "A".to_owned(),
            Err(d) => reject(&d.code.to_string()),
        }
    }

    fn run_content(&self, body: &[u8]) -> String {
        let content = match parse_and_verify_content(body, &self.runtime_pubkey) {
            Ok(c) => c,
            Err(d) => return reject(&d.code.to_string()),
        };
        // Stage 9 path binding against the fixed fetched path.
        if content.path != self.content_path {
            return reject("E_BIND_PATH");
        }
        // Stage 9b: no content_root in the fixed context, so it is a no-op
        // (mirrors Java's `verifyContentSeq` with a null contentRoot).
        "A".to_owned()
    }

    fn run_transaction(&self, body: &[u8]) -> String {
        // No publisher history in the fixed context, so no manifest state_policy
        // is available: pass `None` (mirrors Java's null pinnedStatePolicy).
        let tx = match parse_and_verify_transaction(body, &self.runtime_pubkey, None) {
            Ok(t) => t,
            Err(d) => return reject(&d.code.to_string()),
        };
        match verify_transaction_binding(&tx, &self.submit_path, &self.submit_body) {
            Ok(()) => "A".to_owned(),
            Err(d) => reject(&d.code.to_string()),
        }
    }
}

fn reject(code: &str) -> String {
    format!("R:{code}")
}

/// A warm JVM subprocess running `org.entangled.fuzz.DiffServer`, queried over a
/// length-prefixed stdin/stdout protocol (4-byte big-endian counts).
pub struct JavaDiffServer {
    child: Child,
    stdin: BufWriter<ChildStdin>,
    stdout: BufReader<ChildStdout>,
}

impl JavaDiffServer {
    /// Spawn the server. Configuration comes from the environment:
    ///
    /// * `ENTANGLED_DIFF_JAVA` - the `java` launcher (default `java`).
    /// * `ENTANGLED_DIFF_CLASSPATH` - classpath holding the compiled
    ///   entangled-api-java classes plus the test classes that contain
    ///   `DiffServer` (typically `<repo>/target/classes:<repo>/target/test-classes`).
    /// * `ENTANGLED_CORPUS_PATH` - the corpus directory (forwarded so the server
    ///   can load its own copy of the fixed submit body).
    pub fn spawn() -> Result<Self, String> {
        let java = env::var("ENTANGLED_DIFF_JAVA").unwrap_or_else(|_| "java".to_owned());
        let classpath = env::var("ENTANGLED_DIFF_CLASSPATH").map_err(|_| {
            "ENTANGLED_DIFF_CLASSPATH must hold the entangled-api-java classes (e.g. \
             <repo>/target/classes:<repo>/target/test-classes)"
                .to_owned()
        })?;

        let mut child = Command::new(&java)
            .arg("-cp")
            .arg(&classpath)
            .arg("org.entangled.fuzz.DiffServer")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("failed to spawn java diff-server: {e}"))?;

        let stdin = BufWriter::new(child.stdin.take().expect("piped stdin"));
        let stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
        Ok(Self {
            child,
            stdin,
            stdout,
        })
    }

    /// Ask the server for the Java verdict on `body`.
    pub fn ask(&mut self, body: &[u8]) -> Result<String, String> {
        let len = u32::try_from(body.len()).map_err(|_| "body too large".to_owned())?;
        self.stdin
            .write_all(&len.to_be_bytes())
            .and_then(|()| self.stdin.write_all(body))
            .and_then(|()| self.stdin.flush())
            .map_err(|e| format!("write to diff-server failed: {e}"))?;

        let mut len_buf = [0u8; 4];
        self.stdout
            .read_exact(&mut len_buf)
            .map_err(|e| format!("read from diff-server failed (it may have crashed): {e}"))?;
        let n = u32::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; n];
        self.stdout
            .read_exact(&mut buf)
            .map_err(|e| format!("short read from diff-server: {e}"))?;
        String::from_utf8(buf).map_err(|e| format!("diff-server sent non-UTF-8 verdict: {e}"))
    }
}

impl Drop for JavaDiffServer {
    fn drop(&mut self) {
        // Send the shutdown sentinel (length -1) and reap the child.
        let _ = self.stdin.write_all(&(-1i32).to_be_bytes());
        let _ = self.stdin.flush();
        let _ = self.child.wait();
    }
}
