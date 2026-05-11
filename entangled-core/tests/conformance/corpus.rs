//! Corpus index and vector descriptors.
//!
//! Mirrors the on-disk shape of `docs-spec/corpus/corpus.json`. Only the
//! fields the harness actually consumes are decoded; unknown extra fields
//! in the corpus are tolerated so a corpus update that adds metadata does
//! not require a code change here.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Top-level corpus index.
#[derive(Debug, Deserialize)]
pub struct Corpus {
    pub spec_version_target: String,
    #[allow(dead_code)] // Kept for diagnostic output and future gating.
    pub rc_target: String,
    /// Mocked wall-clock value the harness MUST inject for the duration of
    /// the run. Required by corpus rc.9: canary diagnostics depend on
    /// `now` and the corpus uses fixed `issued_at` timestamps.
    pub clock_now: String,
    pub vectors: Vec<Vector>,
    #[serde(skip)]
    pub root: PathBuf,
}

/// One corpus vector.
#[derive(Debug, Deserialize)]
pub struct Vector {
    pub id: String,
    pub kind: String,
    pub description: String,
    pub input: String,
    pub expected: Expected,
    #[serde(default)]
    pub context: Context,
}

#[derive(Debug, Deserialize)]
pub struct Expected {
    pub verdict: String,
    #[serde(default)]
    pub diagnostic: Option<String>,
    /// Structured `details` payload the corpus expects the implementation
    /// to attach. Compared by subset: every key/value pair listed here
    /// MUST appear in the implementation's diagnostic `details`. Used by
    /// the rc.15+ migration vectors that verify `mismatch_field` and
    /// `underlying_diagnostic_code`.
    #[serde(default)]
    pub diagnostic_details: Option<serde_json::Value>,
}

#[derive(Debug, Default, Deserialize)]
pub struct Context {
    #[serde(default)]
    pub fetched_origin_address: Option<String>,
    #[serde(default)]
    pub fetched_path: Option<String>,
    #[serde(default)]
    pub expected_runtime_pubkey: Option<String>,
    #[serde(default)]
    pub submit_path: Option<String>,
    #[serde(default)]
    pub submit_body_path: Option<String>,
    #[serde(default)]
    pub previously_verified: Option<String>,
    /// rc.16 migration vectors: address of the announced successor
    /// origin, used as the carrier-binding target when running the
    /// successor manifest through Stages 1-9.
    #[serde(default)]
    pub successor_origin_address: Option<String>,
    /// rc.16 migration vectors: corpus-relative path of the successor
    /// manifest fetched from `successor_origin_address`. When present,
    /// the runner runs the successor through Stages 1-9 and wraps any
    /// failure into `E_MIGRATION_MISMATCH` via
    /// `wrap_successor_stage9_failure`.
    #[serde(default)]
    pub successor_manifest_path: Option<String>,
}

impl Corpus {
    /// Try to load `corpus.json`, returning `None` when the corpus is not
    /// present on disk. The corpus is distributed separately from this
    /// crate (see top-level `.gitignore`); a checkout that does not include
    /// it is the expected case on CI runners that have not vendored the
    /// upstream spec repository.
    ///
    /// A malformed corpus or a missing required field is still a harness
    /// bug rather than a vector failure, so those cases panic.
    pub fn try_load() -> Option<Self> {
        let root = Self::corpus_root();
        let index_path = root.join("corpus.json");
        let raw = match fs::read_to_string(&index_path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
            Err(e) => panic!(
                "failed to read corpus index at {}: {e}",
                index_path.display()
            ),
        };
        let mut corpus: Self = serde_json::from_str(&raw).unwrap_or_else(|e| {
            panic!(
                "failed to parse corpus index at {}: {e}",
                index_path.display()
            )
        });
        assert!(
            !corpus.clock_now.is_empty(),
            "corpus missing required top-level `clock_now` field"
        );
        corpus.root = root;
        Some(corpus)
    }

    /// Resolve the corpus root.
    ///
    /// Honours `ENTANGLED_CORPUS_PATH` when set (a CI runner that has
    /// vendored the upstream spec repository points this at the
    /// checked-out `corpus/` directory). Otherwise falls back to the
    /// workspace-local `docs-spec/corpus/` mirror — the layout used by
    /// developers who clone the spec repo alongside this one.
    fn corpus_root() -> PathBuf {
        if let Some(p) = env::var_os("ENTANGLED_CORPUS_PATH") {
            return PathBuf::from(p);
        }
        let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        crate_dir
            .parent()
            .expect("crate root has a parent (workspace dir)")
            .join("docs-spec")
            .join("corpus")
    }

    /// Resolve an `input` / `submit_body_path` / `previously_verified`
    /// reference (which are relative to the corpus root) into an absolute
    /// path.
    pub fn resolve(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }
}
