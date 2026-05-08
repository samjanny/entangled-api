//! Corpus index and vector descriptors.
//!
//! Mirrors the on-disk shape of `docs-spec/corpus/corpus.json`. Only the
//! fields the harness actually consumes are decoded; unknown extra fields
//! in the corpus are tolerated so a corpus update that adds metadata does
//! not require a code change here.

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
}

impl Corpus {
    /// Load `docs-spec/corpus/corpus.json` resolved relative to the crate
    /// root, panicking with a clear message on failure (a missing or
    /// malformed corpus is a harness bug, not a vector failure).
    pub fn load() -> Self {
        let root = Self::corpus_root();
        let index_path = root.join("corpus.json");
        let raw = fs::read_to_string(&index_path).unwrap_or_else(|e| {
            panic!(
                "failed to read corpus index at {}: {e}",
                index_path.display()
            )
        });
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
        corpus
    }

    /// Resolve `docs-spec/corpus/` relative to `CARGO_MANIFEST_DIR` (the
    /// `entangled-core` crate root). The corpus lives one directory up,
    /// under the workspace's `docs-spec/` mirror of the upstream spec
    /// repository.
    fn corpus_root() -> PathBuf {
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
