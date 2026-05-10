//! Per-vector runner.
//!
//! Owns the dispatch from a single corpus [`Vector`] to the appropriate
//! `parse_and_verify_*` plus, where the corpus context dictates, Stage 8
//! canary checks and Stage 9 binding. Each entry point returns a
//! [`VectorOutcome`] indicating whether the implementation's verdict +
//! diagnostic match the corpus's expectation.

use std::fs;
use std::path::PathBuf;

use entangled_core::canon::canonicalize;
use entangled_core::crypto::sha256;
use entangled_core::document::{
    parse_and_verify_content, parse_and_verify_manifest, parse_and_verify_transaction,
    verify_transaction_binding,
};
use entangled_core::state::SubmitBody;
use entangled_core::types::keys::RuntimePubkey;
use entangled_core::types::manifest::OnionAddress;
use entangled_core::types::path::EntangledPath;
use entangled_core::types::timestamp::EntangledTimestamp;
use entangled_core::validation::canary::{
    check_anti_downgrade, check_canary_conflict, RetainedManifestRecord,
};
use entangled_core::validation::{Diagnostic, DiagnosticCode, DocumentKindLabel};

use crate::corpus::{Corpus, Vector};

/// Outcome of running one vector.
pub enum VectorOutcome {
    /// Implementation verdict + diagnostic agree with the corpus.
    Match,
    /// Implementation diverged from the corpus.
    Mismatch { detail: String },
}

/// Run a single vector against the implementation. The `Result` outer layer
/// is reserved for harness-internal errors (missing fixture file, malformed
/// context, etc.) — those are reported separately from a vector mismatch.
pub fn run_vector(vector: &Vector, corpus: &Corpus) -> Result<VectorOutcome, String> {
    let now = parse_clock(&corpus.clock_now)?;
    let raw = read_input(corpus, &vector.input)?;

    let actual = match vector.kind.as_str() {
        "manifest" => run_manifest(vector, corpus, &raw, &now),
        "content" => run_content(vector, &raw),
        "transaction" => run_transaction(vector, corpus, &raw),
        other => return Err(format!("unknown vector kind {other}")),
    }?;

    Ok(compare(vector, actual))
}

/// Internal verdict.
enum Verdict {
    Accept,
    Reject(DiagnosticCode),
}

fn run_manifest(
    vector: &Vector,
    corpus: &Corpus,
    raw: &[u8],
    now: &EntangledTimestamp,
) -> Result<Verdict, String> {
    // Stages 2-6 (parse + Stage 6 self-verification).
    let sig_verified = match parse_and_verify_manifest(raw, now) {
        Ok(v) => v,
        Err(d) => return Ok(Verdict::Reject(d.code)),
    };

    // Stage 8 (canary structure + state) when the vector implies an origin.
    let canary_checked = match sig_verified.verify_canary(now) {
        Ok(c) => c,
        Err(d) => return Ok(Verdict::Reject(d.code)),
    };

    // Stage 8 — anti-downgrade and equal-`issued_at` conflict, when the
    // corpus pre-loads a previously verified manifest as context. The
    // retained record is always built from a fixture the corpus itself
    // blessed as accept; anything that fails to load there is a harness
    // bug, not a vector verdict.
    //
    // §08 lists the two checks as mutually exclusive and applied in order:
    // anti-downgrade rejects strictly older `issued_at` with
    // `E_CANARY_DOWNGRADE`; the equal-`issued_at` conflict check then
    // catches identical `issued_at` paired with a different signed payload
    // (`E_CANARY_CONFLICT`).
    if let Some(prev_rel) = vector.context.previously_verified.as_deref() {
        let retained = build_retained_record(corpus, prev_rel, now)?;
        let canary = canary_checked.canary();
        if let Err(d) = check_anti_downgrade(&canary.issued_at, Some(&retained.issued_at)) {
            return Ok(Verdict::Reject(d.code));
        }
        let new_payload_hash = manifest_payload_hash(raw)?;
        if let Err(d) = check_canary_conflict(
            &canary.issued_at,
            &canary.runtime_pubkey,
            &new_payload_hash,
            Some(&retained),
        ) {
            return Ok(Verdict::Reject(d.code));
        }
    }

    // Stage 9 (origin binding) when the vector supplies a fetched origin.
    if let Some(addr) = vector.context.fetched_origin_address.as_deref() {
        let onion = OnionAddress::try_from(addr)
            .map_err(|e| format!("context.fetched_origin_address invalid: {e}"))?;
        if let Err(d) = canary_checked.verify_origin(&onion) {
            return Ok(Verdict::Reject(d.code));
        }
    }

    Ok(Verdict::Accept)
}

fn run_content(vector: &Vector, raw: &[u8]) -> Result<Verdict, String> {
    // Parse-stage rejections (Stages 2-5) never reach signature
    // verification, so vectors that fail early may legitimately omit
    // `expected_runtime_pubkey` from their context. Fall back to a
    // placeholder key in that case — if the implementation reaches Stage
    // 6 with the placeholder, signature verification will simply fail and
    // the diagnostic mismatch will surface in `compare`.
    let runtime_pk = match vector.context.expected_runtime_pubkey.as_deref() {
        Some(b64) => RuntimePubkey::try_from(b64)
            .map_err(|e| format!("context.expected_runtime_pubkey invalid: {e}"))?,
        None => RuntimePubkey::from_bytes([0u8; 32]),
    };

    let content = match parse_and_verify_content(raw, &runtime_pk) {
        Ok(c) => c,
        Err(d) => return Ok(Verdict::Reject(d.code)),
    };

    // Stage 9: path binding. The crate exposes no helper for this — it is
    // intentionally the caller's responsibility (parser.rs documents this).
    if let Some(fetched) = vector.context.fetched_path.as_deref() {
        let fetched_path = EntangledPath::try_from(fetched)
            .map_err(|e| format!("context.fetched_path invalid: {e}"))?;
        if content.path != fetched_path {
            return Ok(Verdict::Reject(DiagnosticCode::EBindPath));
        }
    }

    Ok(Verdict::Accept)
}

fn run_transaction(vector: &Vector, corpus: &Corpus, raw: &[u8]) -> Result<Verdict, String> {
    let runtime_pk = match vector.context.expected_runtime_pubkey.as_deref() {
        Some(b64) => RuntimePubkey::try_from(b64)
            .map_err(|e| format!("context.expected_runtime_pubkey invalid: {e}"))?,
        None => RuntimePubkey::from_bytes([0u8; 32]),
    };

    let tx = match parse_and_verify_transaction(raw, &runtime_pk) {
        Ok(t) => t,
        Err(d) => return Ok(Verdict::Reject(d.code)),
    };

    // Stage 9 binding (verify_transaction_binding) requires the originating
    // submit path + body. The corpus carries them as context for every
    // vector that reaches this point (a parse-time rejection above would
    // have returned before now).
    let submit_path_str = vector
        .context
        .submit_path
        .as_deref()
        .ok_or_else(|| "transaction vector missing context.submit_path".to_owned())?;
    let submit_path = EntangledPath::try_from(submit_path_str)
        .map_err(|e| format!("context.submit_path invalid: {e}"))?;

    let body_rel = vector
        .context
        .submit_body_path
        .as_deref()
        .ok_or_else(|| "transaction vector missing context.submit_body_path".to_owned())?;
    let body_raw = read_input(corpus, body_rel)?;
    let submit_body: SubmitBody = serde_json::from_slice(&body_raw)
        .map_err(|e| format!("failed to decode submit body at {body_rel}: {e}"))?;

    if let Err(d) = verify_transaction_binding(&tx, &submit_path, &submit_body) {
        return Ok(Verdict::Reject(d.code));
    }

    Ok(Verdict::Accept)
}

fn compare(vector: &Vector, actual: Verdict) -> VectorOutcome {
    match (vector.expected.verdict.as_str(), actual) {
        ("accept", Verdict::Accept) => VectorOutcome::Match,
        ("accept", Verdict::Reject(code)) => VectorOutcome::Mismatch {
            detail: format!("expected accept, got reject {code}"),
        },
        ("reject", Verdict::Accept) => VectorOutcome::Mismatch {
            detail: "expected reject, got accept".to_owned(),
        },
        ("reject", Verdict::Reject(actual_code)) => {
            let expected_code_str = vector
                .expected
                .diagnostic
                .as_deref()
                .expect("reject verdicts must carry a diagnostic in the corpus");
            let actual_code_str = actual_code.to_string();
            if actual_code_str == expected_code_str {
                VectorOutcome::Match
            } else {
                VectorOutcome::Mismatch {
                    detail: format!(
                        "expected diagnostic {expected_code_str}, got {actual_code_str}"
                    ),
                }
            }
        }
        (other, _) => VectorOutcome::Mismatch {
            detail: format!("unknown expected verdict {other:?}"),
        },
    }
}

fn parse_clock(s: &str) -> Result<EntangledTimestamp, String> {
    EntangledTimestamp::try_from(s)
        .map_err(|e| format!("corpus.clock_now {s:?} is not a valid Entangled timestamp: {e}"))
}

fn read_input(corpus: &Corpus, rel: &str) -> Result<Vec<u8>, String> {
    let path: PathBuf = corpus.resolve(rel);
    fs::read(&path).map_err(|e| format!("failed to read {}: {e}", path.display()))
}

/// Compute the SHA-256 of the JCS-canonical signed payload of a manifest.
///
/// "Signed payload" = the manifest object minus `sig`, with `kind:"manifest"`
/// attached, JCS-canonicalized. This matches `RetainedManifestRecord`'s
/// definition (see `validation::canary::check_canary_conflict`).
fn manifest_payload_hash(raw: &[u8]) -> Result<[u8; 32], String> {
    let mut value: serde_json::Value =
        serde_json::from_slice(raw).map_err(|e| format!("manifest payload is not JSON: {e}"))?;
    let map = value
        .as_object_mut()
        .ok_or_else(|| "manifest payload is not a JSON object".to_owned())?;
    map.remove("sig");
    if !map.contains_key("kind") {
        map.insert(
            "kind".to_owned(),
            serde_json::Value::String("manifest".to_owned()),
        );
    }
    let canonical = canonicalize(&value).map_err(|e| format!("JCS failed: {e}"))?;
    Ok(sha256(&canonical))
}

fn build_retained_record(
    corpus: &Corpus,
    prev_rel: &str,
    now: &EntangledTimestamp,
) -> Result<RetainedManifestRecord, String> {
    let raw = read_input(corpus, prev_rel)?;
    // Verify the prior manifest itself before retaining anything from it.
    let sig_verified = parse_and_verify_manifest(&raw, now).map_err(|d: Diagnostic| {
        format!("previously_verified {prev_rel} failed parse_and_verify: {d}")
    })?;
    let canary_checked = sig_verified.verify_canary(now).map_err(|d: Diagnostic| {
        format!("previously_verified {prev_rel} failed verify_canary: {d}")
    })?;
    let canary = canary_checked.canary().clone();
    // We discard the wrapper here; the harness only needs the canary fields
    // and the payload hash for the conflict check.
    let _ = canary_checked;
    let _ = DocumentKindLabel::Manifest;

    let payload_hash = manifest_payload_hash(&raw)?;
    Ok(RetainedManifestRecord {
        issued_at: canary.issued_at,
        runtime_pubkey: canary.runtime_pubkey,
        manifest_payload_hash: payload_hash,
    })
}
