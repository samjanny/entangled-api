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
use entangled_core::types::manifest::{Manifest, OnionAddress};
use entangled_core::types::path::EntangledPath;
use entangled_core::types::timestamp::EntangledTimestamp;
use entangled_core::validation::canary::{
    check_anti_downgrade, check_canary_conflict, RetainedManifestRecord,
};
use entangled_core::validation::{
    check_origin_not_after, verify_migration_announcement, wrap_successor_stage9_failure,
    Diagnostic, DiagnosticCode, DocumentKindLabel,
};

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

/// Internal verdict. Rejects carry the full structured diagnostic so the
/// harness can compare `details` subsets (rc.15+ migration vectors).
enum Verdict {
    Accept,
    Reject(Diagnostic),
}

fn run_manifest(
    vector: &Vector,
    corpus: &Corpus,
    raw: &[u8],
    now: &EntangledTimestamp,
) -> Result<Verdict, String> {
    // Run the announcing manifest fully through Stages 1-9.
    let announcing = match run_manifest_pipeline(vector, corpus, raw, now)? {
        Ok(m) => m,
        Err(d) => return Ok(Verdict::Reject(d)),
    };

    // rc.16 migration vectors: when the corpus supplies a successor
    // manifest, run it through its own Stages 1-9 at the successor
    // address and wrap any failure into E_MIGRATION_MISMATCH with
    // mismatch_field = "successor_stage9_failure". When the successor
    // passes, run the publisher-identity continuity check from §10.
    if let Some(successor_rel) = vector.context.successor_manifest_path.as_deref() {
        let successor_addr_str = vector
            .context
            .successor_origin_address
            .as_deref()
            .ok_or_else(|| {
                "migration vector with successor_manifest_path must supply \
                 successor_origin_address"
                    .to_owned()
            })?;
        let successor_addr = OnionAddress::try_from(successor_addr_str)
            .map_err(|e| format!("context.successor_origin_address invalid: {e}"))?;
        let successor_raw = read_input(corpus, successor_rel)?;

        match run_successor_pipeline(&successor_raw, now, &successor_addr) {
            SuccessorOutcome::Accept(successor) => {
                if let Err(d) = verify_migration_announcement(&announcing, &successor) {
                    return Ok(Verdict::Reject(d));
                }
            }
            SuccessorOutcome::RejectAfterSchema(underlying, successor_pubkey) => {
                let wrapped = wrap_successor_stage9_failure(
                    &announcing,
                    &successor_addr,
                    Some(&successor_pubkey),
                    &underlying,
                );
                return Ok(Verdict::Reject(wrapped));
            }
            SuccessorOutcome::RejectBeforeSchema(underlying) => {
                let wrapped =
                    wrap_successor_stage9_failure(&announcing, &successor_addr, None, &underlying);
                return Ok(Verdict::Reject(wrapped));
            }
        }
    }

    Ok(Verdict::Accept)
}

/// Run a single manifest envelope through Stages 1-9 against the
/// `fetched_origin_address` declared in the vector context, plus the
/// rc.14 `origin.not_after` expiry check. Returns the bare manifest on
/// success so the caller can drive a follow-on migration scenario.
///
/// The outer `Result` reports harness-internal errors (missing fixture,
/// malformed context). The inner `Result` is the manifest verdict: `Ok`
/// on accept, `Err(Diagnostic)` on any Stage 1-9 rejection.
#[allow(clippy::result_large_err)] // Diagnostic is the natural error type; boxing would obscure
                                   // the pipeline shape for no measurable cost in test code.
fn run_manifest_pipeline(
    vector: &Vector,
    corpus: &Corpus,
    raw: &[u8],
    now: &EntangledTimestamp,
) -> Result<Result<Manifest, Diagnostic>, String> {
    let sig_verified = match parse_and_verify_manifest(raw, now) {
        Ok(v) => v,
        Err(d) => return Ok(Err(d)),
    };
    let canary_checked = match sig_verified.verify_canary(now) {
        Ok(c) => c,
        Err(d) => return Ok(Err(d)),
    };

    if let Some(prev_rel) = vector.context.previously_verified.as_deref() {
        let retained = build_retained_record(corpus, prev_rel, now)?;
        let canary = canary_checked.canary();
        if let Err(d) = check_anti_downgrade(&canary.issued_at, Some(&retained.issued_at)) {
            return Ok(Err(d));
        }
        let new_payload_hash = manifest_payload_hash(raw)?;
        if let Err(d) = check_canary_conflict(
            &canary.issued_at,
            &canary.runtime_pubkey,
            &new_payload_hash,
            Some(&retained),
        ) {
            return Ok(Err(d));
        }
    }

    // Stage 9 carrier origin binding (when the vector supplies a
    // fetched address). `verify_origin` consumes the wrapper; the bare
    // `Manifest` is then needed for the rc.14 `origin.not_after` check
    // and for any follow-on migration verification, so the two arms
    // produce the same `Manifest` shape.
    let manifest = if let Some(addr) = vector.context.fetched_origin_address.as_deref() {
        let onion = OnionAddress::try_from(addr)
            .map_err(|e| format!("context.fetched_origin_address invalid: {e}"))?;
        match canary_checked.verify_origin(&onion) {
            Ok(b) => b.into_parts().0,
            Err(d) => return Ok(Err(d)),
        }
    } else {
        canary_checked.skip_origin_check()
    };

    // Stage 9 (§06 / §10 rc.14): origin.not_after expiry. Runs after
    // carrier origin binding succeeds and rejects manifests whose
    // declared `not_after` is past `now + tolerance`.
    if let Err(d) = check_origin_not_after(&manifest, now) {
        return Ok(Err(d));
    }

    Ok(Ok(manifest))
}

#[allow(clippy::large_enum_variant)] // Manifest is large but boxing obscures the test-harness
                                     // pipeline; the enum is constructed once per migration vector.
enum SuccessorOutcome {
    Accept(Manifest),
    /// Successor cleared its own Stage 5 (publisher_pubkey known) but
    /// failed at Stage 5+ thereafter. The pubkey is carried for the
    /// scoped `successor_publisher_pubkey` field per rc.15.
    RejectAfterSchema(Diagnostic, entangled_core::types::keys::PublisherPubkey),
    /// Successor failed before Stage 5 (parse, byte cap, kind). No
    /// validated pubkey; rc.15 omits `successor_publisher_pubkey`.
    RejectBeforeSchema(Diagnostic),
}

/// Run the successor manifest's own Stages 1-9 at the announced
/// successor address. The successor pubkey is captured for the rc.15
/// scoping rule on `successor_publisher_pubkey`.
fn run_successor_pipeline(
    raw: &[u8],
    now: &EntangledTimestamp,
    successor_addr: &OnionAddress,
) -> SuccessorOutcome {
    let sig_verified = match parse_and_verify_manifest(raw, now) {
        Ok(v) => v,
        // `parse_and_verify_manifest` runs Stages 2-6: the Stage 6
        // signature verification needs the publisher pubkey from a
        // schema-validated payload, so Stage 5 has already succeeded by
        // the time a Stage 6 diagnostic surfaces. Capture the pubkey for
        // post-Stage-5 failures; Stage 1-4 rejections never expose one.
        Err(d) => {
            return if d.stage >= 6 {
                // Stage 6+ failure raised by parse_and_verify_manifest
                // means schema passed. Re-extract the pubkey from the raw
                // payload — this is a best-effort read, not validation.
                match read_successor_pubkey_unchecked(raw) {
                    Some(pk) => SuccessorOutcome::RejectAfterSchema(d, pk),
                    None => SuccessorOutcome::RejectBeforeSchema(d),
                }
            } else {
                SuccessorOutcome::RejectBeforeSchema(d)
            };
        }
    };
    let canary_checked = match sig_verified.verify_canary(now) {
        Ok(c) => c,
        Err(d) => {
            let pk = canary_checked_publisher_pubkey(raw);
            return match pk {
                Some(pk) => SuccessorOutcome::RejectAfterSchema(d, pk),
                None => SuccessorOutcome::RejectBeforeSchema(d),
            };
        }
    };
    let origin_bound = match canary_checked.verify_origin(successor_addr) {
        Ok(b) => b,
        Err(d) => {
            let pk = canary_checked_publisher_pubkey(raw);
            return match pk {
                Some(pk) => SuccessorOutcome::RejectAfterSchema(d, pk),
                None => SuccessorOutcome::RejectBeforeSchema(d),
            };
        }
    };
    let manifest = origin_bound.into_parts().0;

    if let Err(d) = check_origin_not_after(&manifest, now) {
        return SuccessorOutcome::RejectAfterSchema(d, manifest.publisher_pubkey);
    }

    SuccessorOutcome::Accept(manifest)
}

/// Best-effort extraction of `publisher_pubkey` from raw manifest bytes
/// after a Stage 6+ rejection — Stage 5 has already passed at that point,
/// so the field is present and well-formed.
fn read_successor_pubkey_unchecked(
    raw: &[u8],
) -> Option<entangled_core::types::keys::PublisherPubkey> {
    let value: serde_json::Value = serde_json::from_slice(raw).ok()?;
    let pk_str = value.get("publisher_pubkey")?.as_str()?;
    entangled_core::types::keys::PublisherPubkey::try_from(pk_str).ok()
}

fn canary_checked_publisher_pubkey(
    raw: &[u8],
) -> Option<entangled_core::types::keys::PublisherPubkey> {
    read_successor_pubkey_unchecked(raw)
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
        Err(d) => return Ok(Verdict::Reject(d)),
    };

    // Stage 9: path binding. The crate exposes no helper for this — it is
    // intentionally the caller's responsibility (parser.rs documents this).
    if let Some(fetched) = vector.context.fetched_path.as_deref() {
        let fetched_path = EntangledPath::try_from(fetched)
            .map_err(|e| format!("context.fetched_path invalid: {e}"))?;
        if content.path != fetched_path {
            return Ok(Verdict::Reject(Diagnostic::new(
                DiagnosticCode::EBindPath,
                DocumentKindLabel::Content,
                "content.path does not match fetched_path",
            )));
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
        Err(d) => return Ok(Verdict::Reject(d)),
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
        return Ok(Verdict::Reject(d));
    }

    Ok(Verdict::Accept)
}

fn compare(vector: &Vector, actual: Verdict) -> VectorOutcome {
    match (vector.expected.verdict.as_str(), actual) {
        ("accept", Verdict::Accept) => VectorOutcome::Match,
        ("accept", Verdict::Reject(d)) => VectorOutcome::Mismatch {
            detail: format!("expected accept, got reject {}", d.code),
        },
        ("reject", Verdict::Accept) => VectorOutcome::Mismatch {
            detail: "expected reject, got accept".to_owned(),
        },
        ("reject", Verdict::Reject(actual_diag)) => {
            let expected_code_str = vector
                .expected
                .diagnostic
                .as_deref()
                .expect("reject verdicts must carry a diagnostic in the corpus");
            let actual_code_str = actual_diag.code.to_string();
            if actual_code_str != expected_code_str {
                return VectorOutcome::Mismatch {
                    detail: format!(
                        "expected diagnostic {expected_code_str}, got {actual_code_str}"
                    ),
                };
            }
            // rc.15+ corpus may pin specific `details` keys (e.g.
            // mismatch_field, underlying_diagnostic_code). Compare by
            // subset: every key/value the corpus lists MUST appear in
            // the implementation's `details`; extra keys are allowed.
            if let Some(expected_details) = vector.expected.diagnostic_details.as_ref() {
                if let Err(mismatch) =
                    check_details_subset(expected_details, actual_diag.details.as_ref())
                {
                    return VectorOutcome::Mismatch { detail: mismatch };
                }
            }
            VectorOutcome::Match
        }
        (other, _) => VectorOutcome::Mismatch {
            detail: format!("unknown expected verdict {other:?}"),
        },
    }
}

/// Verify that every key/value pair in `expected` is also present in
/// `actual`. Extra keys in `actual` are not flagged. Used for rc.15+
/// `diagnostic_details` subset matching.
fn check_details_subset(
    expected: &serde_json::Value,
    actual: Option<&serde_json::Value>,
) -> Result<(), String> {
    let expected_obj = expected
        .as_object()
        .ok_or_else(|| "expected diagnostic_details must be a JSON object".to_owned())?;
    let actual = actual.ok_or_else(|| {
        "expected diagnostic_details present but implementation attached no details".to_owned()
    })?;
    let actual_obj = actual
        .as_object()
        .ok_or_else(|| "implementation diagnostic details is not a JSON object".to_owned())?;
    for (k, v) in expected_obj {
        match actual_obj.get(k) {
            None => return Err(format!("missing details key {k:?}")),
            Some(av) if av != v => {
                return Err(format!("details key {k:?}: expected {}, got {}", v, av,));
            }
            Some(_) => {}
        }
    }
    Ok(())
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
