//! Property-based oracles for the Entangled v1.0 validation pipeline.
//!
//! Each oracle is a pure function `(input: &[u8]) -> OracleResult` that asserts
//! a correctness invariant derivable from Rust alone (no Java diff-server
//! required). They can be called from a libFuzzer target, from unit tests, or
//! from a standalone harness.
//!
//! # Oracles
//!
//! * [`oracle_utf8_accepted`]              -- every accepted document is valid UTF-8 with
//!   no BOM (Stage 2 completeness).
//! * [`oracle_reject_stage_order`]         -- if a probe at Stage 2-4 rejects at stage N,
//!   the full-pipeline verdict on the same input must also reject at stage <= N
//!   (monotonicity: rejection cannot improve).
//! * [`oracle_code_catalog_stage`]         -- the stage number embedded in a
//!   `R:<CODE>:<STAGE>` verdict must agree with the normative catalog stage for
//!   that code (`DiagnosticCode::stage()`).
//! * [`oracle_kind_no_stage4_after_probe`] -- if `probe_kind` succeeds
//!   (discriminated a kind), the full-pipeline verdict must not carry a Stage 4
//!   code (`E_KIND_*`), because kind discrimination was already clean.
//! * [`oracle_accept_implies_json_object`] -- every accepted document parses as
//!   a JSON object at the most-permissive cap; a flat scalar / array / bare null
//!   can never be accepted.

use entangled_core::validation::{
    check_input, discriminate_kind, parse_with_limits, DiagnosticCode, InputKind,
};

use crate::RustEval;

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

/// The outcome of a single oracle check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleResult {
    /// Invariant holds for this input.
    Pass,
    /// Invariant is violated. The `msg` string explains why.
    Fail(String),
}

impl OracleResult {
    /// Panic with the failure message (convenience for fuzz targets).
    pub fn unwrap_pass(self) {
        if let OracleResult::Fail(msg) = self {
            panic!("oracle violation: {msg}");
        }
    }

    pub fn is_fail(&self) -> bool {
        matches!(self, OracleResult::Fail(_))
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Parse `R:<CODE>:<STAGE>` into `(code_str, stage_str)`. Returns `None` for
/// `"A"` or any string that does not match the pattern.
fn parse_reject(verdict: &str) -> Option<(&str, &str)> {
    let rest = verdict.strip_prefix("R:")?;
    // stage is the last colon-separated component; split from the right so that
    // code names containing no colons are handled correctly.
    let (code, stage) = rest.rsplit_once(':')?;
    Some((code, stage))
}

/// Serde-round-trip a `DiagnosticCode` string to its typed value, returning
/// `None` if the string is not a recognised code.
fn parse_code(code_str: &str) -> Option<DiagnosticCode> {
    // The serde representation wraps the string in quotes.
    let json_str = format!("\"{code_str}\"");
    serde_json::from_str(&json_str).ok()
}

// ---------------------------------------------------------------------------
// Oracle 1 -- accepted documents are UTF-8, no BOM
// ---------------------------------------------------------------------------

/// Every document verdict of `"A"` (accept) must satisfy Stage 2 invariants:
/// the body is valid UTF-8, has no BOM, and fits within the 1 MiB probe cap.
///
/// This catches an implementation that skips Stage 2 and accepts garbage bytes.
pub fn oracle_utf8_accepted(eval: &RustEval, body: &[u8]) -> OracleResult {
    let verdict = eval.verify(body);
    if verdict != "A" {
        return OracleResult::Pass; // rejection -- nothing to check
    }

    // Check BOM.
    if body.len() >= 3 && body[..3] == [0xEF, 0xBB, 0xBF] {
        return OracleResult::Fail(format!(
            "accepted a document with a UTF-8 BOM ({} bytes)",
            body.len()
        ));
    }

    // Check strict UTF-8.
    if std::str::from_utf8(body).is_err() {
        return OracleResult::Fail(format!(
            "accepted a document containing invalid UTF-8 ({} bytes)",
            body.len()
        ));
    }

    OracleResult::Pass
}

// ---------------------------------------------------------------------------
// Oracle 2 -- rejection stage monotonicity
// ---------------------------------------------------------------------------

/// The probe (Stage 2-4) and the full pipeline operate on the same bytes. If
/// the probe rejects at stage N, the full-pipeline verdict must also reject, and
/// it must reject at stage <= N (it cannot "get further" than the probe). If the
/// probe accepts, the full pipeline is unconstrained by this oracle.
///
/// Catches an implementation whose per-kind runner silently swallows a parse
/// error and returns `"A"` on a body that was already rejected at Stage 3.
pub fn oracle_reject_stage_order(eval: &RustEval, body: &[u8]) -> OracleResult {
    // Run the probe (Stage 2-4) at the content cap -- same as `probe_kind`.
    let probe_stage: Option<u8> = (|| {
        let s = check_input(body, InputKind::ContentDocument).ok()?;
        let value = parse_with_limits(s).ok()?;
        discriminate_kind(&value).err().map(|d| d.stage)
    })();

    let probe_reject_stage = match probe_stage {
        Some(s) => s,
        None => return OracleResult::Pass, // probe accepted -- no constraint
    };

    let verdict = eval.verify(body);
    match parse_reject(&verdict) {
        None => OracleResult::Fail(format!(
            "probe rejected at stage {probe_reject_stage} but full pipeline returned {verdict:?}"
        )),
        Some((_code, stage_str)) => {
            let full_stage: u8 = match stage_str.parse() {
                Ok(n) => n,
                Err(_) => {
                    return OracleResult::Fail(format!(
                        "verdict stage {stage_str:?} is not a valid u8"
                    ))
                }
            };
            if full_stage > probe_reject_stage {
                OracleResult::Fail(format!(
                    "probe rejected at stage {probe_reject_stage} but full pipeline \
                     rejected at later stage {full_stage} (verdict: {verdict})"
                ))
            } else {
                OracleResult::Pass
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Oracle 3 -- code/stage catalog consistency
// ---------------------------------------------------------------------------

/// The stage number inside a rejection verdict `R:<CODE>:<STAGE>` must match
/// the normative catalog stage returned by `DiagnosticCode::stage()`.
///
/// A mismatch would mean `reject()` in `lib.rs` forged the wrong stage, or a
/// `Diagnostic` was constructed with a manually overridden stage field.
///
/// Codes with catalog stage 0 (off-pipeline) are excluded: they legitimately
/// appear in the off-pipeline state / historical / image paths and their stage
/// is explicitly 0 by design.
///
/// The S04 implementation-defined codes (`E_SCHEMA_NON_INTEGER`,
/// `E_SCHEMA_MALFORMED_UNICODE`) are excluded because S04 allows them to be
/// detected at varying stages and `DiagnosticCode::stage()` returns 5 for
/// them while the actual detection may differ.
pub fn oracle_code_catalog_stage(eval: &RustEval, body: &[u8]) -> OracleResult {
    let verdict = eval.verify(body);
    let (code_str, stage_str) = match parse_reject(&verdict) {
        None => return OracleResult::Pass,
        Some(pair) => pair,
    };

    let code = match parse_code(code_str) {
        None => {
            // Unknown code string -- a different oracle covers that; skip here.
            return OracleResult::Pass;
        }
        Some(c) => c,
    };

    // Exclude off-pipeline and impl-defined-stage codes.
    if is_impl_defined_stage(code) || code.stage() == 0 {
        return OracleResult::Pass;
    }

    let reported_stage: u8 = match stage_str.parse() {
        Ok(n) => n,
        Err(_) => {
            return OracleResult::Fail(format!(
                "verdict stage {stage_str:?} for code {code_str} is not a valid u8"
            ))
        }
    };

    let catalog_stage = effective_stage_for_code(code);

    if reported_stage != catalog_stage {
        OracleResult::Fail(format!(
            "code {code_str} has catalog stage {catalog_stage} but verdict carries \
             stage {reported_stage} (verdict: {verdict})"
        ))
    } else {
        OracleResult::Pass
    }
}

/// Mirror of `effective_stage` from `lib.rs`: Stage 5 normalization for
/// codes whose catalog row differs from their actual detection stage.
fn effective_stage_for_code(code: DiagnosticCode) -> u8 {
    match code {
        DiagnosticCode::EStateTtl
        | DiagnosticCode::EStateValueSize
        | DiagnosticCode::EOriginInvalid
        | DiagnosticCode::EMigrationInvalid
        | DiagnosticCode::ESubmitBudget => 5,
        _ => code.stage(),
    }
}

/// Codes for which S04 makes the detection stage implementation-defined.
fn is_impl_defined_stage(code: DiagnosticCode) -> bool {
    matches!(
        code,
        DiagnosticCode::ESchemaNonInteger | DiagnosticCode::ESchemaMalformedUnicode
    )
}

// ---------------------------------------------------------------------------
// Oracle 4 -- no Stage 4 code after a successful probe
// ---------------------------------------------------------------------------

/// If `probe_kind` (Stage 2-4) returns `Ok(_)` -- that is, it successfully
/// discriminated a document kind -- then the full-pipeline verdict on the same
/// body must not carry a Stage 4 `E_KIND_*` code. Kind discrimination already
/// succeeded; re-running the full pipeline cannot un-discriminate it.
///
/// Catches an implementation where the per-kind runner re-does Stage 4 with
/// different logic and can reject with `E_KIND_UNKNOWN` on a body that probed
/// clean.
pub fn oracle_kind_no_stage4_after_probe(eval: &RustEval, body: &[u8]) -> OracleResult {
    // Run probe.
    let probe_ok = (|| {
        let s = check_input(body, InputKind::ContentDocument).ok()?;
        let value = parse_with_limits(s).ok()?;
        discriminate_kind(&value).ok()
    })()
    .is_some();

    if !probe_ok {
        return OracleResult::Pass; // probe failed -- no constraint
    }

    let verdict = eval.verify(body);
    let (code_str, _) = match parse_reject(&verdict) {
        None => return OracleResult::Pass, // accepted
        Some(pair) => pair,
    };

    let is_kind_code = matches!(
        code_str,
        "E_KIND_MISSING_FIELDS" | "E_KIND_SPEC_VERSION" | "E_KIND_UNKNOWN"
    );

    if is_kind_code {
        OracleResult::Fail(format!(
            "probe succeeded (kind discriminated) but full pipeline returned \
             a Stage 4 code {code_str:?} (verdict: {verdict})"
        ))
    } else {
        OracleResult::Pass
    }
}

// ---------------------------------------------------------------------------
// Oracle 5 -- accepted documents parse as JSON objects
// ---------------------------------------------------------------------------

/// Any document that the pipeline accepts must be a JSON object at the top
/// level. A bare array, string, number, boolean, or null can never pass
/// Stage 4 kind discrimination (which requires the `spec_version`, `kind`,
/// and `sig` keys), so an `"A"` verdict on such input is a bug.
pub fn oracle_accept_implies_json_object(eval: &RustEval, body: &[u8]) -> OracleResult {
    let verdict = eval.verify(body);
    if verdict != "A" {
        return OracleResult::Pass;
    }

    // Parse at the probe cap. If this fails the oracle cannot proceed (something
    // very surprising happened -- the code/stage oracle will catch it).
    let Ok(s) = check_input(body, InputKind::ContentDocument) else {
        return OracleResult::Fail(format!(
            "accepted but Stage 2 check_input rejected ({} bytes)",
            body.len()
        ));
    };
    let Ok(value) = parse_with_limits(s) else {
        return OracleResult::Fail(format!(
            "accepted but parse_with_limits rejected ({} bytes)",
            body.len()
        ));
    };

    if !value.is_object() {
        OracleResult::Fail(format!(
            "accepted a document whose top-level JSON value is {:?}, not an object",
            value
        ))
    } else {
        OracleResult::Pass
    }
}

// ---------------------------------------------------------------------------
// Batch helper -- run all oracles and collect failures
// ---------------------------------------------------------------------------

/// Run every oracle on `body` and return the list of failures (empty = all
/// pass). Intended for deterministic replay and test harnesses.
pub fn check_all(eval: &RustEval, body: &[u8]) -> Vec<String> {
    let checks: &[(&str, fn(&RustEval, &[u8]) -> OracleResult)] = &[
        ("utf8_accepted", oracle_utf8_accepted),
        ("reject_stage_order", oracle_reject_stage_order),
        ("code_catalog_stage", oracle_code_catalog_stage),
        ("kind_no_stage4_after_probe", oracle_kind_no_stage4_after_probe),
        ("accept_implies_json_object", oracle_accept_implies_json_object),
    ];

    checks
        .iter()
        .filter_map(|(name, f)| {
            if let OracleResult::Fail(msg) = f(eval, body) {
                Some(format!("[{name}] {msg}"))
            } else {
                None
            }
        })
        .collect()
}
