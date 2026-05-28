//! `E_STATE_TRANSMIT_BUDGET` — runtime client-side soft-fail (§07:466-482).
//!
//! The transmit-budget rule rejects an individual request-mode `set`
//! operation whose commit would make even the *minimal* submit body
//! (envelope + request_state, no fields) overflow the §09 64 KiB cap.
//! Distinct from `E_SUBMIT_BUDGET` (Stage 5 satisfiability check on the
//! policy itself, runs at manifest validation) and `E_STATE_STORAGE_CAP`
//! (per-publisher byte cap, which is the local storage rule).

use entangled_core::state::{ConsentDecision, StateStore, StorageCap};
use entangled_core::types::state::StateMode;
use entangled_core::validation::DiagnosticCode;

use crate::helpers::{default_runtime, pub_from_seed, set_op, ts};

const ACCEPTED: ConsentDecision = ConsentDecision {
    accepted: true,
    remembered: false,
};

/// Build a request-mode set op whose value is `value_len` bytes of ASCII.
fn big_set(
    namespace: &str,
    key: &str,
    value_len: usize,
    ttl: u32,
) -> entangled_core::types::state::StateUpdateOp {
    let value = "a".repeat(value_len);
    set_op(namespace, key, &value, ttl)
}

#[test]
fn small_request_set_does_not_trigger_transmit_budget() {
    let pub_a = pub_from_seed(150);
    let now = ts("2026-05-07T00:00:00Z");
    let rt = default_runtime();
    let mut store = StateStore::new();

    store
        .set(
            &pub_a,
            &big_set("ns", "k", 100, 3600),
            StateMode::Request,
            ACCEPTED,
            &rt,
            &now,
        )
        .expect("small request entry must commit");
}

#[test]
fn client_only_set_never_triggers_transmit_budget() {
    // Client-only state is never transmitted; the transmit-budget rule
    // does not apply (§07:564).
    let pub_a = pub_from_seed(151);
    let now = ts("2026-05-07T00:00:00Z");
    let rt = default_runtime();
    // Loosen the storage cap so the value itself fits in publisher
    // storage independently of transmit cap.
    let mut store = StateStore::with_cap(StorageCap {
        bytes_per_publisher: 256 * 1024,
    });

    // 60 KiB client-only value: way above the request-state transmit
    // cap, but irrelevant because mode = ClientOnly.
    store
        .set(
            &pub_a,
            &big_set("ns", "k", 60 * 1024, 3600),
            StateMode::ClientOnly,
            ACCEPTED,
            &rt,
            &now,
        )
        .expect("client-only sets are not subject to transmit budget");
}

#[test]
fn single_request_set_above_minimal_submit_cap_rejected() {
    // A single request-mode entry whose value alone pushes the minimal
    // submit body over 64 KiB. Use a 62 KiB value: overhead reserve
    // (4 KiB) + entry envelope (~40 B) + value (62 KiB) = 66 KiB > 64 KiB.
    let pub_a = pub_from_seed(152);
    let now = ts("2026-05-07T00:00:00Z");
    let rt = default_runtime();
    let mut store = StateStore::with_cap(StorageCap {
        bytes_per_publisher: 256 * 1024,
    });

    let err = store
        .set(
            &pub_a,
            &big_set("ns", "k", 62 * 1024, 3600),
            StateMode::Request,
            ACCEPTED,
            &rt,
            &now,
        )
        .expect_err("oversized request-mode set MUST reject");
    assert_eq!(err.code, DiagnosticCode::EStateTransmitBudget);
    let details = err.details.as_ref().expect("details payload");
    assert_eq!(details["namespace"].as_str(), Some("ns"));
    assert_eq!(details["key"].as_str(), Some("k"));
    assert_eq!(details["cap_bytes"].as_u64(), Some(65_536));
    let projected = details["projected_bytes"]
        .as_u64()
        .expect("projected_bytes integer");
    assert!(projected > 65_536, "projected must exceed cap");
}

#[test]
fn accumulated_request_state_overflowing_minimal_submit_rejected() {
    // Multiple medium-sized request-state entries that, taken together,
    // overflow the minimal submit body even though each one alone fits.
    //
    // 4 KiB overhead reserve + 16 entries × (~4 KiB value + ~40 B
    // envelope) ≈ 64 KiB + change. The 17th smaller entry tips it over.
    let pub_a = pub_from_seed(153);
    let now = ts("2026-05-07T00:00:00Z");
    let rt = default_runtime();
    let mut store = StateStore::with_cap(StorageCap {
        bytes_per_publisher: 256 * 1024,
    });

    // 14 entries × 4 KiB fit; the 15th tips it over the 64 KiB cap.
    for i in 0..14 {
        let key_name = format!("k{i:02}");
        store
            .set(
                &pub_a,
                &big_set("ns", &key_name, 4 * 1024, 3600),
                StateMode::Request,
                ACCEPTED,
                &rt,
                &now,
            )
            .unwrap_or_else(|e| panic!("entry {i} must commit but got {e:?}"));
    }

    // The 15th 4 KiB entry should overflow the projected minimal body.
    let err = store
        .set(
            &pub_a,
            &big_set("ns", "k99", 4 * 1024, 3600),
            StateMode::Request,
            ACCEPTED,
            &rt,
            &now,
        )
        .expect_err("aggregate request_state overflow MUST reject");
    assert_eq!(err.code, DiagnosticCode::EStateTransmitBudget);
}

#[test]
fn overwrite_of_existing_slot_does_not_double_count() {
    // Two 30 KiB request entries: aggregate fits because the second one
    // is an overwrite of the first slot. Confirms the projector
    // substitutes rather than adding.
    let pub_a = pub_from_seed(154);
    let now = ts("2026-05-07T00:00:00Z");
    let rt = default_runtime();
    let mut store = StateStore::with_cap(StorageCap {
        bytes_per_publisher: 256 * 1024,
    });

    store
        .set(
            &pub_a,
            &big_set("ns", "k", 30 * 1024, 3600),
            StateMode::Request,
            ACCEPTED,
            &rt,
            &now,
        )
        .expect("first 30 KiB commit");

    // Overwriting the same slot with another 30 KiB must succeed:
    // 4 KiB overhead + 1 entry ≈ 34 KiB << 64 KiB.
    store
        .set(
            &pub_a,
            &big_set("ns", "k", 30 * 1024, 3600),
            StateMode::Request,
            ACCEPTED,
            &rt,
            &now,
        )
        .expect("overwrite of same slot must not double-count");
}

#[test]
fn superseded_entries_do_not_count_against_budget() {
    // A superseded request-mode entry MUST NOT be transmitted
    // (§07:555); it therefore MUST NOT count toward the projected
    // minimal submit body either.
    let pub_a = pub_from_seed(155);
    let now = ts("2026-05-07T00:00:00Z");
    let rt_old = entangled_core::crypto::RuntimeSigningKey::from_seed(&[0x01; 32]).verifying_key();
    let rt_new = entangled_core::crypto::RuntimeSigningKey::from_seed(&[0x02; 32]).verifying_key();
    let mut store = StateStore::with_cap(StorageCap {
        bytes_per_publisher: 256 * 1024,
    });

    // Fill the budget under rt_old to its limit (14 × 4 KiB request
    // entries; 15th would already overflow).
    for i in 0..14 {
        let key_name = format!("k{i:02}");
        store
            .set(
                &pub_a,
                &big_set("ns", &key_name, 4 * 1024, 3600),
                StateMode::Request,
                ACCEPTED,
                &rt_old,
                &now,
            )
            .unwrap();
    }

    // Rotate K_runtime: every entry above is now superseded and
    // excluded from the transmit budget.
    let marked = store.mark_runtime_superseded(&pub_a, &rt_new);
    assert_eq!(marked, 14);

    // A fresh 4 KiB request-mode set under rt_new should succeed even
    // though the publisher's total retained bytes are well above 60 KiB.
    store
        .set(
            &pub_a,
            &big_set("ns", "fresh", 4 * 1024, 3600),
            StateMode::Request,
            ACCEPTED,
            &rt_new,
            &now,
        )
        .expect("superseded entries must not count against transmit budget");
}
