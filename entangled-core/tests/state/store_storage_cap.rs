//! §07 "Storage limits": per-publisher storage cap enforcement on `set`.

use entangled_core::state::{ConsentDecision, StateStore, StorageCap};
use entangled_core::types::state::StateMode;
use entangled_core::validation::DiagnosticCode;

use crate::helpers::{default_runtime, pub_from_seed, set_op, ts};

const ACCEPTED: ConsentDecision = ConsentDecision {
    accepted: true,
    remembered: false,
};

#[test]
fn within_cap_committed() {
    let pub_a = pub_from_seed(31);
    let now = ts("2026-05-07T00:00:00Z");
    let mut store = StateStore::with_cap(StorageCap {
        bytes_per_publisher: 1024,
    });

    // namespace=2, key=2 → overhead 4 bytes per entry; values below leave
    // headroom.
    let value = "x".repeat(800);
    store
        .set(
            &pub_a,
            &set_op("ns", "k1", &value, 600),
            StateMode::Request,
            ACCEPTED,
            &default_runtime(),
            &now,
        )
        .unwrap();

    let used = store.bytes_used_for_publisher(&pub_a, &now);
    assert_eq!(used, 800 + 2 + 2);
}

#[test]
fn second_set_exceeds_cap() {
    let pub_a = pub_from_seed(32);
    let now = ts("2026-05-07T00:00:00Z");
    let mut store = StateStore::with_cap(StorageCap {
        bytes_per_publisher: 1024,
    });

    let v1 = "x".repeat(800);
    store
        .set(
            &pub_a,
            &set_op("ns", "k1", &v1, 600),
            StateMode::Request,
            ACCEPTED,
            &default_runtime(),
            &now,
        )
        .unwrap();
    // 800 + 4 = 804. Adding 300+4 = 304 → 1108 > 1024.
    let v2 = "y".repeat(300);
    let err = store
        .set(
            &pub_a,
            &set_op("ns", "k2", &v2, 600),
            StateMode::Request,
            ACCEPTED,
            &default_runtime(),
            &now,
        )
        .unwrap_err();
    assert_eq!(err.code, DiagnosticCode::EStateStorageCap);
}

#[test]
fn second_set_meets_cap_exactly() {
    let pub_a = pub_from_seed(33);
    let now = ts("2026-05-07T00:00:00Z");
    let mut store = StateStore::with_cap(StorageCap {
        bytes_per_publisher: 1024,
    });

    // 800 + 4 = 804.
    let v1 = "x".repeat(800);
    store
        .set(
            &pub_a,
            &set_op("ns", "k1", &v1, 600),
            StateMode::Request,
            ACCEPTED,
            &default_runtime(),
            &now,
        )
        .unwrap();

    // Need another 220 bytes total: ns=2, key=2 (4) → value=216 → 220.
    // Total 804 + 220 = 1024.
    let v2 = "y".repeat(216);
    store
        .set(
            &pub_a,
            &set_op("ns", "k2", &v2, 600),
            StateMode::Request,
            ACCEPTED,
            &default_runtime(),
            &now,
        )
        .unwrap();
    assert_eq!(store.bytes_used_for_publisher(&pub_a, &now), 1024);
}

#[test]
fn replacing_with_smaller_value_is_allowed_at_cap() {
    let pub_a = pub_from_seed(34);
    let now = ts("2026-05-07T00:00:00Z");
    let mut store = StateStore::with_cap(StorageCap {
        bytes_per_publisher: 1024,
    });

    // Fill to within cap.
    let v1 = "x".repeat(1000);
    store
        .set(
            &pub_a,
            &set_op("ns", "k", &v1, 600),
            StateMode::Request,
            ACCEPTED,
            &default_runtime(),
            &now,
        )
        .unwrap();
    assert_eq!(store.bytes_used_for_publisher(&pub_a, &now), 1000 + 3);

    // Replace with a smaller value — net delta negative; must succeed.
    let v2 = "y".repeat(100);
    store
        .set(
            &pub_a,
            &set_op("ns", "k", &v2, 600),
            StateMode::Request,
            ACCEPTED,
            &default_runtime(),
            &now,
        )
        .unwrap();
    assert_eq!(store.bytes_used_for_publisher(&pub_a, &now), 100 + 3);
}

#[test]
fn caps_are_per_publisher() {
    let pub_a = pub_from_seed(35);
    let pub_b = pub_from_seed(36);
    let now = ts("2026-05-07T00:00:00Z");
    let mut store = StateStore::with_cap(StorageCap {
        bytes_per_publisher: 1024,
    });

    let v = "x".repeat(900);
    store
        .set(
            &pub_a,
            &set_op("ns", "k", &v, 600),
            StateMode::Request,
            ACCEPTED,
            &default_runtime(),
            &now,
        )
        .unwrap();
    // pub_b has its own independent cap; not affected by pub_a usage.
    store
        .set(
            &pub_b,
            &set_op("ns", "k", &v, 600),
            StateMode::Request,
            ACCEPTED,
            &default_runtime(),
            &now,
        )
        .unwrap();

    assert_eq!(store.bytes_used_for_publisher(&pub_a, &now), 900 + 3);
    assert_eq!(store.bytes_used_for_publisher(&pub_b, &now), 900 + 3);
}
