//! `StateStore::mark_runtime_superseded` and the §07 rc.19 N53 MUST set.
//!
//! Spec §07:550-560:
//! * existing request-state entries whose authorizing `K_runtime` has been
//!   superseded MUST be marked as `runtime_superseded` in client storage;
//! * `runtime_superseded` request-state entries MUST NOT be included in
//!   submit requests;
//! * they MUST be retained for user inspection and deletion until their
//!   natural `expires_at`;
//! * client-only state is not affected by this rule.

use entangled_core::state::{ConsentDecision, StateStore};
use entangled_core::types::state::StateMode;

use crate::helpers::{default_runtime, pub_from_seed, rt_from_seed, set_op, slug, ts};

const ACCEPTED: ConsentDecision = ConsentDecision {
    accepted: true,
    remembered: false,
};

#[test]
fn mark_marks_only_entries_authorized_by_a_different_runtime() {
    let pub_a = pub_from_seed(80);
    let now = ts("2026-05-07T00:00:00Z");
    let rt_old = rt_from_seed(0x01);
    let rt_new = rt_from_seed(0x02);
    let mut store = StateStore::new();

    // Two request-mode entries committed under rt_old.
    store
        .set(
            &pub_a,
            &set_op("session", "auth", "tok", 3600),
            StateMode::Request,
            ACCEPTED,
            &rt_old,
            &now,
        )
        .unwrap();
    store
        .set(
            &pub_a,
            &set_op("prefs", "lang", "it", 3600),
            StateMode::Request,
            ACCEPTED,
            &rt_old,
            &now,
        )
        .unwrap();

    // Rotate K_runtime.
    let marked = store.mark_runtime_superseded(&pub_a, &rt_new);
    assert_eq!(marked, 2);

    // Both entries still exist (retained for user inspection per §07:556).
    let auth = store
        .get(&pub_a, &slug("session"), &slug("auth"), &now)
        .expect("entry retained");
    assert!(auth.runtime_superseded);
    let lang = store
        .get(&pub_a, &slug("prefs"), &slug("lang"), &now)
        .expect("entry retained");
    assert!(lang.runtime_superseded);
}

#[test]
fn mark_does_not_re_mark_already_superseded_entries() {
    let pub_a = pub_from_seed(81);
    let now = ts("2026-05-07T00:00:00Z");
    let rt_old = rt_from_seed(0x01);
    let rt_new_a = rt_from_seed(0x02);
    let rt_new_b = rt_from_seed(0x03);
    let mut store = StateStore::new();

    store
        .set(
            &pub_a,
            &set_op("session", "auth", "tok", 3600),
            StateMode::Request,
            ACCEPTED,
            &rt_old,
            &now,
        )
        .unwrap();

    assert_eq!(store.mark_runtime_superseded(&pub_a, &rt_new_a), 1);
    // A subsequent rotation against a different `K_runtime` should not
    // re-flag an entry that is already superseded — there is nothing
    // fresher to compare against.
    assert_eq!(store.mark_runtime_superseded(&pub_a, &rt_new_b), 0);
}

#[test]
fn mark_leaves_client_only_entries_untouched() {
    let pub_a = pub_from_seed(82);
    let now = ts("2026-05-07T00:00:00Z");
    let rt_old = rt_from_seed(0x01);
    let rt_new = rt_from_seed(0x02);
    let mut store = StateStore::new();

    // Client-only: never transmitted, not subject to the rotation rule
    // per §07:564.
    store
        .set(
            &pub_a,
            &set_op("ui", "theme", "dark", 3600),
            StateMode::ClientOnly,
            ACCEPTED,
            &rt_old,
            &now,
        )
        .unwrap();

    let marked = store.mark_runtime_superseded(&pub_a, &rt_new);
    assert_eq!(marked, 0);

    let entry = store
        .get(&pub_a, &slug("ui"), &slug("theme"), &now)
        .expect("client-only entry retained");
    assert!(!entry.runtime_superseded);
}

#[test]
fn mark_leaves_other_publishers_untouched() {
    let pub_a = pub_from_seed(83);
    let pub_b = pub_from_seed(84);
    let now = ts("2026-05-07T00:00:00Z");
    let rt_a_old = rt_from_seed(0x01);
    let rt_a_new = rt_from_seed(0x02);
    let rt_b = rt_from_seed(0x03);
    let mut store = StateStore::new();

    store
        .set(
            &pub_a,
            &set_op("session", "auth", "A", 3600),
            StateMode::Request,
            ACCEPTED,
            &rt_a_old,
            &now,
        )
        .unwrap();
    store
        .set(
            &pub_b,
            &set_op("session", "auth", "B", 3600),
            StateMode::Request,
            ACCEPTED,
            &rt_b,
            &now,
        )
        .unwrap();

    // Mark a rotation only against publisher A.
    let marked = store.mark_runtime_superseded(&pub_a, &rt_a_new);
    assert_eq!(marked, 1);

    let a = store
        .get(&pub_a, &slug("session"), &slug("auth"), &now)
        .unwrap();
    assert!(a.runtime_superseded);
    let b = store
        .get(&pub_b, &slug("session"), &slug("auth"), &now)
        .unwrap();
    assert!(!b.runtime_superseded, "publisher B must be unaffected");
}

#[test]
fn get_request_state_excludes_superseded_entries() {
    use entangled_core::types::state::StatePolicyEntry;

    let pub_a = pub_from_seed(85);
    let now = ts("2026-05-07T00:00:00Z");
    let rt_old = rt_from_seed(0x01);
    let rt_new = rt_from_seed(0x02);
    let mut store = StateStore::new();

    store
        .set(
            &pub_a,
            &set_op("session", "auth", "tok", 3600),
            StateMode::Request,
            ACCEPTED,
            &rt_old,
            &now,
        )
        .unwrap();

    let policy: Vec<StatePolicyEntry> = vec![crate::helpers::policy_entry(
        "session",
        "auth",
        StateMode::Request,
        512,
        86_400,
    )];

    // Before rotation: entry transmitted.
    let pre = store.get_request_state(&pub_a, &policy, &now);
    assert_eq!(pre.len(), 1);

    // After rotation: entry suspended.
    store.mark_runtime_superseded(&pub_a, &rt_new);
    let post = store.get_request_state(&pub_a, &policy, &now);
    assert!(
        post.is_empty(),
        "superseded request entries MUST NOT be transmitted per §07 N53"
    );
}

#[test]
fn no_rotation_with_matching_runtime_keeps_entries_active() {
    let pub_a = pub_from_seed(86);
    let now = ts("2026-05-07T00:00:00Z");
    let rt = default_runtime();
    let mut store = StateStore::new();

    store
        .set(
            &pub_a,
            &set_op("session", "auth", "tok", 3600),
            StateMode::Request,
            ACCEPTED,
            &rt,
            &now,
        )
        .unwrap();

    // Calling mark with the SAME runtime_pubkey is a no-op (no rotation).
    let marked = store.mark_runtime_superseded(&pub_a, &rt);
    assert_eq!(marked, 0);

    let entry = store
        .get(&pub_a, &slug("session"), &slug("auth"), &now)
        .unwrap();
    assert!(!entry.runtime_superseded);
}
