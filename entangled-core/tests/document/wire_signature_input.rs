//! H-1 invariant pin: the JCS canonical bytes used as signature input
//! must be derivable from the parsed wire `Value` directly, never via a
//! `serialize(typed) -> Value -> JCS` round trip.
//!
//! The fix in 0.3.1 switched the verifier from
//! `JCS(reserialize(typed) - sig + kind)` to `JCS(parse(wire) - sig)`,
//! removing the structural dependence on every `Serialize` impl being
//! byte-faithful to its `Deserialize` counterpart. These tests assert
//! both paths agree today, so a future divergence in any newtype's
//! `Serialize` impl will fail loudly here rather than silently break
//! signature verification.

use entangled_core::canon::canonicalize;
use entangled_core::crypto::{sha256, PublisherSigningKey, RuntimeSigningKey};
use entangled_core::document::{
    build_content, build_manifest, build_transaction, parse_and_verify_manifest, ManifestRead,
};
use entangled_core::validation::{
    parse_and_validate_content_with_value, parse_and_validate_manifest_with_value,
    parse_and_validate_transaction_with_value,
};
use serde_json::Value;

use super::fixtures::{unsigned_content, unsigned_manifest_with_publisher, unsigned_transaction};
use crate::common::fixed_now;

/// Strip the top-level `sig` field from a parsed envelope `Value`.
fn strip_sig(mut value: Value) -> Value {
    if let Value::Object(ref mut map) = value {
        map.remove("sig");
    }
    value
}

/// Inject the `kind` discriminator into a typed-model-derived `Value`.
fn inject_kind(mut value: Value, kind: &str) -> Value {
    if let Value::Object(ref mut map) = value {
        map.insert("kind".to_owned(), Value::String(kind.to_owned()));
    }
    value
}

#[test]
fn manifest_wire_and_typed_signature_inputs_canonicalize_byte_equal() {
    let publisher_key = PublisherSigningKey::from_seed(&[0xB1; 32]);
    let unsigned = unsigned_manifest_with_publisher(publisher_key.verifying_key());
    let now = fixed_now();
    let (manifest, bytes) =
        build_manifest(&unsigned, &publisher_key, &now).expect("build_manifest");

    let (_typed, wire_value) =
        parse_and_validate_manifest_with_value(&bytes, &now).expect("parse_and_validate_manifest");
    let wire_payload = strip_sig(wire_value);
    let wire_jcs = canonicalize(&wire_payload).expect("canon wire");

    // Reconstruct the pre-0.3.1 verifier input: round-trip through the
    // typed model, drop sig, attach kind.
    let typed_value = serde_json::to_value(&manifest).expect("to_value(manifest)");
    let typed_payload = inject_kind(strip_sig(typed_value), "manifest");
    let typed_jcs = canonicalize(&typed_payload).expect("canon typed");

    assert_eq!(
        wire_jcs, typed_jcs,
        "wire-Value JCS must equal reserialize-typed JCS — Serialize/Deserialize \
         drift would break this and silently break signature verification"
    );
}

#[test]
fn content_wire_and_typed_signature_inputs_canonicalize_byte_equal() {
    let runtime_key = RuntimeSigningKey::from_seed(&[0xB2; 32]);
    let unsigned = unsigned_content();
    let (content, bytes) = build_content(&unsigned, &runtime_key).expect("build_content");

    let (_typed, wire_value) =
        parse_and_validate_content_with_value(&bytes).expect("parse_and_validate_content");
    let wire_jcs = canonicalize(&strip_sig(wire_value)).expect("canon wire");

    let typed_value = serde_json::to_value(&content).expect("to_value(content)");
    let typed_jcs =
        canonicalize(&inject_kind(strip_sig(typed_value), "content")).expect("canon typed");

    assert_eq!(wire_jcs, typed_jcs);
}

#[test]
fn transaction_wire_and_typed_signature_inputs_canonicalize_byte_equal() {
    let runtime_key = RuntimeSigningKey::from_seed(&[0xB3; 32]);
    let unsigned = unsigned_transaction();
    let (tx, bytes) = build_transaction(&unsigned, &runtime_key).expect("build_transaction");

    let (_typed, wire_value) =
        parse_and_validate_transaction_with_value(&bytes).expect("parse_and_validate_transaction");
    let wire_jcs = canonicalize(&strip_sig(wire_value)).expect("canon wire");

    let typed_value = serde_json::to_value(&tx).expect("to_value(tx)");
    let typed_jcs =
        canonicalize(&inject_kind(strip_sig(typed_value), "transaction")).expect("canon typed");

    assert_eq!(wire_jcs, typed_jcs);
}

/// `Manifest::canonical_payload_hash` MUST produce the same digest the
/// verifier hashes — otherwise callers using it to populate
/// `RetainedManifestRecord::manifest_payload_hash` will see spurious
/// `E_CANARY_CONFLICT` events on re-fetches.
#[test]
fn manifest_canonical_payload_hash_matches_wire_hash() {
    let publisher_key = PublisherSigningKey::from_seed(&[0xC1; 32]);
    let unsigned = unsigned_manifest_with_publisher(publisher_key.verifying_key());
    let now = fixed_now();
    let (manifest, bytes) =
        build_manifest(&unsigned, &publisher_key, &now).expect("build_manifest");

    let (_typed, wire_value) =
        parse_and_validate_manifest_with_value(&bytes, &now).expect("parse_and_validate_manifest");
    let wire_hash = sha256(&canonicalize(&strip_sig(wire_value)).expect("canon"));

    assert_eq!(manifest.canonical_payload_hash(), wire_hash);
}

/// `ManifestRead::canonical_payload_hash` must be reachable before
/// `into_parts()` — Stage-7 trust callers need it at
/// `ManifestSigVerified` time to populate retained-manifest records.
#[test]
fn manifest_canonical_payload_hash_available_pre_into_parts() {
    let publisher_key = PublisherSigningKey::from_seed(&[0xC2; 32]);
    let unsigned = unsigned_manifest_with_publisher(publisher_key.verifying_key());
    let now = fixed_now();
    let (manifest, bytes) =
        build_manifest(&unsigned, &publisher_key, &now).expect("build_manifest");

    let verified = parse_and_verify_manifest(&bytes, &now).expect("parse_and_verify_manifest");
    let hash_pre = verified.canonical_payload_hash();
    let hash_post = manifest.canonical_payload_hash();
    assert_eq!(
        hash_pre, hash_post,
        "ManifestRead and Manifest must agree on the canonical payload hash"
    );
}

/// Belt-and-braces: rearranged wire input (key order shuffled) still
/// canonicalizes identically — confirms the JCS comparator handles the
/// member-ordering responsibility on its own, so the H-1 wire-Value
/// path is not order-sensitive at the parser layer.
#[test]
fn manifest_wire_signature_input_invariant_under_key_reordering() {
    let publisher_key = PublisherSigningKey::from_seed(&[0xB4; 32]);
    let unsigned = unsigned_manifest_with_publisher(publisher_key.verifying_key());
    let now = fixed_now();
    let (_manifest, bytes) =
        build_manifest(&unsigned, &publisher_key, &now).expect("build_manifest");

    let original: Value = serde_json::from_slice(&bytes).expect("parse json");
    // Re-serialize from a BTreeMap key-rearranged form by going through a
    // fresh map populated in reverse order, then back through serde_json.
    let reordered_bytes = {
        let obj = original.as_object().expect("object").clone();
        let mut reversed: Vec<(String, Value)> = obj.into_iter().collect();
        reversed.reverse();
        let reordered_map: serde_json::Map<String, Value> = reversed.into_iter().collect();
        serde_json::to_vec(&Value::Object(reordered_map)).expect("serialize reordered")
    };

    let (_t1, wire_orig) =
        parse_and_validate_manifest_with_value(&bytes, &now).expect("parse original");
    let (_t2, wire_reordered) =
        parse_and_validate_manifest_with_value(&reordered_bytes, &now).expect("parse reordered");
    assert_eq!(
        canonicalize(&strip_sig(wire_orig)).unwrap(),
        canonicalize(&strip_sig(wire_reordered)).unwrap(),
        "JCS must canonicalize key order — wire key order at parser layer is irrelevant"
    );
}
