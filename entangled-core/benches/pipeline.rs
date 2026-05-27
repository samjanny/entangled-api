//! Performance benchmarks for the entangled-core hot paths.
//!
//! Run with:  cargo bench --bench pipeline
//! Baseline:  cargo bench --bench pipeline -- --save-baseline pre-opt
//! Compare:   cargo bench --bench pipeline -- --baseline pre-opt

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use data_encoding::BASE32;
use sha3::{Digest, Sha3_256};

use entangled_core::crypto::{sha256, PublisherSigningKey, RuntimeSigningKey};
use entangled_core::document::{
    build_content, build_manifest, build_transaction, parse_and_verify_content,
    parse_and_verify_manifest, UnsignedContent, UnsignedManifest, UnsignedTransaction,
};
use entangled_core::types::{
    blocks::{Block, FeedbackVariant},
    canary::Canary,
    inline::{InlineElement, TextMark},
    keys::{ContentHash, OriginPubkey, PublisherPubkey, RuntimePubkey, SpecVersion},
    manifest::{Carrier, OnionAddress, Origin},
    meta::Meta,
    path::EntangledPath,
    timestamp::EntangledTimestamp,
};
use entangled_core::validation::{
    parse_and_validate_content, parse_and_validate_manifest, validate_content_index,
    verify_content_against_index,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ts(s: &str) -> EntangledTimestamp {
    EntangledTimestamp::try_from(s).unwrap()
}

fn fixed_now() -> EntangledTimestamp {
    ts("2026-05-07T00:00:00Z")
}

fn path(s: &str) -> EntangledPath {
    EntangledPath::try_from(s).unwrap()
}

fn derive_onion_address(pubkey: &[u8; 32]) -> OnionAddress {
    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(pubkey);
    hasher.update([0x03]);
    let digest = hasher.finalize();
    let checksum = [digest[0], digest[1]];
    let mut payload = [0u8; 35];
    payload[..32].copy_from_slice(pubkey);
    payload[32..34].copy_from_slice(&checksum);
    payload[34] = 0x03;
    let body = BASE32.encode(&payload).to_ascii_lowercase();
    let s = format!("{body}.onion");
    OnionAddress::try_from(s.as_str()).unwrap()
}

fn make_paragraph(text: &str) -> Block {
    Block::Paragraph {
        content: vec![InlineElement::Text {
            value: text.to_owned(),
            marks: Vec::<TextMark>::new(),
        }],
    }
}

struct TestKeys {
    publisher: PublisherSigningKey,
    publisher_pk: PublisherPubkey,
    runtime: RuntimeSigningKey,
    runtime_pk: RuntimePubkey,
    origin_pk: OriginPubkey,
    onion: OnionAddress,
}

fn test_keys() -> TestKeys {
    let publisher = PublisherSigningKey::from_seed(&[0xA1; 32]);
    let publisher_pk = publisher.verifying_key();
    let runtime = RuntimeSigningKey::from_seed(&[0xB2; 32]);
    let runtime_pk = runtime.verifying_key();
    let origin_pk_bytes = *PublisherSigningKey::from_seed(&[0xC3; 32])
        .verifying_key()
        .as_bytes();
    let origin_pk = OriginPubkey::from_bytes(origin_pk_bytes);
    let onion = derive_onion_address(&origin_pk_bytes);
    TestKeys {
        publisher,
        publisher_pk,
        runtime,
        runtime_pk,
        origin_pk,
        onion,
    }
}

fn minimal_unsigned_manifest(keys: &TestKeys) -> UnsignedManifest {
    UnsignedManifest {
        spec_version: SpecVersion,
        publisher_pubkey: keys.publisher_pk,
        origin: Origin {
            carrier: Carrier::TorV3,
            address: keys.onion.clone(),
            origin_pubkey: keys.origin_pk,
            not_after: None,
        },
        canary: Canary {
            runtime_pubkey: keys.runtime_pk,
            issued_at: ts("2026-05-07T00:00:00Z"),
            next_expected: ts("2026-06-06T00:00:00Z"),
            statement: "All clear.".to_owned(),
            freshness_proof: None,
        },
        state_policy: vec![],
        navigation: vec![],
        min_refresh_interval: 86_400,
        updated: ts("2026-05-07T00:00:00Z"),
        migration_pointer: None,
        content_root: None,
    }
}

fn minimal_unsigned_content() -> UnsignedContent {
    UnsignedContent {
        spec_version: SpecVersion,
        path: path("/articles/first"),
        meta: Meta {
            title: "First post".to_owned(),
            published_at: ts("2026-05-07T00:00:00Z"),
        },
        blocks: vec![make_paragraph("Hello world.")],
        seq: None,
    }
}

fn large_unsigned_content(n_blocks: usize) -> UnsignedContent {
    let blocks: Vec<Block> = (0..n_blocks)
        .map(|i| make_paragraph(&format!("Paragraph {i} with some representative content that exercises the inline validation path and NFC checks.")))
        .collect();
    UnsignedContent {
        spec_version: SpecVersion,
        path: path("/articles/large"),
        meta: Meta {
            title: "Large document".to_owned(),
            published_at: ts("2026-05-07T00:00:00Z"),
        },
        blocks,
        seq: Some(1),
    }
}

fn minimal_unsigned_transaction() -> UnsignedTransaction {
    UnsignedTransaction {
        spec_version: SpecVersion,
        in_response_to: path("/contact"),
        request_id: entangled_core::types::keys::RequestId::generate(),
        request_hash: entangled_core::types::keys::RequestHash::try_from(
            "sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        .unwrap(),
        state_updates: vec![],
        blocks: vec![Block::Feedback {
            variant: FeedbackVariant::Success,
            content: vec![InlineElement::Text {
                value: "Received.".to_owned(),
                marks: Vec::<TextMark>::new(),
            }],
        }],
    }
}

fn make_content_index_bytes(n_entries: usize) -> Vec<u8> {
    let mut entries = serde_json::Map::new();
    for i in 0..n_entries {
        let path = format!("/articles/post-{i}");
        let hash_bytes = sha256(format!("content-{i}").as_bytes());
        let hash_str = format!(
            "sha-256:{}",
            data_encoding::BASE64URL_NOPAD.encode(&hash_bytes)
        );
        let entry = serde_json::json!({
            "seq": (i + 1) as u64,
            "hash": hash_str,
        });
        entries.insert(path, entry);
    }
    let index = serde_json::json!({ "entries": entries });
    serde_json::to_vec(&index).unwrap()
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

fn bench_build_manifest(c: &mut Criterion) {
    let keys = test_keys();
    let unsigned = minimal_unsigned_manifest(&keys);
    let now = fixed_now();

    c.bench_function("build_manifest", |b| {
        b.iter(|| build_manifest(black_box(&unsigned), &keys.publisher, &now).unwrap())
    });
}

fn bench_parse_verify_manifest(c: &mut Criterion) {
    let keys = test_keys();
    let unsigned = minimal_unsigned_manifest(&keys);
    let now = fixed_now();
    let (_manifest, bytes) = build_manifest(&unsigned, &keys.publisher, &now).unwrap();

    c.bench_function("parse_verify_manifest", |b| {
        b.iter(|| {
            let v = parse_and_verify_manifest(black_box(&bytes), &now).unwrap();
            v.skip_canary_check();
        })
    });
}

fn bench_parse_validate_manifest(c: &mut Criterion) {
    let keys = test_keys();
    let unsigned = minimal_unsigned_manifest(&keys);
    let now = fixed_now();
    let (_manifest, bytes) = build_manifest(&unsigned, &keys.publisher, &now).unwrap();

    c.bench_function("parse_validate_manifest_stages2_5", |b| {
        b.iter(|| parse_and_validate_manifest(black_box(&bytes), &now).unwrap())
    });
}

fn bench_canonical_payload_hash(c: &mut Criterion) {
    let keys = test_keys();
    let unsigned = minimal_unsigned_manifest(&keys);
    let now = fixed_now();
    let (manifest, _bytes) = build_manifest(&unsigned, &keys.publisher, &now).unwrap();

    c.bench_function("canonical_payload_hash", |b| {
        b.iter(|| black_box(manifest.canonical_payload_hash()))
    });
}

fn bench_build_content_small(c: &mut Criterion) {
    let keys = test_keys();
    let unsigned = minimal_unsigned_content();

    c.bench_function("build_content_1_block", |b| {
        b.iter(|| build_content(black_box(&unsigned), &keys.runtime).unwrap())
    });
}

fn bench_build_content_large(c: &mut Criterion) {
    let keys = test_keys();
    let unsigned = large_unsigned_content(100);

    c.bench_function("build_content_100_blocks", |b| {
        b.iter(|| build_content(black_box(&unsigned), &keys.runtime).unwrap())
    });
}

fn bench_parse_verify_content(c: &mut Criterion) {
    let keys = test_keys();
    let unsigned = minimal_unsigned_content();
    let (_content, bytes) = build_content(&unsigned, &keys.runtime).unwrap();

    c.bench_function("parse_verify_content_1_block", |b| {
        b.iter(|| parse_and_verify_content(black_box(&bytes), &keys.runtime_pk).unwrap())
    });
}

fn bench_parse_verify_content_large(c: &mut Criterion) {
    let keys = test_keys();
    let unsigned = large_unsigned_content(100);
    let (_content, bytes) = build_content(&unsigned, &keys.runtime).unwrap();

    c.bench_function("parse_verify_content_100_blocks", |b| {
        b.iter(|| parse_and_verify_content(black_box(&bytes), &keys.runtime_pk).unwrap())
    });
}

fn bench_parse_validate_content(c: &mut Criterion) {
    let keys = test_keys();
    let unsigned = large_unsigned_content(100);
    let (_content, bytes) = build_content(&unsigned, &keys.runtime).unwrap();

    c.bench_function("parse_validate_content_100_blocks_stages2_5", |b| {
        b.iter(|| parse_and_validate_content(black_box(&bytes)).unwrap())
    });
}

fn bench_build_transaction(c: &mut Criterion) {
    let keys = test_keys();
    let unsigned = minimal_unsigned_transaction();

    c.bench_function("build_transaction", |b| {
        b.iter(|| build_transaction(black_box(&unsigned), &keys.runtime).unwrap())
    });
}

fn bench_validate_content_index_small(c: &mut Criterion) {
    let index_bytes = make_content_index_bytes(10);
    let hash = sha256(&index_bytes);
    let content_root = entangled_core::types::keys::ContentRoot::from_bytes(hash);

    c.bench_function("validate_content_index_10_entries", |b| {
        b.iter(|| validate_content_index(black_box(&index_bytes), &content_root).unwrap())
    });
}

fn bench_validate_content_index_large(c: &mut Criterion) {
    let index_bytes = make_content_index_bytes(500);
    let hash = sha256(&index_bytes);
    let content_root = entangled_core::types::keys::ContentRoot::from_bytes(hash);

    c.bench_function("validate_content_index_500_entries", |b| {
        b.iter(|| validate_content_index(black_box(&index_bytes), &content_root).unwrap())
    });
}

fn bench_verify_content_against_index(c: &mut Criterion) {
    let index_bytes = make_content_index_bytes(100);
    let hash = sha256(&index_bytes);
    let content_root = entangled_core::types::keys::ContentRoot::from_bytes(hash);
    let index = validate_content_index(&index_bytes, &content_root).unwrap();

    let doc_hash_bytes = sha256(b"content-50");
    let doc_hash = ContentHash::from_bytes(doc_hash_bytes);

    c.bench_function("verify_content_against_index_hit", |b| {
        b.iter(|| {
            verify_content_against_index(
                black_box(&index),
                "/articles/post-50",
                Some(51),
                &doc_hash,
            )
            .unwrap()
        })
    });

    c.bench_function("verify_content_against_index_miss", |b| {
        b.iter(|| {
            verify_content_against_index(
                black_box(&index),
                "/articles/not-indexed",
                None,
                &doc_hash,
            )
            .unwrap()
        })
    });
}

fn bench_sha256_1k(c: &mut Criterion) {
    let data = vec![0xABu8; 1024];
    c.bench_function("sha256_1k", |b| b.iter(|| sha256(black_box(&data))));
}

fn bench_sha256_64k(c: &mut Criterion) {
    let data = vec![0xABu8; 65536];
    c.bench_function("sha256_64k", |b| b.iter(|| sha256(black_box(&data))));
}

criterion_group!(
    build,
    bench_build_manifest,
    bench_build_content_small,
    bench_build_content_large,
    bench_build_transaction,
);

criterion_group!(
    parse,
    bench_parse_verify_manifest,
    bench_parse_validate_manifest,
    bench_parse_verify_content,
    bench_parse_verify_content_large,
    bench_parse_validate_content,
);

criterion_group!(manifest_ops, bench_canonical_payload_hash,);

criterion_group!(
    content_index,
    bench_validate_content_index_small,
    bench_validate_content_index_large,
    bench_verify_content_against_index,
);

criterion_group!(crypto, bench_sha256_1k, bench_sha256_64k,);

criterion_main!(build, parse, manifest_ops, content_index, crypto);
