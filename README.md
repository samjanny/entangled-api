# Entangled API

[![CI](https://github.com/samjanny/entangled-api/actions/workflows/ci.yml/badge.svg)](https://github.com/samjanny/entangled-api/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![MSRV](https://img.shields.io/badge/MSRV-1.88-orange.svg)](#install)

Rust implementation of the Entangled v1.0 protocol: typed signed documents, closed-schema validation, JCS canonicalization, Ed25519 signing and verification, Publisher Identity Phrase derivation, Tor v3 origin binding, canary checks, and client-side state helpers.

Entangled is a protocol for publishing signed, structured documents over hostile or anonymity-oriented carrier networks. It is designed for small content sites where the reader should be able to verify publisher identity while the client keeps the rendering attack surface deliberately narrow.

A site built with Entangled is not a web application. It is a set of signed JSON documents served over a carrier such as Tor v3 and rendered by a dedicated client. There is no JavaScript, no DOM scripting, no HTML, no cookies, no ambient browser storage, and no publisher-controlled client chrome.

## Status

`entangled-api` currently contains one Rust crate:

- [`entangled-core`](./entangled-core): the protocol core library.

Current crate version: `0.5.6`.

Implemented in `entangled-core`:

- Manifest, content, and transaction document types.
- Closed-schema validation for Entangled v1.0 wire formats.
- Eleven signed content block kinds.
- JCS canonicalization for signature inputs.
- Ed25519 signing and strict verification.
- Signature domain separation for manifests, content, and transactions.
- Publisher Identity Phrase derivation and recovery.
- Tor v3 onion address parsing and origin binding.
- Manifest type-state verification pipeline.
- Canary structure checks and canary state calculation.
- Anti-downgrade helper for publisher history checks.
- Client-side state storage with policy-aware helpers.
- Submit-body construction and validation.

Out of scope for this crate:

- Network transport.
- HTTP client/server implementation.
- Full Entangled browser/client UI.
- Trust-state persistence and UI chrome.
- Publisher history storage.
- Consent prompt UI.
- Image decoding and rendering.

Those are expected to live in higher-level crates or applications.

## Why Entangled exists

Entangled separates four concerns that are usually tangled together on the web:

1. **Publisher identity** — a long-term offline Ed25519 identity key.
2. **Carrier reachability** — an address such as a Tor v3 onion service.
3. **Routine publication signing** — a periodically rotated runtime key.
4. **Document rendering** — a constrained grammar rendered by the client.

The goal is to let a reader verify that a document belongs to the same publisher across server compromise, origin rotation, or carrier migration, while avoiding the attack surface of a general-purpose browser runtime.

Entangled is not an anonymity layer, a web replacement, a distributed storage system, or a deniability mechanism. It relies on the selected carrier network for routing, reachability, and any network-layer anonymity.

## Repository layout

```text
.
├── Cargo.toml                  # Workspace manifest
├── Cargo.lock                  # Locked dependency set
├── deny.toml                   # cargo-deny policy
├── CHANGELOG.md
├── LICENSE-MIT
├── LICENSE-APACHE
└── entangled-core/             # Rust core implementation
    ├── Cargo.toml
    ├── README.md
    ├── src/
    └── tests/
```

The protocol specification itself lives in a separate repository,
[github.com/samjanny/entangled](https://github.com/samjanny/entangled),
referenced from the [Specification](#specification) section below.

## Install

Add the core crate to a Rust project:

```toml
[dependencies]
entangled-core = "0.1"
```

Or, while developing against this repository:

```toml
[dependencies]
entangled-core = { path = "entangled-core" }
```

Minimum supported Rust version: `1.88`.

## Quick start

Derive a Publisher Identity Phrase from a publisher public key and recover the key from the phrase:

```rust
use entangled_core::crypto::{derive_pip, pip_to_pubkey, PublisherSigningKey};

let publisher = PublisherSigningKey::from_seed(&[0x42; 32]);
let publisher_pubkey = publisher.verifying_key();

let pip = derive_pip(&publisher_pubkey);
assert_eq!(pip.split_whitespace().count(), 24);

let recovered = pip_to_pubkey(&pip).unwrap();
assert_eq!(recovered, publisher_pubkey);
```

The PIP is public. It is not a seed phrase, password, recovery secret, or private key. It is a human-readable fingerprint of the publisher identity key.

## Building and signing documents

The `document` module mirrors each signed wire type with an `Unsigned*` counterpart (`UnsignedManifest`, `UnsignedContent`, `UnsignedTransaction`) and a `build_*` function. The builder validates the unsigned value against the closed schema, canonicalizes it (JCS), signs the canonical payload with the role-appropriate key, and returns the signed struct plus its exact serialized wire bytes. Manifests are signed by `K_publisher`; content and transaction documents by `K_runtime`.

A content document is signed by the runtime key:

```rust
use entangled_core::crypto::RuntimeSigningKey;
use entangled_core::document::{build_content, UnsignedContent};
use entangled_core::types::blocks::Block;
use entangled_core::types::inline::{InlineElement, TextMark};
use entangled_core::types::keys::SpecVersion;
use entangled_core::types::meta::Meta;
use entangled_core::types::path::EntangledPath;
use entangled_core::types::timestamp::EntangledTimestamp;

# fn demo() -> Result<(), entangled_core::document::DocumentError> {
let runtime = RuntimeSigningKey::from_seed(&[0x01; 32]);

let unsigned = UnsignedContent {
    spec_version: SpecVersion,
    path: EntangledPath::try_from("/articles/first-post")
        .expect("valid content path"),
    meta: Meta {
        title: "First post".to_owned(),
        published_at: EntangledTimestamp::try_from("2026-05-07T00:00:00Z")
            .expect("valid timestamp"),
    },
    blocks: vec![Block::Paragraph {
        content: vec![InlineElement::Text {
            value: "Hello, world.".to_owned(),
            marks: Vec::<TextMark>::new(),
        }],
    }],
    // Optional content sequence number; required only when the manifest
    // declares `content_root` and the path is indexed (see the content
    // index section).
    seq: None,
};

let (content, wire_bytes) = build_content(&unsigned, &runtime)?;
// `wire_bytes` is the exact byte sequence to serve at `content.path`.
# let _ = (content, wire_bytes);
# Ok(())
# }
```

Manifests follow the same shape with `build_manifest`, which additionally takes the current time to enforce the `updated` clock-skew bound at build time. `UnsignedManifest` carries the nested `origin` and `canary` blocks; once assembled, signing is one call:

```rust
use entangled_core::crypto::PublisherSigningKey;
use entangled_core::document::{build_manifest, UnsignedManifest};
use entangled_core::types::timestamp::EntangledTimestamp;

# // The full UnsignedManifest construction (origin, canary, state_policy, ...)
# // is elided here; see tests/tor/integration_full.rs for a complete value.
# fn demo(unsigned: &UnsignedManifest) -> Result<(), entangled_core::document::DocumentError> {
let publisher = PublisherSigningKey::from_seed(&[0x42; 32]);
let now = EntangledTimestamp::try_from("2026-05-07T00:00:00Z")
    .expect("valid timestamp");

let (manifest, wire_bytes) = build_manifest(unsigned, &publisher, &now)?;
// `wire_bytes` is the exact byte sequence to serve at `/manifest.json`.
# let _ = (manifest, wire_bytes);
# Ok(())
# }
```

`build_transaction` is analogous (signed by `K_runtime`, taking an `UnsignedTransaction`). On failure the builders return `DocumentError`; its `DocumentError::Validation(Diagnostic)` variant carries the normative diagnostic, so a caller can match on the contained `Diagnostic.code` (a `DiagnosticCode` per the specification's section 11). The produced `wire_bytes` round-trip exactly: feeding them back into `parse_and_verify_*` (below) reproduces the signed struct.

## Security model at a glance

Entangled uses three key roles:

| Key | Role | Exposure profile |
| --- | --- | --- |
| `K_publisher` | Long-term publisher identity | Offline; used only for publisher ceremonies |
| `K_origin` | Carrier endpoint identity | Online or near-online; for Tor v3, the onion service key |
| `K_runtime` | Routine document signing | Online; rotated periodically through the manifest canary |

The publisher key signs the manifest. The manifest authorizes the current origin and runtime key. Content and transaction documents are signed by the runtime key.

A server compromise may expose `K_origin` and `K_runtime`, but should not expose `K_publisher` if the operator follows the intended custody model. The publisher identity survives server compromise as long as `K_publisher` remains offline and uncompromised.

## Validation pipeline

`entangled-core` implements the static validation and signature-verification parts of the Entangled client pipeline:

1. Input byte-size checks.
2. UTF-8 and BOM checks.
3. JSON parsing with structural limits.
4. Document-kind discrimination.
5. Closed-schema validation.
6. Signature verification.
7. Manifest type-state transition into canary and origin checks.

Trust-state lookup, TOFU pinning, externally verified PIP state, publisher history persistence, and client UI behavior remain the responsibility of the embedding client.

## Manifest verification

Manifest parsing returns a type-state wrapper rather than a bare `Manifest`. This forces callers to explicitly continue or consciously opt out of later verification stages.

```rust
use entangled_core::document::parse_and_verify_manifest;
use entangled_core::types::{EntangledTimestamp, OnionAddress};

# fn verify_manifest_bytes(
#     manifest_bytes: &[u8],
#     now: &EntangledTimestamp,
#     fetched_onion: &OnionAddress,
#     content_index_bytes: Option<&[u8]>,
# ) -> Result<(), entangled_core::validation::Diagnostic> {
let verified = parse_and_verify_manifest(manifest_bytes, now)?;

let (manifest, canary_state, content_index) = verified
    .verify_canary(now)?
    .verify_origin(fetched_onion, now)?
    .verify_content_index(content_index_bytes)?
    .into_parts();

let runtime_pubkey = manifest.canary.runtime_pubkey;
# let _ = canary_state;
# let _ = content_index;
# let _ = runtime_pubkey;
# Ok(())
# }
```

`verify_content_index` enforces the Section 09:116 hard-fail model when the manifest declares `content_root`: callers MUST supply the `/content_index.json` response body bytes, which are hash-verified against `content_root` and structurally validated. A manifest that omits `content_root` accepts `None` here and yields `content_index = None`.

If a caller is building offline tooling, conformance tests, or another context where canary/origin/content-index checks are intentionally not applicable, the API provides explicit opt-out methods such as `skip_canary_check`, `skip_origin_check`, and `skip_content_index_check`.

## Canary state and the Expired user-override contract

`verify_canary` returns the manifest as `ManifestCanaryChecked` and exposes the classified `CanaryState` via `canary_state()`. The library does not act on the state: rendering policy lives in the embedding client.

Section 08:183 of the specification is a normative MUST: when `CanaryState::Expired` is observed, the client MUST refuse to render current content. The content area MUST be blank or a client-generated placeholder; publisher-controlled content MUST NOT appear.

Section 08:185 attaches a second MUST to the rendering block: the client MUST provide a per-session user-override affordance with these properties:

- an affirmative-action chrome control (a button, key combination, or equivalent affordance) whose semantics are unambiguously "accept the risk and proceed"; passive events MUST NOT count as acceptance;
- the override applies only for the remainder of the current session for the affected site, does not persist across sessions, does not modify the canary state, and does not suppress the chrome warning;
- while the override is active, a persistent, not-easily-dismissible warning MUST stay visible in the chrome.

The Section 11 diagnostic code `E_CANARY_EXPIRED` is catalogued at `error` severity (rc.23 N64; the code was `W_CANARY_EXPIRED` at `warning` severity in rc.10 through rc.22, and rc.23 closed the catalog-vs-behavior mismatch by renaming and promoting). The catalog now aligns with the Section 08:183 normative MUST that rendering of current content is blocked. The Section 08:185 per-session user-override affordance and the Section 08 permissive-canary mode are the spec-defined laxer-policy carve-outs to the default block, distinct from a Section 11:87 client-side reclassification of severity. `entangled-core` classifies the canary, surfaces `CanaryState::Expired`, and emits the diagnostic at `error` severity. The override state, the chrome affordance, and the session-scoped persistence all live in the embedding client.

## Content verification

Content documents are verified against the runtime key authorized by a verified manifest:

```rust
use entangled_core::document::parse_and_verify_content;
use entangled_core::types::RuntimePubkey;

# fn verify_content_bytes(
#     content_bytes: &[u8],
#     runtime_pubkey: &RuntimePubkey,
# ) -> Result<(), entangled_core::validation::Diagnostic> {
let content = parse_and_verify_content(content_bytes, runtime_pubkey)?;

// Higher-level clients should also bind `content.path` to the path that was fetched.
# let _ = content;
# Ok(())
# }
```

## Transaction verification

Transaction documents are also signed by the runtime key:

```rust
use entangled_core::document::parse_and_verify_transaction;
use entangled_core::types::RuntimePubkey;

# fn verify_transaction_bytes(
#     transaction_bytes: &[u8],
#     runtime_pubkey: &RuntimePubkey,
# ) -> Result<(), entangled_core::validation::Diagnostic> {
let transaction = parse_and_verify_transaction(transaction_bytes, runtime_pubkey)?;

// Higher-level clients should bind `transaction.in_response_to` to the submit path.
# let _ = transaction;
# Ok(())
# }
```

## Core modules

| Module | Purpose |
| --- | --- |
| `types` | Wire-format types for manifests, content, transactions, blocks, links, forms, paths, timestamps, and keys |
| `canon` | JCS canonicalization and signature-input construction |
| `crypto` | Ed25519 wrappers, signing helpers, SHA-256 helpers, and PIP derivation |
| `validation` | Input checks, closed-schema validation, diagnostic codes, canary checks, state policy checks, and submit validation |
| `document` | High-level builders, parsers, and manifest type-state wrappers |
| `state` | Client-side state store and submit-body construction helpers |
| `tor` | Tor v3 onion address parsing, checksum validation, and origin binding |

## Development

Run the test suite:

```bash
cargo test --all --locked
```

Run formatting and lint checks:

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
```

Run dependency/license/advisory checks if `cargo-deny` is installed:

```bash
cargo deny check advisories licenses bans sources
```

A recommended local pre-release check is:

```bash
cargo fmt --all --check
cargo test --all --locked
cargo clippy --all-targets --all-features -- -D warnings
cargo deny check advisories licenses bans sources
```

## Security posture

The core crate forbids unsafe Rust at the crate root:

```rust
#![forbid(unsafe_code)]
```

Some transitive dependencies may use `unsafe` internally for cryptographic arithmetic or SIMD optimizations. Those are dependency-level implementation details, not unsafe code in this crate.

Security-relevant design choices include:

- strict Ed25519 verification;
- separate signing domains for each document family;
- bounded input size and structural validation;
- duplicate-key rejection during JSON parsing;
- closed schemas with unknown-field rejection;
- deterministic canonicalization before signing and verification;
- explicit Tor v3 origin binding;
- explicit PIP-based publisher identity model;
- runtime-key rotation through manifest canaries.

If you report a security issue, please include:

- the affected crate/version or commit;
- a minimal reproducer if available;
- whether the issue affects signature verification, canonicalization, parsing, state handling, origin binding, or API misuse.

## Specification

The protocol specification lives in a separate repository:
[github.com/samjanny/entangled](https://github.com/samjanny/entangled).

- [`00-overview.md`](https://github.com/samjanny/entangled/blob/main/specs/00-overview.md)
- [`01-glossary.md`](https://github.com/samjanny/entangled/blob/main/specs/01-glossary.md)
- [`02-document-schema.md`](https://github.com/samjanny/entangled/blob/main/specs/02-document-schema.md)
- [`03-block-types.md`](https://github.com/samjanny/entangled/blob/main/specs/03-block-types.md)
- [`04-canonicalization.md`](https://github.com/samjanny/entangled/blob/main/specs/04-canonicalization.md)
- [`05-keys-and-signing.md`](https://github.com/samjanny/entangled/blob/main/specs/05-keys-and-signing.md)
- [`06-manifest.md`](https://github.com/samjanny/entangled/blob/main/specs/06-manifest.md)
- [`07-state.md`](https://github.com/samjanny/entangled/blob/main/specs/07-state.md)
- [`08-canary.md`](https://github.com/samjanny/entangled/blob/main/specs/08-canary.md)
- [`09-transport.md`](https://github.com/samjanny/entangled/blob/main/specs/09-transport.md)
- [`10-client-behavior.md`](https://github.com/samjanny/entangled/blob/main/specs/10-client-behavior.md)
- [`11-errors-and-versioning.md`](https://github.com/samjanny/entangled/blob/main/specs/11-errors-and-versioning.md)

For operational guidance, see
[`docs/operator-playbook.md`](https://github.com/samjanny/entangled/blob/main/docs/operator-playbook.md).

## License

Code is dual-licensed under either of:

- MIT License
- Apache License, Version 2.0

Protocol/specification documents are covered separately under the licenses declared in
[`LICENSE.md`](https://github.com/samjanny/entangled/blob/main/LICENSE.md)
in the spec repository.
