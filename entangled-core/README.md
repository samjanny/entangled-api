# entangled-core

Rust implementation of the Entangled v1.0 protocol — typed documents, closed-schema validation, JCS canonicalization, Ed25519 signing/verification, BIP-39 PIP derivation, Tor v3 origin binding, and client-side state management.

The full protocol specification is at [github.com/samjanny/entangled](https://github.com/samjanny/entangled).

## Status

Version 0.1.0. The library covers the static API surface of Entangled v1.0:

- Document types (Manifest, Content, Transaction)
- Block types (11 kinds, closed schema)
- Closed-schema validation (Stages 2-5 of §10)
- JCS canonicalization (RFC 8785)
- Ed25519 sign/verify (RFC 8032)
- Publisher Identity Phrase (BIP-39 24-word)
- Tor v3 origin binding (rend-spec-v3.txt)
- Canary state and anti-downgrade (Stage 8)
- State management with consent model
- Submit body construction and validation

Out of scope for this crate (will be in `entangled-client` and `entangled-transport`):

- HTTP/onion transport
- Trust state machine (Stage 7)
- Publisher history persistence
- UI chrome and consent prompts

## Quick start

```rust
use entangled_core::crypto::{derive_pip, pip_to_pubkey, PublisherSigningKey};

// Build a publisher signing key from a deterministic seed (test/dev).
let publisher = PublisherSigningKey::from_seed(&[0x42; 32]);
let publisher_pubkey = publisher.verifying_key();

// Derive the human-shareable Publisher Identity Phrase.
let pip = derive_pip(&publisher_pubkey);
assert_eq!(pip.split_whitespace().count(), 24);

// Recover the pubkey from the PIP only.
let recovered = pip_to_pubkey(&pip).unwrap();
assert_eq!(recovered, publisher_pubkey);
```

The same example, runnable, lives at the top of [`lib.rs`](src/lib.rs).

## License

Dual-licensed under MIT or Apache-2.0, at your choice.

## Forbidden unsafe

This crate has `#![forbid(unsafe_code)]` at the top of `lib.rs`. Some dependencies (`ed25519-dalek`, `curve25519-dalek`, `sha2`, `sha3`) contain `unsafe` for SIMD and field-arithmetic optimizations; they are maintained by the RustCrypto and dalek-cryptography projects.

## Module guide

- [`types`](https://docs.rs/entangled-core/latest/entangled_core/types/) — wire format types
- [`canon`](https://docs.rs/entangled-core/latest/entangled_core/canon/) — JCS canonicalization
- [`crypto`](https://docs.rs/entangled-core/latest/entangled_core/crypto/) — Ed25519, SHA-256, BIP-39
- [`validation`](https://docs.rs/entangled-core/latest/entangled_core/validation/) — pipeline stages 2-5 + canary + clock skew + state policy
- [`document`](https://docs.rs/entangled-core/latest/entangled_core/document/) — high-level builder/parser API
- [`state`](https://docs.rs/entangled-core/latest/entangled_core/state/) — client-side state management
- [`tor`](https://docs.rs/entangled-core/latest/entangled_core/tor/) — Tor v3 onion address handling
