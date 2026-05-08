# Conformance corpus integration

The Entangled v1.0 conformance corpus is vendored at the workspace root
under `docs-spec/corpus/`. The harness in this directory loads
`corpus.json`, mocks the implementation clock to its top-level `clock_now`
field, and runs every vector through the appropriate
`parse_and_verify_*` plus, where context dictates, Stage 8 canary checks
and Stage 9 binding.

A single integration test — `corpus_vectors_match_spec` — fails on the
first divergence with a message naming the vector id.

```
cargo test --test conformance
```
