# entangled-core differential fuzzing

A differential fuzz harness that compares this crate (`entangled-core`) against
the independent Java reference (`entangled-api-java`) on the same inputs, to
surface places where the two conformant-looking implementations disagree on a
verdict. It is a pre-audit tool: a divergence is usually a spec ambiguity or an
implementation bug that the single-live-violation conformance corpus cannot
reach, because exposing it requires combining two violations in one document.

This is a standalone crate (its own workspace and lockfile, nightly + libFuzzer
only). It is deliberately not a member of the `entangled-api` workspace, so the
main `cargo build/test --workspace --locked` is unaffected.

## What it does

Both implementations expose the same verifier surface: a function from raw
response bytes to an accept/reject outcome. The harness feeds bytes to each, with
an identical fixed context pinned to the corpus's canonical values (origin,
runtime key, paths, clock `2026-05-07T00:01:00Z`), and reduces each outcome to a
normalized verdict string:

* `A` - accept
* `R:<CODE>` - reject with a section 11 diagnostic code
* `X:<reason>` - an unexpected throwable on the Java side (a one-sided crash; the
  Rust side surfaces a panic to the fuzzer directly)

The document kind is self-discriminated from `kind`, and the byte cap applied is
that discriminated kind's cap. The cross-endpoint case (a client that fetched
`/manifest.json` but received a content document, where the 64 KiB vs 1 MiB caps
differ) is a Stage 1 client concern outside both verifier cores and is not
exercised here.

The harness compares Rust against Java, **not** against the corpus's recorded
verdict. The fixed context intentionally differs from each vector's own context,
so three minimal vectors (001 manifest, 003 content, 005 transaction) accept and
exercise the deep accept-path stages, while every other input rejects; the only
question asked is whether the two implementations agree.

## Prerequisites

* Rust nightly and `cargo-fuzz` (`cargo install cargo-fuzz`).
* The Java reference built: from `entangled-api-java`, `mvn test-compile` (the
  diff-server `org.entangled.fuzz.DiffServer` is a test-scoped class).
* A JDK 21 on `PATH` (the `java` launcher the diff-server runs under).
* The conformance corpus checked out (the spec repo's `corpus/` directory).

## Running

```sh
# from this directory (entangled-core/fuzz)
export ENTANGLED_CORPUS_PATH=/path/to/entangled/corpus
export ENTANGLED_DIFF_CLASSPATH=/path/to/entangled-api-java/target/classes:/path/to/entangled-api-java/target/test-classes
# optionally ENTANGLED_DIFF_JAVA=/path/to/jdk-21/bin/java

# 1. Deterministic gate / regression: replay all corpus inputs through both
#    implementations and assert agreement. Proves the harness is wired correctly
#    before burning CPU on fuzzing.
cargo +nightly run --bin replay

# 2. Seed the libFuzzer corpus from the conformance vectors (one-time).
mkdir -p corpus/differential
#   ... copy each vector's input.json into corpus/differential/<id>.json ...

# 3. Fuzz. Strict mode: the first divergence is a crash artifact.
cargo +nightly fuzz run differential -- -max_len=70000 corpus/differential

# 3b. Discovery mode: enumerate every distinct divergence class in one run.
ENTANGLED_DIFF_LOG=/tmp/divergences.tsv \
  cargo +nightly fuzz run differential -- -max_len=70000 -max_total_time=600 corpus/differential
#   each line: rust<TAB>java<TAB>hex(input), one representative per (rust, java) pair

# 4. Triage one input (prints both verdicts).
cargo +nightly run --bin inspect -- artifacts/differential/crash-<hash>
```

## Binaries

* `differential` (libFuzzer target) - the fuzzer. Strict by default; discovery
  mode under `ENTANGLED_DIFF_LOG`.
* `replay` - deterministic differential over all corpus vectors; exit 0 on full
  agreement, 1 on divergence, 2 on harness error. The CI-runnable gate.
* `inspect <file>` - print the Rust and Java verdict for one input file.

## Throughput

Every input round-trips to the warm JVM over a pipe, so exec/s is well below a
pure in-process fuzzer. That is the accepted cost of an every-input differential;
the high-quality corpus seeds and the fixed accept-boundary context make each
execution count. The JVM is started once per campaign, not per input.

## Scope of the differential

In scope: Stage 2 byte checks, Stage 3 JSON parsing and the section 04 number
grammar, Stage 4 kind discrimination, Stage 5 closed-schema validation, Stage 6
signature verification (including JCS canonicalization and the section 05 strict
profile), Stage 8 canary structural checks, and Stage 9 path/origin/request
binding - for all three document kinds.

Out of scope (by construction): the cross-endpoint byte-cap case; the
history-dependent Stage 8 checks (anti-downgrade, canary-conflict, runtime-reuse)
and the migration flow, which need a seeded publisher history / successor the
fixed context does not supply; the trust-state machine, image layer, and
transport layer, which neither verifier core implements.
