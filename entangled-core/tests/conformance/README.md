# Conformance corpus integration

The Entangled v1.0 conformance corpus is distributed separately from this implementation.
When the corpus becomes available, place the corpus archive under
`tests/conformance/corpus/` (gitignored) and add tests in this directory that:

1. enumerate the corpus files;
2. for each file, parse it with the appropriate `parse_and_verify_*` function;
3. check that the outcome (accept or reject with specific diagnostic code) matches the expected outcome encoded in the corpus.

The corpus is not vendored in this repository. Each test run reads from a local copy.

This file is intentionally minimal until the corpus exists.
