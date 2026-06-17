#!/usr/bin/env bash
# fuzz.sh -- wrapper around cargo-fuzz and the auxiliary binaries in this crate.
#
# USAGE
#   fuzz.sh [MODE] [OPTIONS]
#
# MODES
#   run [TARGET]          Run cargo-fuzz on TARGET (default: oracles).
#                         TARGET is one of: oracles, differential.
#   replay                Rust-vs-Java differential replay over the corpus.
#   check-oracles         Rust-only oracle check over the corpus (no Java).
#   inspect FILE          Print both verdicts for a single input file.
#   list                  Print available fuzz targets.
#   help                  Print this message.
#
# ENVIRONMENT -- required for corpus-aware modes
#   ENTANGLED_CORPUS_PATH     Path to the conformance corpus directory
#                              (must contain corpus.json).
#
# ENVIRONMENT -- required for modes that call the Java diff-server
#   ENTANGLED_DIFF_CLASSPATH  Java classpath for the compiled entangled-api-java
#                              classes, e.g.:
#                              <repo>/target/classes:<repo>/target/test-classes
#
# ENVIRONMENT -- optional
#   ENTANGLED_DIFF_JAVA       java launcher (default: java).
#   ENTANGLED_DIFF_LOG        Discovery-mode log path for the differential target.
#                              When set, divergences are recorded and the run
#                              continues instead of panicking on the first one.
#
# LIBFUZZER PASS-THROUGH OPTIONS (only for 'run' mode)
#   -d / --duration SECS  Max total fuzzing time in seconds (default: unlimited).
#   -j / --jobs N         Number of parallel fuzzing jobs (default: 1).
#   -m / --max-len BYTES  Max input length in bytes (default: 70000).
#   --                    Pass any remaining arguments verbatim to libFuzzer.
#
# EXAMPLES
#   # Rust-only oracle fuzz, 5 minutes, 4 jobs:
#   ENTANGLED_CORPUS_PATH=~/corpus ./fuzz.sh run oracles -d 300 -j 4
#
#   # Differential fuzz in discovery mode, no time limit:
#   ENTANGLED_CORPUS_PATH=~/corpus \
#   ENTANGLED_DIFF_CLASSPATH=~/entangled-api-java/target/classes:... \
#   ENTANGLED_DIFF_LOG=/tmp/diff.log \
#   ./fuzz.sh run differential -j 2
#
#   # Quick oracle check over the corpus, no fuzzer:
#   ENTANGLED_CORPUS_PATH=~/corpus ./fuzz.sh check-oracles
#
#   # Replay corpus through both Rust and Java:
#   ENTANGLED_CORPUS_PATH=~/corpus \
#   ENTANGLED_DIFF_CLASSPATH=... \
#   ./fuzz.sh replay
#
#   # Triage a crash artifact:
#   ENTANGLED_CORPUS_PATH=~/corpus \
#   ENTANGLED_DIFF_CLASSPATH=... \
#   ./fuzz.sh inspect artifacts/differential/crash-deadbeef

set -euo pipefail

# ---------------------------------------------------------------------------
# Locate the fuzz crate directory (this script lives next to Cargo.toml).
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

die() { echo "fuzz.sh: error: $*" >&2; exit 1; }

usage() {
    sed -n '/^# USAGE/,/^[^#]/{ /^#/{ s/^# \{0,1\}//; p }; /^[^#]/q }' "$0"
}

# ---------------------------------------------------------------------------
# Detect toolchain.
# ---------------------------------------------------------------------------
if ! rustup toolchain list 2>/dev/null | grep -q nightly; then
    die "nightly toolchain not found -- install with: rustup toolchain install nightly"
fi
CARGO_NIGHTLY="cargo +nightly"

# ---------------------------------------------------------------------------
# Parse global mode.
# ---------------------------------------------------------------------------
MODE="${1:-run}"
shift || true

case "$MODE" in
    run|replay|check-oracles|inspect|list|help) ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown mode '$MODE'; run 'fuzz.sh help' for usage" ;;
esac

# ---------------------------------------------------------------------------
# MODE: help
# ---------------------------------------------------------------------------
if [[ "$MODE" == "help" ]]; then
    sed -n '2,/^set -/{ /^#/{ s/^# \{0,1\}//; p }; /^set -/q }' "$0"
    exit 0
fi

# ---------------------------------------------------------------------------
# MODE: list
# ---------------------------------------------------------------------------
if [[ "$MODE" == "list" ]]; then
    echo "Available fuzz targets:"
    (cd "$SCRIPT_DIR" && $CARGO_NIGHTLY fuzz list)
    exit 0
fi

# ---------------------------------------------------------------------------
# MODE: replay
# ---------------------------------------------------------------------------
if [[ "$MODE" == "replay" ]]; then
    [[ -n "${ENTANGLED_CORPUS_PATH:-}" ]] || \
        die "ENTANGLED_CORPUS_PATH must be set for replay"
    [[ -n "${ENTANGLED_DIFF_CLASSPATH:-}" ]] || \
        die "ENTANGLED_DIFF_CLASSPATH must be set for replay (Java diff-server required)"
    echo "==> Running differential replay over corpus ..."
    (cd "$SCRIPT_DIR" && \
        ENTANGLED_CORPUS_PATH="$ENTANGLED_CORPUS_PATH" \
        ENTANGLED_DIFF_CLASSPATH="$ENTANGLED_DIFF_CLASSPATH" \
        ${ENTANGLED_DIFF_JAVA:+ENTANGLED_DIFF_JAVA="$ENTANGLED_DIFF_JAVA"} \
        $CARGO_NIGHTLY run --bin replay)
    exit $?
fi

# ---------------------------------------------------------------------------
# MODE: check-oracles
# ---------------------------------------------------------------------------
if [[ "$MODE" == "check-oracles" ]]; then
    [[ -n "${ENTANGLED_CORPUS_PATH:-}" ]] || \
        die "ENTANGLED_CORPUS_PATH must be set for check-oracles"
    echo "==> Running Rust-only oracle check over corpus ..."
    (cd "$SCRIPT_DIR" && \
        ENTANGLED_CORPUS_PATH="$ENTANGLED_CORPUS_PATH" \
        $CARGO_NIGHTLY run --bin check_oracles)
    exit $?
fi

# ---------------------------------------------------------------------------
# MODE: inspect
# ---------------------------------------------------------------------------
if [[ "$MODE" == "inspect" ]]; then
    FILE="${1:-}"
    [[ -n "$FILE" ]] || die "inspect requires a file argument"
    [[ -n "${ENTANGLED_CORPUS_PATH:-}" ]] || \
        die "ENTANGLED_CORPUS_PATH must be set for inspect"
    [[ -n "${ENTANGLED_DIFF_CLASSPATH:-}" ]] || \
        die "ENTANGLED_DIFF_CLASSPATH must be set for inspect (Java diff-server required)"
    echo "==> Inspecting: $FILE"
    (cd "$SCRIPT_DIR" && \
        ENTANGLED_CORPUS_PATH="$ENTANGLED_CORPUS_PATH" \
        ENTANGLED_DIFF_CLASSPATH="$ENTANGLED_DIFF_CLASSPATH" \
        ${ENTANGLED_DIFF_JAVA:+ENTANGLED_DIFF_JAVA="$ENTANGLED_DIFF_JAVA"} \
        $CARGO_NIGHTLY run --bin inspect -- "$FILE")
    exit $?
fi

# ---------------------------------------------------------------------------
# MODE: run
# ---------------------------------------------------------------------------

# Default target.
TARGET="oracles"
DURATION=""
JOBS=1
MAX_LEN=70000
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        oracles|differential)
            TARGET="$1"; shift ;;
        -d|--duration)
            DURATION="${2:?--duration requires a value}"; shift 2 ;;
        -j|--jobs)
            JOBS="${2:?--jobs requires a value}"; shift 2 ;;
        -m|--max-len)
            MAX_LEN="${2:?--max-len requires a value}"; shift 2 ;;
        --)
            shift; EXTRA_ARGS+=("$@"); break ;;
        -*)
            die "unknown option '$1'; use -- to pass flags directly to libFuzzer" ;;
        *)
            die "unexpected argument '$1'" ;;
    esac
done

# Validate env for targets that need the corpus.
[[ -n "${ENTANGLED_CORPUS_PATH:-}" ]] || \
    die "ENTANGLED_CORPUS_PATH must be set (the harness needs the submit body vector)"

if [[ "$TARGET" == "differential" ]]; then
    [[ -n "${ENTANGLED_DIFF_CLASSPATH:-}" ]] || \
        die "ENTANGLED_DIFF_CLASSPATH must be set for the differential target"
fi

# Build libFuzzer args.
LIBFUZZER_ARGS=("-max_len=$MAX_LEN")
[[ -n "$DURATION" ]] && LIBFUZZER_ARGS+=("-max_total_time=$DURATION")
LIBFUZZER_ARGS+=("${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}")

# Assemble env forwarding (only export vars that are set).
ENV_FORWARD=()
ENV_FORWARD+=("ENTANGLED_CORPUS_PATH=$ENTANGLED_CORPUS_PATH")
[[ -n "${ENTANGLED_DIFF_CLASSPATH:-}" ]] && \
    ENV_FORWARD+=("ENTANGLED_DIFF_CLASSPATH=$ENTANGLED_DIFF_CLASSPATH")
[[ -n "${ENTANGLED_DIFF_JAVA:-}" ]] && \
    ENV_FORWARD+=("ENTANGLED_DIFF_JAVA=$ENTANGLED_DIFF_JAVA")
[[ -n "${ENTANGLED_DIFF_LOG:-}" ]] && \
    ENV_FORWARD+=("ENTANGLED_DIFF_LOG=$ENTANGLED_DIFF_LOG")

echo "==> Target  : $TARGET"
echo "==> Jobs    : $JOBS"
echo "==> Max len : $MAX_LEN bytes"
[[ -n "$DURATION" ]] && echo "==> Duration: ${DURATION}s"
[[ "$TARGET" == "differential" && -n "${ENTANGLED_DIFF_LOG:-}" ]] && \
    echo "==> Mode    : discovery (log -> $ENTANGLED_DIFF_LOG)"
echo ""

# cargo-fuzz wants to run from the fuzz crate directory.
cd "$SCRIPT_DIR"

env "${ENV_FORWARD[@]}" \
    $CARGO_NIGHTLY fuzz run "$TARGET" \
    -- \
    "-jobs=$JOBS" \
    "${LIBFUZZER_ARGS[@]}"
