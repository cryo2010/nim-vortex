#!/usr/bin/env bash
# Build the scenario harness for one matrix cell and run it under a memory/race
# tool. Driven by env: TOOL (valgrind|helgrind|tsan), SCENARIO, TARGET
# (sync|async|chronos), MM (orc|arc). Used by the CI matrix in ci.yml; runnable
# locally too (tsan needs clang; valgrind/helgrind need valgrind installed).
set -euo pipefail

TOOL=${TOOL:?set TOOL}
SCENARIO=${SCENARIO:?set SCENARIO}
TARGET=${TARGET:?set TARGET}
MM=${MM:-orc}

cd "$(dirname "$0")/../.."         # repo root
SUPP_DIR=conformance/memcheck

# Compressed scenarios need a codec linked; uncompressed ones deliberately build
# without one (so the no-codec path is exercised too).
CODEC=""
case "$SCENARIO" in
  http1c|http2c|streamdownc) CODEC="-d:httpGzip --passL:-lz" ;;
esac

# -d:plainHttp: no OpenSSL (tool-friendly). -d:useMalloc: let the tool see the
# heap. --debugger:native: real symbols/line numbers in tool reports.
BASE="-p:src -d:plainHttp --mm:$MM --threads:on -d:backend=$TARGET"
BASE="$BASE -d:useMalloc --debugger:native --hints:off $CODEC"
BIN="/tmp/harness_${TOOL}_${SCENARIO}_${TARGET}_${MM}"

echo "== build: TOOL=$TOOL SCENARIO=$SCENARIO TARGET=$TARGET MM=$MM =="
case "$TOOL" in
  tsan)
    nim c $BASE --passC:-fsanitize=thread --passL:-fsanitize=thread \
      -o:"$BIN" "$SUPP_DIR/harness.nim"
    ;;
  valgrind|helgrind)
    nim c $BASE -o:"$BIN" "$SUPP_DIR/harness.nim"
    ;;
  *) echo "unknown TOOL: $TOOL" >&2; exit 2 ;;
esac

export SCENARIO
echo "== run under $TOOL =="
case "$TOOL" in
  valgrind)
    # Fail on real memory errors (invalid access, uninitialised reads) and on
    # `definitely lost` leaks. `indirectly lost` is not an error kind: those are
    # children of a root, and our only roots-at-exit are process-lifetime async
    # runtime globals (suppressed below). --gen-suppressions prints exact
    # suppression text in the log if a new benign global appears.
    # --track-fds catches fd leaks (open at exit) + double-close, but the curl
    # driven http2 scenarios spawn curl via osproc, whose pipe reaping double-
    # closes fds (std-lib, unsuppressible in this valgrind); the harness's
    # /proc/self/fd growth check still covers fd leaks there, so skip it for them.
    FDFLAG="--track-fds=yes"
    case "$SCENARIO" in http2|http2c) FDFLAG="" ;; esac
    REPS=${REPS:-25} valgrind --tool=memcheck --error-exitcode=1 \
      --leak-check=full --errors-for-leak-kinds=definite \
      --show-leak-kinds=definite --track-origins=yes $FDFLAG \
      --gen-suppressions=all --suppressions="$SUPP_DIR/nim.supp" "$BIN"
    ;;
  helgrind)
    REPS=${REPS:-12} valgrind --tool=helgrind --error-exitcode=1 \
      --suppressions="$SUPP_DIR/helgrind.supp" "$BIN"
    ;;
  tsan)
    REPS=${REPS:-40} TSAN_OPTIONS="halt_on_error=1:abort_on_error=1" "$BIN"
    ;;
esac
