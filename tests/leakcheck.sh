#!/usr/bin/env bash
# Leak gate for the async adapters' per-loop-thread state (#422): build the
# shared adapter suite (tests/test_adapter.nim) against each backend, run it
# under a leak checker, and fail if any leaked allocation was made by a
# dispatcher (chronos's or asyncdispatch's newDispatcher) or by the adapter's
# thread-local reader tables. Those are what a loop thread's teardown must
# release; each leaked once per loop thread that used the adapter.
#
#   macOS: `leaks --atExit --list` over a -d:useMalloc build (so Nim's heap is
#          malloc's and visible to it), with MallocStackLogging for the stacks.
#   Linux: LeakSanitizer over the ASan build tests/config.nims makes under
#          NIM_SANITIZE=1 (which also implies -d:useMalloc).
#
# Other leaks the suite reports (the test's own SSL_CTX, a few exception
# objects raised by its handlers, the detached tasks its #423 cases let fail)
# are counted in the summary line printed and kept in the log, but do not fail
# the gate. A suite that did not run to its end fails it: on macOS judged by its
# final success line (leaks reports on any exit and does not pass the suite's
# exit status on), on Linux by the suite's exit status.
# Usage: tests/leakcheck.sh [asyncdispatch] [chronos] [strict]
# (default: asyncdispatch chronos; chronos and strict need chronos installed).
set -euo pipefail

cd "$(dirname "$0")/.."   # repo root, so tests/config.nims resolves the src path

backends=("$@")
if [ ${#backends[@]} -eq 0 ]; then backends=(asyncdispatch chronos); fi

# A leaked block counts against the gate when its allocation stack goes through
# a dispatcher constructor or a table store made by vortex's adapter modules.
# Every leaked block is checked, not only the roots: a dispatcher still reachable
# from some other leaked object (a closure, a future) is a child in the leak
# tree, and its tree label (`<malloc in allocImpl>`) says nothing about where
# it came from, so `leaks --list` is asked for each block's own stack. LSan
# already gives every direct and indirect leak its own stack.
pattern='newDispatcher|X5BX5Deq___OOZsrcZvortexZadapters'

case "$(uname -s)" in
  Darwin)
    command -v leaks >/dev/null || { echo "error: /usr/bin/leaks not found" >&2; exit 1; }
    mode=leaks ;;
  Linux) mode=lsan ;;
  *) echo "error: no leak checker for $(uname -s)" >&2; exit 1 ;;
esac

fail=0
for b in "${backends[@]}"; do
  case "$b" in
    asyncdispatch) flags=() ;;
    chronos) flags=(-d:vortexChronos) ;;
    strict) flags=(-d:vortexChronos -d:chronosStrictReentrancy=true) ;;
    *) echo "error: unknown backend $b" >&2; exit 1 ;;
  esac
  bin="tests/test_adapter_leak_$b"
  log="nimcache/leakcheck_$b.log"
  mkdir -p nimcache
  echo "== leakcheck: $b ($mode) =="
  if [ "$mode" = leaks ]; then
    nim c --hints:off -d:useMalloc ${flags[@]+"${flags[@]}"} \
      --nimcache:"nimcache/leakcheck_$b" -o:"$bin" tests/test_adapter.nim
    # leaks exits 1 whenever it finds any leak; the verdict is ours, below.
    MallocStackLogging=1 leaks --atExit --list -- "./$bin" >"$log" 2>&1 || true
    if grep -q '\[FAILED\]' "$log"; then
      grep -B3 '\[FAILED\]' "$log"; echo "FAIL: $b: the suite failed"; fail=1; continue
    fi
    # leaks reports on any exit, so a suite cut short (a module-level exception,
    # a crash) still yields a report, over a partial run. The suite's last line
    # proves it ran to the end; leaks does not pass the suite's exit status on.
    if grep -qE '^Error: unhandled exception|^SIGSEGV|^SIGBUS' "$log" ||
       ! grep -qx 'server shut down cleanly' "$log"; then
      tail -40 "$log"; echo "FAIL: $b: the suite did not run to completion"; fail=1; continue
    fi
    grep -E '^Process [0-9]+: [0-9]+ leaks? for' "$log" || {
      cat "$log"; echo "FAIL: $b: no leaks report"; fail=1; continue; }
    # One "Leak:" line and its "Call stack:" per leaked block; keep the blocks
    # whose stack matches the pattern.
    hits=$(awk -v pat="$pattern" '
      /^Leak: / { if (blk != "" && blk ~ pat) { n++; out = out blk "\n" } blk = ""; inblk = 1 }
      /^$/ { if (blk != "" && blk ~ pat) { n++; out = out blk "\n" } blk = ""; inblk = 0 }
      inblk { blk = blk $0 "\n" }
      END { if (blk ~ pat) { n++; out = out blk }
            if (n > 0) printf "%d\n%s", n, out }' "$log")
  else
    # LSan reports at exit and would turn any leak into a failing exit code;
    # exitcode=0 hands the verdict to the filter below instead.
    NIM_SANITIZE=1 nim c --hints:off ${flags[@]+"${flags[@]}"} \
      --nimcache:"nimcache/leakcheck_$b" -o:"$bin" tests/test_adapter.nim
    status=0
    ASAN_OPTIONS="detect_leaks=1:detect_container_overflow=0" \
      LSAN_OPTIONS="exitcode=0" "./$bin" >"$log" 2>&1 || status=$?
    if [ "$status" -ne 0 ]; then
      tail -40 "$log"; echo "FAIL: $b: the suite exited $status"; fail=1; continue
    fi
    grep -E '^SUMMARY: AddressSanitizer: [0-9]+ byte' "$log" ||
      echo "(no leaks reported)"
    # One report per "Direct leak"/"Indirect leak" block, ending at a blank line.
    hits=$(awk -v pat="$pattern" '
      /^(Direct|Indirect) leak/ { inblk = 1; blk = "" }
      inblk { blk = blk $0 "\n" }
      inblk && /^$/ { inblk = 0; if (blk ~ pat) { n++; out = out blk } }
      END { if (inblk && blk ~ pat) { n++; out = out blk }
            if (n > 0) printf "%d\n%s", n, out }' "$log")
  fi
  if [ -n "$hits" ]; then
    echo "$hits" | tail -n +2
    echo "FAIL: $b: $(echo "$hits" | head -1) leaked block(s) or report(s) trace to a dispatcher or an adapter table (full report: $log)"
    fail=1
  else
    echo "ok: $b: no dispatcher or adapter-table leaks"
  fi
done
exit $fail
