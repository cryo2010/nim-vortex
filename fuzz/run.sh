#!/bin/sh
# Build and run the libFuzzer harnesses over the untrusted-input decoders.
#
# Requires clang with the libFuzzer runtime: Linux clang, or Homebrew LLVM
# on macOS (Apple clang does not ship libclang_rt.fuzzer). Easiest is the
# Arch container (bench/Dockerfile) with `pacman -S clang compiler-rt`.
#
#   DUR=60 fuzz/run.sh              # 60s per target (default 30)
#   fuzz/run.sh hpack              # a single target
#
# ASAN needs -d:useMalloc so it sees Nim's allocations; checks stay on so
# logic errors surface as crashes rather than being optimized away.
set -e
DUR="${DUR:-30}"
CLANG="${CLANG:-clang}"
targets="${*:-http1 hpack qpack}"

for t in $targets; do
  echo "== building fuzz_$t =="
  nim c --cc:clang --clang.exe:"$CLANG" --clang.linkerexe:"$CLANG" \
    --noMain:on --mm:orc -d:useMalloc --opt:speed \
    --boundChecks:on --overflowChecks:on \
    --passC:-fsanitize=fuzzer,address --passL:-fsanitize=fuzzer,address \
    -o:"fuzz/fuzz_$t" "fuzz/fuzz_$t.nim"
  mkdir -p "fuzz/corpus/$t"
  echo "== fuzzing $t for ${DUR}s =="
  "./fuzz/fuzz_$t" -max_total_time="$DUR" -print_final_stats=1 \
    "fuzz/corpus/$t" "fuzz/seeds/$t"
done
