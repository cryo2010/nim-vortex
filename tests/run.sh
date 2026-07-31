#!/usr/bin/env bash
# Run the vortex default test suite directly, WITHOUT `nimble test`.
#
# nimble does not propagate a task's exit code (nim-lang/nimble#1802): a failing
# test still makes `nimble test` exit 0, so CI reports green on red. Running
# `nim c -r` per suite here, under `set -e`, propagates the first failure so CI
# actually fails.
#
# Build knobs are read by tests/config.nims from the environment:
#   NIM_MM=orc|arc     memory manager (default orc)
#   NIM_SANITIZE=1     build under AddressSanitizer + UBSan
#   NIM_COMPRESS=1     enable gzip/brotli/zstd (so those tests run, not skip)
set -euo pipefail

cd "$(dirname "$0")/.."   # repo root, so tests/config.nims resolves the src path

# Discover suites so the list never drifts as tests are added. nullglob makes a
# no-match expand to nothing (not the literal pattern); we then fail if empty so
# a broken glob can't pass CI with zero suites run. The glob is sorted, so the
# order is deterministic (suites are independent).
shopt -s nullglob
suites=(tests/test_*.nim)
shopt -u nullglob
if [ ${#suites[@]} -eq 0 ]; then
  echo "error: no test suites found (tests/test_*.nim)" >&2
  exit 1
fi

for f in "${suites[@]}"; do
  echo "== $(basename "$f" .nim) =="
  nim c -r --hints:off "$f"
done
