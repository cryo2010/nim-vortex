#!/bin/sh
# AddressSanitizer/LeakSanitizer memcheck of the ngtcp2/nghttp3 HTTP/3 backend.
# Runs the ngtcp2 h3 server (numThreads=1) built with -fsanitize=address, drives
# it with the real ngtcp2/nghttp3 h2load client, then triggers a graceful
# shutdown (SIGTERM) so LSan reports leaks on clean exit. Fails on any ASan error
# or on a leak attributed to vortex's own code (the C++ shim vq_ngtcp2 or the Nim
# backend); process-lifetime OpenSSL/ngtcp2/nghttp3 library globals are ignored.
#
# ASan (compiled in) is used rather than valgrind: valgrind cannot run on the
# Arch deps image (stripped ld.so), and its ngtcp2 `ossl` backend needs
# OpenSSL >= 3.5, which the Debian base valgrind wants does not ship.
#
# Usage:  sh conformance/memcheck/h3ngtcp2.sh
# Needs: docker.  Env: N (requests), C (conns), M (streams/conn).
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)
deps=vortex-ngtcp2-deps
simg=vortex-h3ng-asan-img
cimg=vortex-h3load-client-img
net=vortex-h3ng-memcheck
srv=vortex-h3ng-memcheck-srv
n=${N:-500}; c=${C:-8}; m=${M:-16}

if [ "$(uname -m)" = "x86_64" ]; then basearg="--build-arg BASE=archlinux:latest"; else basearg=""; fi

docker image inspect "$deps" >/dev/null 2>&1 || \
  docker build -f "$root/conformance/h3load/deps.Dockerfile" -t "$deps" $basearg "$root"
docker image inspect "$cimg" >/dev/null 2>&1 || \
  docker build -f "$root/conformance/h3load/client.Dockerfile" -t "$cimg" $basearg "$root/conformance/h3load"
docker build -f "$here/Dockerfile.h3ngtcp2" -t "$simg" "$root"

cleanup() { docker rm -f "$srv" >/dev/null 2>&1 || true; docker network rm "$net" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
docker network create "$net" >/dev/null 2>&1 || true
docker rm -f "$srv" >/dev/null 2>&1 || true

# halt_on_error=0 so ASan keeps serving; LSan runs at exit. detect_leaks=1 (LSan).
docker run -d --name "$srv" --network "$net" --network-alias server \
  -e ASAN_OPTIONS=halt_on_error=0:detect_leaks=1:exitcode=99 "$simg" >/dev/null

i=0
until docker logs "$srv" 2>&1 | grep -q "listening"; do
  i=$((i + 1)); [ "$i" -gt 600 ] && { echo "server did not start" >&2; docker logs "$srv" | tail; exit 1; }
  sleep 0.2
done
echo "ngtcp2 h3 server up (ASan)"

echo "=== h2load: $n requests, $c connections, $m streams/conn ==="
docker run --rm --network "$net" "$cimg" \
  h2load --npn-list=h3 -n "$n" -c "$c" -m "$m" https://server:4433/ 2>&1 | \
  grep -E "status codes:|requests:" || true

echo "graceful shutdown (LSan reports on clean exit)..."
docker stop -t 30 "$srv" >/dev/null 2>&1 || true
out=$(docker logs "$srv" 2>&1)

echo "=== sanitizer output ==="
echo "$out" | grep -E "ERROR: AddressSanitizer|LeakSanitizer|Direct leak|Indirect leak|SUMMARY" | head -30 || \
  echo "(no ASan/LSan diagnostics -- clean)"

if echo "$out" | grep -qE "ERROR: AddressSanitizer"; then
  echo "RESULT: AddressSanitizer reported a memory error." >&2; exit 1
fi
# Gate leaks only when the stack names vortex's own code.
if echo "$out" | grep -A20 -E "Direct leak|Indirect leak" | grep -qE "vq_ngtcp2|backend\.nim|ngtcp2Zbackend"; then
  echo "RESULT: leak attributed to vortex code:" >&2
  echo "$out" | grep -B2 -A20 -E "Direct leak|Indirect leak" | grep -E "vq_ngtcp2|backend\.nim|ngtcp2Zbackend" | head >&2
  exit 1
fi
echo "RESULT: no ASan errors and no leaks attributed to vortex code (shim/backend clean)."
