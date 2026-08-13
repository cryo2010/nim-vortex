#!/bin/sh
# Phase-3 milestone check for the ngtcp2/nghttp3 backend: builds the standalone
# smoke server (src/vortex/http3/ngtcp2/smoke_server.nim, which drives the
# vq_ngtcp2 shim directly over a UDP socket and answers a fixed 200) and drives
# it with the real ngtcp2/nghttp3 h2load HTTP/3 client. Proves the shim
# handshakes and serves HTTP/3 in isolation from vortex's event loop.
#
# Usage:  sh conformance/h3load/ngtcp2_smoke.sh
# Needs: docker.  Env: N (requests), C (conns), M (streams/conn).
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)
deps=vortex-ngtcp2-deps
cimg=vortex-h3load-client-img
net=vortex-ngtcp2-smoke
srv=vortex-ngtcp2-smoke-srv
n=${N:-200}; c=${C:-4}; m=${M:-8}

if [ "$(uname -m)" = "x86_64" ]; then basearg="--build-arg BASE=archlinux:latest"; else basearg=""; fi

docker image inspect "$deps" >/dev/null 2>&1 || \
  docker build -f "$here/deps.Dockerfile" -t "$deps" $basearg "$root"
docker image inspect "$cimg" >/dev/null 2>&1 || \
  docker build -f "$here/client.Dockerfile" -t "$cimg" $basearg "$here"

cleanup() { docker rm -f "$srv" >/dev/null 2>&1 || true; docker network rm "$net" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
docker network create "$net" >/dev/null 2>&1 || true
docker rm -f "$srv" >/dev/null 2>&1 || true

docker run -d --name "$srv" --network "$net" --network-alias server \
  -v "$root":/work -w /work/src/vortex/http3/ngtcp2 "$deps" sh -c '
    nim cpp --mm:orc --threads:on -d:release --passC:"-std=c++20" \
      --passL:"-lngtcp2 -lngtcp2_crypto_ossl -lnghttp3 -lssl -lcrypto" \
      --nimcache:/tmp/nc -o:/tmp/smoke_server smoke_server.nim >/tmp/build.log 2>&1 \
      || { echo BUILDFAIL; cat /tmp/build.log; exit 1; }
    cd /tmp
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -keyout key.pem -out cert.pem \
      -subj "/CN=localhost" -addext "subjectAltName=DNS:server,DNS:localhost" >/dev/null 2>&1
    exec /tmp/smoke_server
  ' >/dev/null

i=0
until docker logs "$srv" 2>&1 | grep -q "listening"; do
  i=$((i + 1)); [ "$i" -gt 600 ] && { echo "server did not start" >&2; docker logs "$srv"; exit 1; }
  sleep 0.1
done
echo "ngtcp2 smoke server up"

echo "=== h2load HTTP/3: $n requests, $c connections, up to $m streams/conn ==="
out=$(docker run --rm --network "$net" "$cimg" \
      h2load --npn-list=h3 -n "$n" -c "$c" -m "$m" https://server:4433/ 2>&1)
echo "$out" | grep -E "Application protocol|requests:|status codes:|finished in|req/s" || true

if echo "$out" | grep -qE "[1-9][0-9]* (failed|errored|timeout)"; then
  echo "RESULT: ngtcp2 smoke had failed/errored/timed-out requests." >&2; exit 1
fi
if echo "$out" | grep "status codes:" | grep -qvE " $n 2xx,"; then
  echo "RESULT: ngtcp2 smoke saw non-2xx responses." >&2; exit 1
fi
echo
echo "RESULT: ngtcp2/nghttp3 shim smoke passed ($n requests, all 2xx over HTTP/3)."
