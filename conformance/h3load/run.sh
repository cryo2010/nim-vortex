#!/bin/sh
# HTTP/3 (QUIC) throughput/stress test with nghttp2's h2load built for HTTP/3.
# Builds a vortex HTTP/3 server image and an h2load-http3 client image, starts
# the server, and drives many concurrent QUIC connections and streams at it,
# printing the achieved req/s and failing if any request does not complete 2xx.
#
# This uses a real QUIC client stack (ngtcp2 + nghttp3) -- the same stack the
# server runs -- so the number reflects the server --
# the HTTP/3 throughput/regression measurement.
#
# Usage:  sh conformance/h3load/run.sh        (or `nimble h3load`)
# Needs: docker.
#
# Env knobs: H3LOAD_REQUESTS (default 100000), H3LOAD_CONNS (default 32),
#            H3LOAD_STREAMS (max concurrent streams per connection, default 32).
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)
net=vortex-h3load
srvc=vortex-h3load-server
simg=vortex-h3load-server-img
cimg=vortex-h3load-client-img
reqs=${H3LOAD_REQUESTS:-100000}
conns=${H3LOAD_CONNS:-32}
streams=${H3LOAD_STREAMS:-32}

if [ "$(uname -m)" = "x86_64" ]; then
  basearg="--build-arg BASE=archlinux:latest"
else
  basearg=""
fi

echo "building ngtcp2/nghttp3 deps image (if missing)..."
docker image inspect vortex-ngtcp2-deps >/dev/null 2>&1 || \
  docker build -f "$here/deps.Dockerfile" -t vortex-ngtcp2-deps $basearg "$root"
echo "building HTTP/3 server image..."
docker build -f "$here/Dockerfile" -t "$simg" "$root"
echo "building h2load-http3 client image (builds the QUIC stack from source)..."
docker build -f "$here/client.Dockerfile" -t "$cimg" $basearg "$here"

cleanup() {
  docker rm -f "$srvc" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker network create "$net" >/dev/null 2>&1 || true
docker rm -f "$srvc" >/dev/null 2>&1 || true
docker run -d --name "$srvc" --network "$net" --network-alias server "$simg" \
  >/dev/null

# start() binds before returning, so the "listening" log line means ready.
i=0
until docker logs "$srvc" 2>&1 | grep -q "listening"; do
  i=$((i + 1))
  [ "$i" -gt 100 ] && { echo "server did not start" >&2; docker logs "$srvc"; exit 1; }
  sleep 0.1
done
echo "vortex HTTP/3 server up on the docker network"

echo "=== h2load HTTP/3: $reqs requests, $conns connections, up to $streams streams/conn ==="
out=$(docker run --rm --network "$net" "$cimg" \
      h2load --npn-list=h3 -n "$reqs" -c "$conns" -m "$streams" \
             https://server:4433/ 2>&1)
echo "$out" | grep -E "requests:|status codes:|finished in|req/s|traffic:" || true

if echo "$out" | grep -qE "[1-9][0-9]* (failed|errored|timeout)"; then
  echo "RESULT: h3load had failed/errored/timed-out requests." >&2
  docker logs "$srvc" | tail -20 >&2
  exit 1
fi
if echo "$out" | grep "status codes:" | grep -qE "[1-9][0-9]* (1xx|3xx|4xx|5xx)"; then
  echo "RESULT: h3load saw non-2xx responses." >&2
  exit 1
fi

echo
echo "RESULT: h3load passed ($reqs requests x $conns connections over HTTP/3, all 2xx)."
