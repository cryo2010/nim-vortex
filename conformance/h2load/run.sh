#!/bin/sh
# Stress smoke with nghttp2's h2load: fire many concurrent HTTP/1.1 and HTTP/2
# (h2c prior-knowledge) requests at a vortex server and fail if any request
# does not complete with a 2xx. This is not a benchmark (CI numbers are noisy)
# -- it stress-tests the event loop, connection lifecycle, and concurrency and
# catches hangs, dropped requests, or crashes under load.
#
# Usage:  sh conformance/h2load/run.sh        (or `nimble h2load`)
# Needs: docker.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)
net=vortex-h2load
srvc=vortex-h2load-server
simg=vortex-h2load-server-img
cimg=vortex-h2load-client-img
reqs=${H2LOAD_REQUESTS:-50000}
conns=${H2LOAD_CONNS:-50}

if [ "$(uname -m)" = "x86_64" ]; then
  basearg="--build-arg BASE=archlinux:latest"
else
  basearg=""
fi

echo "building vortex server image..."
docker build -f "$here/Dockerfile" -t "$simg" $basearg "$root"
echo "building h2load client image..."
docker build -f "$here/client.Dockerfile" -t "$cimg" "$here"

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
echo "vortex server up on the docker network"

# Run one h2load invocation and fail on any non-2xx / failed / errored / timeout.
run_load() {
  desc="$1"; shift
  echo "=== $desc ==="
  out=$(docker run --rm --network "$net" "$cimg" \
        h2load "$@" -n "$reqs" -c "$conns" http://server:8080/ 2>&1)
  echo "$out" | grep -E "requests:|status codes:|finished in" || true
  if echo "$out" | grep -qE "[1-9][0-9]* (failed|errored|timeout)"; then
    echo "RESULT: $desc had failed/errored/timed-out requests." >&2
    docker logs "$srvc" | tail -20 >&2
    exit 1
  fi
  if echo "$out" | grep "status codes:" | grep -qE "[1-9][0-9]* (1xx|3xx|4xx|5xx)"; then
    echo "RESULT: $desc saw non-2xx responses." >&2
    exit 1
  fi
}

run_load "HTTP/2 (h2c prior knowledge)" -m 20
run_load "HTTP/1.1" --h1

echo
echo "RESULT: h2load passed ($reqs requests x $conns connections, all 2xx)."
