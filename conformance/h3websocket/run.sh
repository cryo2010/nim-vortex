#!/bin/sh
# HTTP/3 WebSocket conformance (RFC 9220) via an aioquic client.
#
# Builds a vortex HTTP/3 WebSocket echo server image and an aioquic client
# image, runs the server, and runs the client against it over a private
# docker network (QUIC is UDP). The client exits non-zero on any mismatch,
# which fails this script.
#
# Usage:  sh conformance/h3websocket/run.sh        (or `nimble h3websocket`)
# Needs: docker.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)
net=vortex-h3ws
srvc=vortex-h3ws-server
simg=vortex-h3ws-server-img
cimg=vortex-h3ws-client-img

if [ "$(uname -m)" = "x86_64" ]; then
  basearg="--build-arg BASE=archlinux:latest"
else
  basearg=""
fi

echo "building HTTP/3 WebSocket server image..."
docker build -f "$here/Dockerfile" -t "$simg" $basearg "$root"
echo "building aioquic client image..."
docker build -f "$here/client.Dockerfile" -t "$cimg" "$root"

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
echo "HTTP/3 WebSocket server up on the docker network"

echo "running aioquic conformance client..."
if docker run --rm --network "$net" "$cimg"; then
  echo
  echo "RESULT: HTTP/3 WebSocket conformance passed."
else
  echo
  echo "RESULT: HTTP/3 WebSocket conformance FAILED." >&2
  docker logs "$srvc" | tail -20 >&2
  exit 1
fi
