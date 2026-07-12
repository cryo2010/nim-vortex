#!/bin/sh
# HTTP/1.1 conformance via h1spec (dropseed/h1spec).
#
# Builds a vortex HTTP/1.1 server image and an h1spec client image, runs the
# server, and runs h1spec against it over a private docker network. h1spec
# exits non-zero on any failing case, which fails this script.
#
# Usage:  sh conformance/h1spec/run.sh        (or `nimble h1spec`)
# Needs: docker.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)
net=vortex-h1spec
srvc=vortex-h1spec-server
simg=vortex-h1spec-server-img
cimg=vortex-h1spec-client-img

if [ "$(uname -m)" = "x86_64" ]; then
  basearg="--build-arg BASE=archlinux:latest"
else
  basearg=""
fi

echo "building HTTP/1.1 server image..."
docker build -f "$here/Dockerfile" -t "$simg" $basearg "$root"
echo "building h1spec client image..."
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
echo "HTTP/1.1 server up on the docker network"

echo "running h1spec..."
if docker run --rm --network "$net" "$cimg"; then
  echo
  echo "RESULT: h1spec passed."
else
  echo
  echo "RESULT: h1spec reported failures." >&2
  docker logs "$srvc" | tail -20 >&2
  exit 1
fi
