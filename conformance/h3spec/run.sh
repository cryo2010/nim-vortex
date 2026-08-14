#!/bin/sh
# HTTP/3 conformance via h3spec (kazu-yamamoto/h3spec).
#
# Builds a vortex HTTP/3 server image and an h3spec client image, runs the
# server, and runs h3spec against it over a private docker network (QUIC is
# UDP). Scoped to the "HTTP/3 servers" group -- the HTTP/3 + QPACK error
# cases that vortex's codec owns. The "QUIC servers" group (RFC 9000
# transport conformance) is OpenSSL's QUIC stack, not vortex, so it is
# excluded. h3spec exits non-zero on any failure, which fails this script.
#
# Usage:  sh conformance/h3spec/run.sh        (or `nimble h3spec`)
# Needs: docker.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)
net=vortex-h3spec
srvc=vortex-h3spec-server
simg=vortex-h3spec-server-img
cimg=vortex-h3spec-client-img

if [ "$(uname -m)" = "x86_64" ]; then
  basearg="--build-arg BASE=archlinux:latest"
else
  basearg=""
fi

echo "building ngtcp2/nghttp3 deps image (if missing)..."
docker image inspect vortex-ngtcp2-deps >/dev/null 2>&1 || \
  docker build -f "$root/conformance/h3load/deps.Dockerfile" -t vortex-ngtcp2-deps $basearg "$root"
echo "building HTTP/3 server image..."
docker build -f "$here/Dockerfile" -t "$simg" "$root"
echo "building h3spec client image..."
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
echo "HTTP/3 server up on the docker network"

echo "running h3spec (HTTP/3 servers group)..."
if docker run --rm --network "$net" "$cimg"; then
  echo
  echo "RESULT: h3spec passed (HTTP/3 servers group)."
else
  echo
  echo "RESULT: h3spec reported failures." >&2
  docker logs "$srvc" | tail -20 >&2
  exit 1
fi
