#!/bin/sh
# HTTP/2 protocol conformance via h2spec, over TLS.
#
# Builds a vortex HTTP/2-over-TLS server image, runs it, and runs the
# summerwind/h2spec image against it over a private docker network. h2spec
# exits non-zero when any test fails, which fails this script.
#
# Usage:  sh conformance/h2spec/run.sh        (or `nimble h2spec`)
# Needs: docker.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)
net=vortex-h2spec
srvc=vortex-h2spec-server
img=vortex-h2spec-server-img
port=8443

if [ "$(uname -m)" = "x86_64" ]; then
  basearg="--build-arg BASE=archlinux:latest"
else
  basearg=""
fi

echo "building HTTP/2 server image..."
docker build -f "$here/Dockerfile" -t "$img" $basearg "$root"

cleanup() {
  docker rm -f "$srvc" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker network create "$net" >/dev/null 2>&1 || true
docker rm -f "$srvc" >/dev/null 2>&1 || true
docker run -d --name "$srvc" --network "$net" --network-alias server "$img" \
  >/dev/null

# start() binds before returning, so the "listening" log line means ready.
i=0
until docker logs "$srvc" 2>&1 | grep -q "listening"; do
  i=$((i + 1))
  [ "$i" -gt 100 ] && { echo "server did not start" >&2; docker logs "$srvc"; exit 1; }
  sleep 0.1
done
echo "HTTP/2 server up on the docker network"

echo "running h2spec over TLS..."
if docker run --rm --network "$net" summerwind/h2spec \
     -t -k -h server -p "$port"; then
  echo
  echo "RESULT: h2spec passed (0 failed)."
else
  echo
  echo "RESULT: h2spec reported failures." >&2
  exit 1
fi
