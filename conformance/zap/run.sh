#!/bin/sh
# Security scan with the OWASP ZAP baseline (passive) scanner.
#
# Builds a plaintext vortex server image, starts it, and runs ZAP's packaged
# zap-baseline.py against it over a private docker network. The baseline scan
# spiders the site and passively inspects responses; zap.conf promotes the
# security-header rules the app satisfies to FAIL, so a regression that drops a
# header fails this script. -I keeps mere warnings from failing the run.
#
# Usage:  sh conformance/zap/run.sh        (or `nimble zap`)
# Needs: docker.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)
net=vortex-zap
srvc=vortex-zap-server
simg=vortex-zap-server-img
zimg=${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}

if [ "$(uname -m)" = "x86_64" ]; then
  basearg="--build-arg BASE=archlinux:latest"
else
  basearg=""
fi

echo "building vortex target image..."
docker build -f "$here/Dockerfile" -t "$simg" $basearg "$root"
echo "pulling ZAP scanner image ($zimg)..."
docker pull "$zimg"

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
echo "vortex target up on the docker network"

# The rule config lives in $here; mount it read-only at ZAP's work dir. The
# scan exits 0 on a clean/warn-only run (with -I), 1 on any FAIL, 3 on error.
echo "running ZAP baseline scan..."
if docker run --rm --network "$net" -v "$here:/zap/wrk/:ro" "$zimg" \
     zap-baseline.py -t http://server:8080 -c zap.conf -I -m 1; then
  echo
  echo "RESULT: ZAP baseline passed."
else
  echo
  echo "RESULT: ZAP baseline reported failures." >&2
  docker logs "$srvc" | tail -20 >&2
  exit 1
fi
