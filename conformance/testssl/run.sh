#!/bin/sh
# TLS configuration scan with testssl.sh: check vortex's OpenSSL-backed TLS for
# weak protocol versions, weak ciphers, and known vulnerabilities. Runs the
# protocol (-p), cipher (-s) and vulnerability (-U) groups -- not the cert-trust
# group, since the test cert is a throwaway self-signed one. Fails on any
# HIGH/CRITICAL finding.
#
# Usage:  sh conformance/testssl/run.sh        (or `nimble testssl`)
# Needs: docker.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)
net=vortex-testssl
srvc=vortex-testssl-server
img=vortex-testssl-server-img
timg=${TESTSSL_IMAGE:-drwetter/testssl.sh:latest}
port=8443

if [ "$(uname -m)" = "x86_64" ]; then
  basearg="--build-arg BASE=archlinux:latest"
else
  basearg=""
fi

echo "building vortex TLS server image..."
docker build -f "$here/Dockerfile" -t "$img" $basearg "$root"
echo "pulling testssl.sh image ($timg)..."
docker pull "$timg"

out=$(mktemp -d)
chmod 777 "$out"
cleanup() {
  docker rm -f "$srvc" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  rm -rf "$out"
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
echo "vortex TLS server up on the docker network"

echo "running testssl.sh (protocols, ciphers, vulnerabilities)..."
# --severity HIGH: only HIGH/CRITICAL findings land in the JSON, so a non-empty
# findings array is the gate. testssl.sh's own exit code is not severity-based.
docker run --rm --network "$net" -v "$out:/out" "$timg" \
  --color 0 --quiet --severity HIGH --jsonfile /out/r.json \
  -p -s -U "server:$port" || true

if [ ! -s "$out/r.json" ]; then
  echo "RESULT: testssl produced no report." >&2
  exit 1
fi

if grep -qE '"severity"[[:space:]]*:[[:space:]]*"(HIGH|CRITICAL)"' "$out/r.json"; then
  echo
  echo "RESULT: testssl found HIGH/CRITICAL issues:" >&2
  grep -E '"(id|severity|finding)"' "$out/r.json" >&2
  exit 1
fi

echo
echo "RESULT: testssl passed (no HIGH/CRITICAL protocol, cipher, or vuln findings)."
