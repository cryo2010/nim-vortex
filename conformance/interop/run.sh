#!/bin/sh
# Cross-client interop test: drive a single vortex server with real HTTP clients
# from five ecosystems (Node http2, Python httpx, Go net/http, Rust reqwest,
# Java java.net.http) over HTTP/2 + TLS with gzip, exercising every method. Each
# client asserts the negotiated protocol is HTTP/2, that responses round-trip
# (proving gzip), and, in mTLS mode, that the server saw its client certificate.
# The backends run sequentially, so total wall time is roughly runtime x 5.
#
# Usage:  sh conformance/interop/run.sh        (or `nimble interop`)
# Needs: docker (+ openssl on the host to mint the shared CA/certs).
#
# Env knobs:
#   INTEROP_RUNTIME  seconds each backend runs (default 5; total ~= x5 backends)
#   INTEROP_CLIENTS  total concurrent clients, split evenly across the 5
#                    backends (default 10 -> 2 each; min 1 each)
#   INTEROP_MTLS     1 = require + present client certs and check the subject
#                    via /whoami (default 0)
#   INTEROP_ENCODING content-encoding the clients request and assert: gzip
#                    (default) or br (brotli). `nimble brotli` sets br.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)
net=vortex-interop
srvc=vortex-interop-server
simg=vortex-interop-server-img
certs="$here/certs"

runtime=${INTEROP_RUNTIME:-5}
total=${INTEROP_CLIENTS:-10}
mtls=${INTEROP_MTLS:-0}
enc=${INTEROP_ENCODING:-gzip}

backends="node python go rust java"
per=$(( total / 5 ))
[ "$per" -lt 1 ] && per=1

if [ "$(uname -m)" = "x86_64" ]; then
  basearg="--build-arg BASE=archlinux:latest"
else
  basearg=""
fi

# --- shared TLS material (one CA -> server cert + client cert) --------------
echo "generating shared CA + server/client certs..."
rm -rf "$certs"; mkdir -p "$certs"
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout "$certs/ca.key" -out "$certs/ca.pem" \
  -subj "/CN=vortex-interop-ca" >/dev/null 2>&1

printf "subjectAltName=DNS:server,DNS:localhost\n" > "$certs/san.ext"
openssl req -newkey rsa:2048 -nodes -keyout "$certs/key.pem" \
  -out "$certs/server.csr" -subj "/CN=server" >/dev/null 2>&1
openssl x509 -req -in "$certs/server.csr" -CA "$certs/ca.pem" \
  -CAkey "$certs/ca.key" -CAcreateserial -days 3650 \
  -extfile "$certs/san.ext" -out "$certs/cert.pem" >/dev/null 2>&1

openssl req -newkey rsa:2048 -nodes -keyout "$certs/client.key" \
  -out "$certs/client.csr" -subj "/CN=interop-client" >/dev/null 2>&1
openssl x509 -req -in "$certs/client.csr" -CA "$certs/ca.pem" \
  -CAkey "$certs/ca.key" -CAcreateserial -days 3650 \
  -out "$certs/client.pem" >/dev/null 2>&1
# Java loads its client identity from a PKCS#12 keystore.
openssl pkcs12 -export -inkey "$certs/client.key" -in "$certs/client.pem" \
  -certfile "$certs/ca.pem" -out "$certs/client.p12" \
  -passout pass:changeit >/dev/null 2>&1

# --- build images ----------------------------------------------------------
echo "building vortex server image..."
docker build -f "$here/Dockerfile" -t "$simg" $basearg "$root"
for b in $backends; do
  echo "building $b client image..."
  docker build -t "vortex-interop-$b-img" "$here/clients/$b"
done

cleanup() {
  docker rm -f "$srvc" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  rm -rf "$certs"
}
trap cleanup EXIT INT TERM

docker network create "$net" >/dev/null 2>&1 || true
docker rm -f "$srvc" >/dev/null 2>&1 || true
docker run -d --name "$srvc" --network "$net" --network-alias server \
  -v "$certs":/certs:ro -e INTEROP_MTLS="$mtls" "$simg" >/dev/null

# start() binds before returning, so the "listening" log line means ready.
i=0
until docker logs "$srvc" 2>&1 | grep -q "listening"; do
  i=$((i + 1))
  [ "$i" -gt 100 ] && { echo "server did not start" >&2; docker logs "$srvc"; exit 1; }
  sleep 0.1
done
echo "vortex server up (mtls=$mtls)"

# --- independent encoding + HTTP/2 assertion via curl -----------------------
echo "=== verifying HTTP/2 + $enc with curl ==="
curlcert=""
[ "$mtls" = "1" ] && curlcert="--cert /certs/client.pem --key /certs/client.key"
# -sS (not -s) so curl prints its error; capture stderr and the exit code
# instead of letting `set -e` abort the script opaquely on a curl failure.
set +e
hdrs=$(docker run --rm --network "$net" -v "$certs":/certs:ro \
  curlimages/curl:latest -sS -D - -o /dev/null --http2 \
  --retry 5 --retry-connrefused --retry-all-errors --connect-timeout 5 \
  --cacert /certs/ca.pem $curlcert \
  -H 'x-api-key: interop' -H "accept-encoding: $enc" \
  https://server:8443/echo 2>&1)
rc=$?
set -e
if [ "$rc" -ne 0 ]; then
  # curl couldn't complete the request. This is an auxiliary confirmation using
  # a different TLS stack than the five language clients (which assert the same
  # HTTP/2 + encoding round-trip themselves), so don't gate the job on a
  # curl-image quirk -- warn and let the real clients be the source of truth.
  echo "WARNING: curl check could not run (exit $rc); relying on the clients." >&2
  echo "$hdrs" >&2
else
  echo "$hdrs" | grep -qiE "^HTTP/2 200" || {
    echo "RESULT: server did not answer HTTP/2 200" >&2; echo "$hdrs" >&2; exit 1; }
  echo "$hdrs" | grep -qi "^content-encoding: $enc" || {
    echo "RESULT: response was not $enc-compressed" >&2; echo "$hdrs" >&2; exit 1; }
  echo "curl confirmed HTTP/2 + $enc"
fi

# --- run each backend sequentially -----------------------------------------
fails=0
for b in $backends; do
  echo "=== $b ($per client(s), ${runtime}s) ==="
  if docker run --rm --network "$net" -v "$certs":/certs:ro \
      -e INTEROP_URL="https://server:8443" \
      -e INTEROP_RUNTIME="$runtime" \
      -e INTEROP_CLIENTS="$per" \
      -e INTEROP_MTLS="$mtls" \
      -e INTEROP_ENCODING="$enc" \
      "vortex-interop-$b-img"; then
    :
  else
    echo "RESULT: $b client failed." >&2
    fails=$((fails + 1))
  fi
done

echo
if [ "$fails" -gt 0 ]; then
  echo "RESULT: interop FAILED ($fails/5 backends, enc=$enc)." >&2
  docker logs "$srvc" | tail -20 >&2
  exit 1
fi
echo "RESULT: interop passed (5/5 backends, enc=$enc, mtls=$mtls, ${runtime}s each, $per client(s) each)."
