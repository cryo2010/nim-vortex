#!/bin/sh
# Per-workload stress soak (pass/fail). Builds the vortex server (protocol ×
# server-runtime) and a Python load client, drives ONE workload
# (VORTEX_WORKLOAD) at the server for VORTEX_SECONDS, and verifies it: checksums
# and echoes **hard-fail** (the client's non-zero exit propagates out). Responses
# are discarded, so memory stays flat; the server's CPU/RSS is printed each
# VORTEX_REPORT_SECONDS. Not a CI gate (Docker, long runtimes, big transfers).
#
# Usage:  VORTEX_WORKLOAD=streamdownload sh conformance/stress/run.sh
#         (normally via `nimble stressRequests` / `stressWs` / `stressSse` /
#          `stressStreamUpload` / `stressStreamDownload`, or `nimble stress`)
# Needs: docker.
#
# Env (mirrors nim-navi's NAVI_*):
#   VORTEX_WORKLOAD  requests | ws | sse | streamupload | streamdownload
#   VORTEX_PROTO     h1 | h2 | h3 | all           (default h2; all = h1 h2)
#   VORTEX_SERVER    sync | async | async-await | chronos | chronos-await | all
#   VORTEX_SECONDS / VORTEX_REPORT_SECONDS / VORTEX_CONCURRENCY / VORTEX_CLIENTS
#   VORTEX_REQ_COMPRESSION / VORTEX_RESP_COMPRESSION   none | gzip | br | zstd
#   VORTEX_STREAM_BYTES   streaming transfer size (default 1 GiB)
#   VORTEX_RUN_ID    isolation id for the docker network/container/image names,
#                    so runs can go in parallel (default: this run's PID)
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)

workload=${VORTEX_WORKLOAD:-requests}
proto=${VORTEX_PROTO:-h2}
server=${VORTEX_SERVER:-sync}
seconds=${VORTEX_SECONDS:-60}
report=${VORTEX_REPORT_SECONDS:-60}
conc=${VORTEX_CONCURRENCY:-32}
clients=${VORTEX_CLIENTS:-3}
reqc=${VORTEX_REQ_COMPRESSION:-gzip}
respc=${VORTEX_RESP_COMPRESSION:-gzip}
sbytes=${VORTEX_STREAM_BYTES:-1073741824}

# A per-run id isolates concurrent runs: each gets its own docker network,
# server container, and image tags, so several `run.sh` / `nimble stress`
# invocations can run in parallel without clobbering one another (fixed names
# would share a `vortex-stress-server` container / `...-img` tag / `server`
# alias and sabotage each other). Default to the PID; generated once here --
# before the STRESS_SMOKE self-re-exec (`sh "$0"` per workload) -- and exported
# so every workload of one smoke shares the same id. Set VORTEX_RUN_ID yourself
# to name a run.
id="${VORTEX_RUN_ID:-$$}"
export VORTEX_RUN_ID="$id"

# The `stress` smoke runs every workload, short, and fails on any.
if [ "${STRESS_SMOKE:-0}" = "1" ]; then
  rc=0
  for w in requests ws sse streamupload streamdownload; do
    echo; echo "########## smoke: $w ##########"
    STRESS_SMOKE=0 VORTEX_WORKLOAD="$w" sh "$0" || rc=1
  done
  echo
  [ "$rc" = 0 ] && echo "== stress smoke: all workloads passed ==" \
                || echo "== stress smoke: FAILURES (see above) =="
  exit "$rc"
fi

if [ "$(uname -m)" = "x86_64" ]; then basearg="--build-arg BASE=archlinux:latest"; else basearg=""; fi

net=vortex-stress-$id
srvc=vortex-stress-server-$id
simg=vortex-stress-server-img-$id
cimg=vortex-stress-client-img-$id

docker network create "$net" >/dev/null 2>&1 || true
# Tear down everything this run created -- the network and the per-run image
# tags, not just the server container -- so a per-run id can't leak resources.
# The shared build-cache layers survive (only the tags are removed), so
# rebuilds stay fast. The `server` alias is per-network, so the client is
# unchanged.
cleanup() {
  docker rm -f "$srvc" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  docker rmi -f "$simg" "$cimg" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "building client image..."
docker build -f "$here/client.Dockerfile" -t "$cimg" "$root" >/dev/null

# proto -> build flags / port / scheme / QUIC toggle
proto_cfg() {
  case "$1" in
    h1) pflags="-d:plainHttp"; tls=0; h3=0; port=8080; scheme=http ;;
    h2) pflags="";             tls=1; h3=0; port=8443; scheme=https ;;
    h3) pflags="";             tls=1; h3=1; port=8443; scheme=https ;;  # QUIC + aioquic client
    *) echo "unknown VORTEX_PROTO: $1" >&2; exit 2 ;;
  esac
}

# union of the req/resp compression codecs -> -d:httpX + link libs
codec_flags() {
  cflags=""
  for cc in "$reqc" "$respc"; do
    case "$cc" in
      gzip) case "$cflags" in *httpGzip*) ;; *) cflags="$cflags -d:httpGzip --passL:-lz" ;; esac ;;
      br)   case "$cflags" in *httpBrotli*) ;; *) cflags="$cflags -d:httpBrotli --passL:-lbrotlienc --passL:-lbrotlidec --passL:-lbrotlicommon" ;; esac ;;
      zstd) case "$cflags" in *httpZstd*) ;; *) cflags="$cflags -d:httpZstd --passL:-lzstd" ;; esac ;;
      none|"") ;;
      *) echo "unknown compression: $cc" >&2; exit 2 ;;
    esac
  done
}

run_cell() {
  p="$1"; s="$2"
  proto_cfg "$p"; codec_flags
  compress=0; [ "$respc" != none ] && [ "$respc" != "" ] && compress=1
  bflags="$pflags$cflags"
  echo
  echo "=== $workload [proto=$p server=$s] : ${seconds}s, ${clients}x${conc} ==="

  echo "building server image (BUILD_FLAGS='${bflags:-none}' RUNTIME=$s)..."
  docker build -f "$here/Dockerfile" -t "$simg" $basearg \
    --build-arg BUILD_FLAGS="$bflags" --build-arg RUNTIME="$s" "$root" >/dev/null

  docker rm -f "$srvc" >/dev/null 2>&1 || true
  docker run -d --name "$srvc" --network "$net" --network-alias server \
    -e STRESS_PORT="$port" -e STRESS_TLS="$tls" -e STRESS_HTTP3="$h3" \
    -e STRESS_COMPRESS="$compress" -e STREAM_BYTES="$sbytes" "$simg" >/dev/null

  i=0
  until docker logs "$srvc" 2>&1 | grep -q "listening"; do
    i=$((i + 1)); [ "$i" -gt 300 ] && { echo "server did not start" >&2; docker logs "$srvc"; return 1; }
    sleep 0.1
  done

  # The client reports RSS/heap (from the server's /stats) and prints the
  # per-cell "== <workload> <server> <proto> passed ==" line on success.
  set +e
  docker run --rm --network "$net" \
    -e VORTEX_WORKLOAD="$workload" -e VORTEX_PROTO="$p" -e STRESS_SERVER="$s" \
    -e STRESS_BASE="$scheme://server:$port" \
    -e VORTEX_SECONDS="$seconds" -e VORTEX_REPORT_SECONDS="$report" \
    -e VORTEX_CONCURRENCY="$conc" -e VORTEX_CLIENTS="$clients" \
    -e VORTEX_REQ_COMPRESSION="$reqc" -e VORTEX_RESP_COMPRESSION="$respc" \
    -e VORTEX_STREAM_BYTES="$sbytes" "$cimg"
  crc=$?
  set -e

  docker rm -f "$srvc" >/dev/null 2>&1 || true
  [ "$crc" = 0 ] || echo "== $workload $s $p FAILED (exit $crc) =="
  return "$crc"
}

case "$proto"  in all) protos="h1 h2" ;; *) protos="$proto" ;; esac
case "$server" in all) servers="sync async async-await chronos chronos-await" ;; *) servers="$server" ;; esac

rc=0
for p in $protos; do for s in $servers; do run_cell "$p" "$s" || rc=1; done; done

echo
[ "$rc" = 0 ] && echo "== $workload: all cells passed ==" \
              || echo "== $workload: FAILURES (see above) =="
exit "$rc"
