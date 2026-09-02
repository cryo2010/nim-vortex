#!/bin/sh
# Per-workload performance bench (throughput + latency). Builds the vortex server
# (protocol x server-runtime) and a Python load client, drives ONE workload
# (VORTEX_WORKLOAD) at the server for VORTEX_SECONDS at max rate, and reports
# req/s | msg/s | evt/s | MB/s plus latency percentiles (p50/p90/p99/max) and the
# server's RSS/heap each VORTEX_REPORT_SECONDS. Unlike `stress`, it does NOT
# verify correctness and never pass/fails on data -- it measures.
#
# The bench SERVER is identical to the stress server, so this reuses
# conformance/stress/Dockerfile + stress_server.nim directly (referenced by path,
# not forked). Moving/renaming conformance/stress/ would break this harness.
#
# Numbers are for relative/regression tracking and cross-runtime comparison, not
# absolute peak: the pure-Python client caps throughput on cheap endpoints. Use
# `nimble saturate` (h2load) / `nimble h3load` for absolute peak req/s.
#
# Usage:  VORTEX_WORKLOAD=requests sh conformance/bench/run.sh
#         (normally via `nimble benchRequests` / `benchWs` / `benchSse` /
#          `benchStreamUpload` / `benchStreamDownload`, or `nimble bench`)
# Needs: docker.
#
# Env (same as stress):
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
stressdir=$(CDPATH= cd -- "$here/../stress" && pwd)   # reuse the stress server image

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

# A per-run id isolates concurrent runs (own docker network/container/image tags),
# generated once here -- before the BENCH_SMOKE self-re-exec -- and exported so
# every workload of one smoke shares it. Set VORTEX_RUN_ID yourself to name a run.
id="${VORTEX_RUN_ID:-$$}"
export VORTEX_RUN_ID="$id"

# The `bench` smoke runs every workload, short.
if [ "${BENCH_SMOKE:-0}" = "1" ]; then
  rc=0
  for w in requests ws sse streamupload streamdownload; do
    echo; echo "########## bench: $w ##########"
    BENCH_SMOKE=0 VORTEX_WORKLOAD="$w" sh "$0" || rc=1
  done
  echo
  [ "$rc" = 0 ] && echo "== bench smoke: all workloads ran ==" \
                || echo "== bench smoke: some cells could not measure (see above) =="
  exit "$rc"
fi

if [ "$(uname -m)" = "x86_64" ]; then basearg="--build-arg BASE=archlinux:latest"; else basearg=""; fi

net=vortex-bench-$id
srvc=vortex-bench-server-$id
simg=vortex-bench-server-img-$id
cimg=vortex-bench-client-img-$id

docker network create "$net" >/dev/null 2>&1 || true
cleanup() {
  docker rm -f "$srvc" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  docker rmi -f "$simg" "$cimg" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "building bench client image..."
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
  echo "=== bench $workload [proto=$p server=$s] : ${seconds}s, ${clients}x${conc} ==="

  echo "building server image (BUILD_FLAGS='${bflags:-none}' RUNTIME=$s)..."
  docker build -f "$stressdir/Dockerfile" -t "$simg" $basearg \
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

  # The bench client prints per-interval throughput + latency and a final
  # "== <workload> <server> <proto> bench: ... ==" line. A non-zero exit means it
  # could not measure at all (transport/connect failure), which flags the cell.
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
  [ "$crc" = 0 ] || echo "== bench $workload $s $p COULD NOT MEASURE (exit $crc) =="
  return "$crc"
}

case "$proto"  in all) protos="h1 h2" ;; *) protos="$proto" ;; esac
case "$server" in all) servers="sync async async-await chronos chronos-await" ;; *) servers="$server" ;; esac

rc=0
for p in $protos; do for s in $servers; do run_cell "$p" "$s" || rc=1; done; done

echo
[ "$rc" = 0 ] && echo "== bench $workload: all cells ran ==" \
              || echo "== bench $workload: some cells could not measure (see above) =="
exit "$rc"
