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
#   VORTEX_PROTO     h1 | h2 | h3 | all           (default h2; all = h1 h2 h3)
#   VORTEX_SERVER    sync | async | async-await | chronos | chronos-await | all
#   VORTEX_SECONDS / VORTEX_REPORT_SECONDS / VORTEX_CONCURRENCY / VORTEX_CLIENTS
#   VORTEX_REQ_COMPRESSION / VORTEX_RESP_COMPRESSION   none | gzip | br | zstd
#   VORTEX_STREAM_BYTES   streaming transfer size (default 1 GiB)
#   VORTEX_RUN_ID    isolation id for the docker network/container/image names,
#                    so runs can go in parallel (default: this run's PID)
#   VORTEX_CHAOS     none | all | CSV of slowread,slowwrite,idle,abort,vanish
#                    (default all). Launches a second, UNVERIFIED misbehaving
#                    client (chaos.py) per cell alongside the verified canary;
#                    the canary still hard-fails, and the sidecar can only add
#                    failures, never mask one (canary wins). none = no sidecar
#                    (and no drain pause), the pre-chaos behavior.
#   VORTEX_CHAOS_CONC     chaos sidecar worker count (default 8)
#   VORTEX_CHAOS_SEED     per-worker seeded RNG for reproducible chaos (default 1)
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)

workload=${VORTEX_WORKLOAD:-requests}
# Case-insensitive: accept ALL/All/all etc. so a stray capital doesn't trip the
# `all` expansion (and proto/server matching) below and hard-exit with an
# "unknown VORTEX_PROTO" before anything runs.
proto=$(printf '%s' "${VORTEX_PROTO:-h2}" | tr 'A-Z' 'a-z')
server=$(printf '%s' "${VORTEX_SERVER:-sync}" | tr 'A-Z' 'a-z')
seconds=${VORTEX_SECONDS:-60}
report=${VORTEX_REPORT_SECONDS:-60}
conc=${VORTEX_CONCURRENCY:-32}
clients=${VORTEX_CLIENTS:-3}
reqc=${VORTEX_REQ_COMPRESSION:-gzip}
respc=${VORTEX_RESP_COMPRESSION:-gzip}
sbytes=${VORTEX_STREAM_BYTES:-1073741824}
chaos=$(printf '%s' "${VORTEX_CHAOS:-all}" | tr 'A-Z' 'a-z')
chaosconc="${VORTEX_CHAOS_CONC:-8}"
chaosseed="${VORTEX_CHAOS_SEED:-1}"

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
chc=vortex-stress-chaos-$id
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
  docker rm -f "$chc" >/dev/null 2>&1 || true
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
  bflags="$pflags$cflags${VORTEX_EXTRA_FLAGS:+ ${VORTEX_EXTRA_FLAGS}}"
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

  # Chaos sidecar: a second, UNVERIFIED client that misbehaves on purpose while
  # the verified canary below runs unchanged. Launched DETACHED here so it is
  # already up and has sampled its fd baseline (off the still-quiet server)
  # before the canary starts adding real traffic; consulted only after the
  # canary exits (see below), so it can add failures but never mask one.
  if [ "$chaos" != "none" ]; then
    docker rm -f "$chc" >/dev/null 2>&1 || true
    docker run -d --name "$chc" --network "$net" \
      -e VORTEX_CHAOS="$chaos" -e VORTEX_CHAOS_CONC="$chaosconc" \
      -e VORTEX_CHAOS_SEED="$chaosseed" -e VORTEX_PROTO="$p" \
      -e VORTEX_WORKLOAD="$workload" \
      -e STRESS_BASE="$scheme://server:$port" \
      -e VORTEX_SECONDS="$seconds" -e VORTEX_REPORT_SECONDS="$report" \
      -e VORTEX_STREAM_BYTES="$sbytes" "$cimg" python chaos.py >/dev/null
    # Wait for the sidecar's fd baseline so it is sampled before the canary
    # connects. chaos.py prints "chaos: baseline fds=N" once, before it starts
    # inducing chaos; cap at ~30 s (300 * 0.1 s), then give up on this cell.
    i=0
    until docker logs "$chc" 2>&1 | grep -q "chaos: baseline"; do
      i=$((i + 1))
      [ "$i" -gt 300 ] && { echo "chaos sidecar did not reach baseline" >&2; docker logs "$chc"; docker rm -f "$chc" >/dev/null 2>&1 || true; return 1; }
      sleep 0.1
    done
  fi

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

  # Wait for the chaos sidecar to finish and collect its verdict. It closes
  # everything and waits a drain pause (up to 40 s on h3) before its final
  # /stats fd sample, so the server must stay up until it exits -- hence the
  # server teardown below moves AFTER this wait. Cap at ~90 s (900 * 0.1 s),
  # covering the drain plus slack; on cap, treat it as a watchdog fail (3).
  xrc=0
  if [ "$chaos" != "none" ]; then
    i=0
    until [ "$(docker inspect -f '{{.State.Status}}' "$chc" 2>/dev/null)" != running ]; do
      i=$((i + 1))
      if [ "$i" -gt 900 ]; then docker rm -f "$chc" >/dev/null 2>&1 || true; xrc=3; break; fi
      sleep 0.1
    done
    if [ "$xrc" = 0 ]; then xrc=$(docker inspect -f '{{.State.ExitCode}}' "$chc"); fi
    echo "--- chaos sidecar ---"
    docker logs "$chc" 2>&1 || true
    docker rm -f "$chc" >/dev/null 2>&1 || true
  fi

  # Server teardown. Moved to AFTER the sidecar wait so the sidecar's final
  # /stats fd sample lands on a live server; when chaos=none the sidecar block
  # above is skipped and this is exactly where it used to be (a no-op reorder).
  docker rm -f "$srvc" >/dev/null 2>&1 || true
  [ "$crc" = 0 ] || echo "== $workload $s $p FAILED (exit $crc) =="
  # Canary wins: only fold in the sidecar's verdict when the canary passed, so
  # chaos can add a failure but never mask one.
  if [ "$crc" = 0 ] && [ "$xrc" != 0 ]; then
    echo "== $workload $s $p chaos sidecar FAILED (exit $xrc) =="
    crc=$xrc
  fi
  return "$crc"
}

case "$proto"  in all) protos="h1 h2 h3" ;; *) protos="$proto" ;; esac
case "$server" in all) servers="sync async async-await chronos chronos-await" ;; *) servers="$server" ;; esac

rc=0
for p in $protos; do for s in $servers; do run_cell "$p" "$s" || rc=1; done; done

echo
[ "$rc" = 0 ] && echo "== $workload: all cells passed ==" \
              || echo "== $workload: FAILURES (see above) =="
exit "$rc"
