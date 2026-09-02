#!/bin/sh
# Cross-language performance bench: vortex vs Go vs Rust, one workload at a time,
# driven by the compiled navi client (h1/h2/h3). Three phases so the report is
# never interleaved with docker-build noise:
#   1. BUILD  -- build the navi client image + each (framework,proto) server image
#               (all build output goes to stderr).
#   2. RUN    -- per supported (framework,proto,workload) cell: start the server,
#               sample its container RSS via `docker stats`, run the client, and
#               append its RESULT line (+ peak rss) to a per-run results dir.
#   3. REPORT -- report.nim reads the results dir and prints ONE table (stdout).
#
# The bench server IS the stress server (conformance/stress/stress_server.nim +
# Dockerfile) for vortex; Go/Rust servers implement the same endpoint contract.
#
# Env: VORTEX_WORKLOAD, VORTEX_PROTO (h1|h2|h3|all), BENCH_FRAMEWORKS
# (vortex|go|rust|all), VORTEX_{SECONDS,REPORT_SECONDS,CONCURRENCY,CLIENTS,
# STREAM_BYTES,RUN_ID}, BENCH_SMOKE (1 = all workloads).
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)
stressdir=$(CDPATH= cd -- "$here/../stress" && pwd)

workload=${VORTEX_WORKLOAD:-requests}
proto=${VORTEX_PROTO:-h2}
frameworks=${BENCH_FRAMEWORKS:-all}
seconds=${VORTEX_SECONDS:-15}
report=${VORTEX_REPORT_SECONDS:-15}
conc=${VORTEX_CONCURRENCY:-32}
clients=${VORTEX_CLIENTS:-3}
sbytes=${VORTEX_STREAM_BYTES:-1073741824}
id="${VORTEX_RUN_ID:-$$}"
export VORTEX_RUN_ID="$id"

case "$proto"      in all) protos="h1 h2 h3" ;; *) protos="$proto" ;; esac
case "$frameworks" in all) fws="vortex go rust" ;; *) fws="$frameworks" ;; esac

results="${TMPDIR:-/tmp}/vortex-bench-$id"
net=vortex-bench-$id
cimg=vortex-bench-client-img-$id

# --- the `bench` smoke: every workload, then one big table -------------------
if [ "${BENCH_SMOKE:-0}" = "1" ]; then
  rm -rf "$results"; mkdir -p "$results"
  for w in requests ws sse streamupload streamdownload; do
    BENCH_SMOKE=0 BENCH_KEEP_RESULTS=1 VORTEX_WORKLOAD="$w" sh "$0" >&2 || true
  done
  nim r --hints:off "$here/report.nim" "$results"
  exit 0
fi

if [ "$(uname -m)" = "x86_64" ]; then basearg="--build-arg BASE=archlinux:latest"; else basearg=""; fi

[ "${BENCH_KEEP_RESULTS:-0}" = "1" ] || { rm -rf "$results"; mkdir -p "$results"; }
mkdir -p "$results"
docker network create "$net" >/dev/null 2>&1 || true

cleanup() {
  docker rm -f "$srvc" >/dev/null 2>&1 || true
  [ -n "${sampler:-}" ] && kill "$sampler" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
}
trap 'cleanup' EXIT INT TERM
srvc=""; sampler=""

# proto -> tls/h3/port/scheme; vortex build flags
proto_cfg() {
  case "$1" in
    h1) tls=0; h3=0; port=8080; scheme=http;  vflags="-d:plainHttp" ;;
    h2) tls=1; h3=0; port=8443; scheme=https; vflags="" ;;
    h3) tls=1; h3=1; port=8443; scheme=https; vflags="" ;;
    *) echo "unknown VORTEX_PROTO: $1" >&2; exit 2 ;;
  esac
}

# capability: does <framework> serve <workload> over <proto>? (sparse matrix)
supported() {  # $1=fw $2=workload $3=proto
  case "$2" in
    ws) [ "$3" = h1 ] ;;                                  # ws: h1 only (no Go/navi Extended CONNECT)
    streamupload) ! { [ "$1" = vortex ] && [ "$3" = h3 ]; } ;;  # vortex h3 upload gap
    streamdownload) ! { [ "$1" = rust ] && [ "$3" = h3 ]; } ;;  # ngtcp2<->quinn h3 tail-stall
    *) true ;;
  esac
}

# --- BUILD PHASE (all output to stderr) --------------------------------------
{
  echo "=== build: navi client image ==="
  docker build -f "$here/client/navi/Dockerfile" -t "$cimg" $basearg "$root"
  for fw in $fws; do
    for p in $protos; do
      supported "$fw" "$workload" "$p" || continue
      proto_cfg "$p"
      simg="vortex-bench-$fw-$p-img-$id"
      echo "=== build: $fw server ($p) ==="
      case "$fw" in
        vortex) docker build -f "$stressdir/Dockerfile" -t "$simg" $basearg \
                  --build-arg BUILD_FLAGS="$vflags" --build-arg RUNTIME=sync "$root" ;;
        go)     docker build -f "$here/servers/go/Dockerfile"   -t "$simg" "$here/servers/go" ;;
        rust)   docker build -f "$here/servers/rust/Dockerfile" -t "$simg" "$here/servers/rust" ;;
        *) echo "unknown framework: $fw" >&2; exit 2 ;;
      esac
    done
  done
} >&2

# --- RUN PHASE ---------------------------------------------------------------
run_cell() {  # $1=fw $2=proto
  fw="$1"; p="$2"; proto_cfg "$p"
  simg="vortex-bench-$fw-$p-img-$id"
  srvc="vortex-bench-srv-$id"
  rssfile="$results/${fw}_${p}_${workload}.rss"; : > "$rssfile"

  docker rm -f "$srvc" >/dev/null 2>&1 || true
  docker run -d --name "$srvc" --network "$net" --network-alias server \
    -e STRESS_PORT="$port" -e STRESS_TLS="$tls" -e STRESS_HTTP3="$h3" \
    -e STRESS_COMPRESS=0 -e STREAM_BYTES="$sbytes" "$simg" >/dev/null

  i=0
  until docker logs "$srvc" 2>&1 | grep -q "listening"; do
    i=$((i + 1)); [ "$i" -gt 300 ] && { echo "$fw $p: server did not start" >&2; docker logs "$srvc" >&2; docker rm -f "$srvc" >/dev/null 2>&1; return 1; }
    sleep 0.1
  done

  # peak container RSS sampler (uniform cross-language memory metric)
  ( peak=0
    while docker inspect "$srvc" >/dev/null 2>&1; do
      m=$(docker stats --no-stream --format '{{.MemUsage}}' "$srvc" 2>/dev/null | awk '{print $1}')
      b=$(echo "$m" | awk '/GiB/{printf "%d",$1*1073741824} /MiB/{printf "%d",$1*1048576} /KiB/{printf "%d",$1*1024} /^[0-9.]+B/{printf "%d",$1}' 2>/dev/null || echo 0)
      [ -n "$b" ] && [ "$b" -gt "$peak" ] 2>/dev/null && peak="$b"
      echo "$peak" > "$rssfile"
      sleep 1
    done ) &
  sampler=$!

  docker run --rm --network "$net" \
    -e VORTEX_WORKLOAD="$workload" -e VORTEX_PROTO="$p" -e BENCH_FRAMEWORK="$fw" \
    -e STRESS_BASE="$scheme://server:$port" \
    -e VORTEX_SECONDS="$seconds" -e VORTEX_REPORT_SECONDS="$report" \
    -e VORTEX_CONCURRENCY="$conc" -e VORTEX_CLIENTS="$clients" \
    -e VORTEX_STREAM_BYTES="$sbytes" "$cimg" \
    2> "$results/${fw}_${p}_${workload}.log" \
    | grep '^RESULT ' > "$results/${fw}_${p}_${workload}.line" || \
      echo "RESULT framework=$fw proto=$p workload=$workload unit=- throughput=0 p50_ms=0 p90_ms=0 p99_ms=0 max_ms=0 ops=0 err=0 non2xx=0 status=nomeasure" > "$results/${fw}_${p}_${workload}.line"

  kill "$sampler" >/dev/null 2>&1 || true; sampler=""
  docker rm -f "$srvc" >/dev/null 2>&1 || true; srvc=""
  # fold peak rss into the RESULT line
  rss=$(cat "$rssfile" 2>/dev/null || echo 0)
  sed -i.bak "s/\$/ rss_bytes=${rss:-0}/" "$results/${fw}_${p}_${workload}.line" 2>/dev/null || \
    { printf ' rss_bytes=%s\n' "${rss:-0}" >> "$results/${fw}_${p}_${workload}.line"; }
  rm -f "$results/${fw}_${p}_${workload}.line.bak"
}

for fw in $fws; do
  for p in $protos; do
    if supported "$fw" "$workload" "$p"; then
      echo "=== run: $workload $fw $p ===" >&2
      run_cell "$fw" "$p" || true
    else
      echo "RESULT framework=$fw proto=$p workload=$workload unit=- throughput=0 p50_ms=0 p90_ms=0 p99_ms=0 max_ms=0 ops=0 err=0 non2xx=0 status=skip rss_bytes=0" \
        > "$results/${fw}_${p}_${workload}.line"
    fi
  done
done

# --- REPORT PHASE ------------------------------------------------------------
[ "${BENCH_KEEP_RESULTS:-0}" = "1" ] || nim r --hints:off "$here/report.nim" "$results"
