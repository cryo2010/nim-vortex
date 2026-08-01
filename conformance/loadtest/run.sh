#!/bin/sh
# Configurable k6 load test with a live Grafana + Prometheus dashboard.
#
# Brings up Prometheus + Grafana (once, and leaves them up for viewing), builds
# the selected vortex backend image(s), starts each on a private docker network,
# and drives k6 load into it while streaming metrics to Grafana. Runs for a
# configurable duration in either a max-throughput or a fixed-rate model.
#
# Usage:  sh conformance/loadtest/run.sh          (or `nimble loadtest`)
#         sh conformance/loadtest/run.sh --down    (stop Grafana/Prometheus)
#         sh conformance/loadtest/run.sh --down -v (also drop retained history)
# Needs: docker (with the compose plugin).
#
# Env knobs:
#   BACKEND   h1 | h2 | h2-gzip | all     (default h1)
#   RUNTIME   sync | async | async-await | chronos | chronos-await | all
#             handler execution model (default sync)
#   MODE      throughput | rate           (default throughput)
#   DURATION  k6 duration, e.g. 30s, 2m   (default 30s)
#   VUS       virtual users, throughput mode   (default 50)
#   RATE      target req/s, rate mode          (default 5000)
#   ENDPOINT  /plaintext | /json | /big   (default /plaintext; use /big for gzip)
#
# NOTE: k6 cannot drive HTTP/3 or h2c (its HTTP/2 needs TLS), so this harness
# covers h1 and h2-over-TLS only. For h3 / h2c load use conformance/h3load and
# conformance/h2load (real ngtcp2/nghttp2 clients).
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)

# --- Teardown path -----------------------------------------------------------
if [ "${1:-}" = "--down" ]; then
  # Pass a trailing -v through to drop the retained metrics/dashboards.
  docker compose -f "$here/docker-compose.yml" down ${2:-}
  exit 0
fi

backend=${BACKEND:-h1}
runtime=${RUNTIME:-sync}
mode=${MODE:-throughput}
duration=${DURATION:-30s}
vus=${VUS:-50}
rate=${RATE:-5000}
endpoint=${ENDPOINT:-/plaintext}

net=vortex-loadtest
srvc=vortex-loadtest-server
simg=vortex-loadtest-server-img

if [ "$(uname -m)" = "x86_64" ]; then
  basearg="--build-arg BASE=archlinux:latest"
else
  basearg=""
fi

# --- Observability stack (idempotent; stays up after the run) ----------------
echo "starting Prometheus + Grafana..."
docker compose -f "$here/docker-compose.yml" up -d

statspid=""
cleanup() {
  [ -n "$statspid" ] && kill "$statspid" >/dev/null 2>&1
  docker rm -f "$srvc" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# Sample the server container with `docker stats` and push CPU (cores) + memory
# (bytes) to the Pushgateway, which Prometheus scrapes. Runs on the host, so it
# works on Docker Desktop (where cAdvisor cannot reach the daemon to name
# containers). `docker stats --no-stream` blocks ~1-2s per read, pacing the loop.
sample_server_stats() {
  while docker inspect -f '{{.State.Running}}' "$srvc" >/dev/null 2>&1; do
    line=$(docker stats --no-stream --format '{{.CPUPerc}}|{{.MemUsage}}' "$srvc" 2>/dev/null) || break
    [ -n "$line" ] || { sleep 1; continue; }
    printf '%s\n' "$line" | awk -F'|' '{
      cpu=$1; sub(/%/,"",cpu);
      mem=$2; sub(/ .*/,"",mem);
      num=mem; sub(/[A-Za-z]+/,"",num);
      unit=mem; sub(/[0-9.]+/,"",unit);
      m=1; if(unit=="KiB")m=1024; else if(unit=="MiB")m=1048576;
      else if(unit=="GiB")m=1073741824; else if(unit=="B")m=1;
      printf "loadtest_server_cpu_cores %.3f\nloadtest_server_memory_bytes %d\n", cpu/100, num*m
    }' | curl -s --data-binary @- http://localhost:9091/metrics/job/loadtest_server >/dev/null 2>&1
  done
}

# Stop the sampler and clear its Pushgateway group so the series ends when the run
# does (Prometheus keeps the history it already scraped).
stop_server_stats() {
  [ -n "$statspid" ] && kill "$statspid" >/dev/null 2>&1
  statspid=""
  curl -s -X DELETE http://localhost:9091/metrics/job/loadtest_server >/dev/null 2>&1 || true
}

# backend -> build flags / tls / compress / port / scheme
backend_cfg() {
  case "$1" in
    h1)      bflags="-d:plainHttp";            tls=0; comp=0; port=8080; scheme=http ;;
    h2)      bflags="";                        tls=1; comp=0; port=8443; scheme=https ;;
    h2-gzip) bflags="-d:httpGzip --passL:-lz"; tls=1; comp=1; port=8443; scheme=https ;;
    *) echo "unknown BACKEND: $1 (want h1 | h2 | h2-gzip | all)" >&2; exit 2 ;;
  esac
}

validate_runtime() {
  case "$1" in
    sync|async|async-await|chronos|chronos-await) ;;
    *) echo "unknown RUNTIME: $1 (want sync|async|async-await|chronos|chronos-await|all)" >&2; exit 2 ;;
  esac
}

run_case() {
  b="$1"; r="$2"
  backend_cfg "$b"
  echo
  echo "=== backend $b, runtime $r: $scheme://:$port, mode=$mode, duration=$duration, endpoint=$endpoint ==="

  echo "building server image (protocol: ${bflags:-none}; runtime: $r)..."
  docker build -f "$here/Dockerfile" -t "$simg" $basearg \
    --build-arg BUILD_FLAGS="$bflags" --build-arg RUNTIME="$r" "$root"

  docker rm -f "$srvc" >/dev/null 2>&1 || true
  docker run -d --name "$srvc" --network "$net" --network-alias server \
    -e LOADTEST_PORT="$port" -e LOADTEST_TLS="$tls" -e LOADTEST_COMPRESS="$comp" \
    "$simg" >/dev/null

  # start() binds before returning, so the "listening" log line means ready.
  i=0
  until docker logs "$srvc" 2>&1 | grep -q "listening"; do
    i=$((i + 1))
    [ "$i" -gt 100 ] && { echo "server did not start" >&2; docker logs "$srvc"; exit 1; }
    sleep 0.1
  done
  echo "server up: $scheme://server:$port"

  # Push the server container's CPU/memory to the Pushgateway while k6 runs.
  sample_server_stats & statspid=$!

  # testid separates runs; backend/runtime/mode are also tagged so the dashboard
  # can group or filter by any single axis.
  ts=$(date +%Y%m%d-%H%M%S)
  echo "running k6..."
  # Ship latency as a native histogram (not per-flush percentile aggregation of
  # every raw sample) so the Prometheus output stays cheap at high req/s.
  if ! docker run --rm --network "$net" \
    -e TARGET_URL="$scheme://server:$port" \
    -e ENDPOINT="$endpoint" -e MODE="$mode" -e DURATION="$duration" \
    -e VUS="$vus" -e RATE="$rate" \
    -e K6_PROMETHEUS_RW_SERVER_URL="http://prometheus:9090/api/v1/write" \
    -e K6_PROMETHEUS_RW_TREND_AS_NATIVE_HISTOGRAM="true" \
    -e K6_PROMETHEUS_RW_PUSH_INTERVAL="1s" \
    -v "$here/loadtest.js:/loadtest.js:ro" \
    grafana/k6 run -o experimental-prometheus-rw \
      --tag testid="$b-$r-$mode-$ts" \
      --tag backend="$b" --tag runtime="$r" --tag mode="$mode" /loadtest.js
  then
    rc=$?
    stop_server_stats
    docker rm -f "$srvc" >/dev/null 2>&1 || true
    echo >&2
    echo "RESULT: k6 exited non-zero ($rc) for backend $b / runtime $r." >&2
    if [ "$rc" = 137 ]; then
      echo "  Exit 137 = the k6 container was OOM-killed. k6 retains a sample per" >&2
      echo "  request, so its memory grows with total requests. Give Docker more" >&2
      echo "  memory, lower VUS/RATE, or shorten DURATION. The vortex server is" >&2
      echo "  unaffected. See conformance/loadtest/README.md for the budget." >&2
    fi
    exit "$rc"
  fi

  stop_server_stats
  docker rm -f "$srvc" >/dev/null 2>&1 || true
}

if [ "$backend" = "all" ]; then backends="h1 h2 h2-gzip"; else backends="$backend"; fi
if [ "$runtime" = "all" ]; then
  runtimes="sync async async-await chronos chronos-await"
else
  validate_runtime "$runtime"; runtimes="$runtime"
fi

for b in $backends; do
  for r in $runtimes; do
    run_case "$b" "$r"
  done
done

echo
echo "RESULT: load test run complete."
echo "Charts: http://localhost:3000  (Grafana, dashboard \"vortex load test (k6)\")."
echo "Filter with the 'test id' variable. Stop the stack: sh $0 --down  (add -v to drop history)."
