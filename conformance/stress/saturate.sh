#!/bin/sh
# Configurable stress test: h2load fires as many requests as it can at a vortex
# backend while Grafana shows the server's own CPU/memory (docker stats) live and
# the achieved req/s as a summary. Companion to `nimble loadtest` (k6): loadtest
# holds a chosen load and charts client-side latency; stress saturates and charts
# the server. h2load is the driver (not k6), so the client is not the bottleneck.
#
# Usage:  sh conformance/stress/saturate.sh          (or `nimble saturate`)
#         sh conformance/stress/saturate.sh --down    (stop Grafana/Prometheus)
#         sh conformance/stress/saturate.sh --down -v (also drop retained history)
# Needs: docker (with the compose plugin).
#
# Env knobs:
#   BACKEND   h1 | h2 | h2-gzip | all   (default h1)
#   DURATION  seconds to saturate       (default 30)
#   CONNS     concurrent connections    (default 100)
#   STREAMS   concurrent streams/conn, h2 only (default 32)
#   ENDPOINT  /plaintext | /json | /big (default /plaintext; use /big for gzip)
#
# NOTE: h2load reports only a final summary, so req/s is shown as a stat (not a
# live curve); the live charts are the server's docker-stats CPU/memory. h2load
# drives h1/h2/h2c; for HTTP/3 saturation use conformance/h3load.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)

if [ "${1:-}" = "--down" ]; then
  docker compose -f "$here/docker-compose.yml" down ${2:-}
  exit 0
fi

backend=${BACKEND:-h1}
dur=${DURATION:-30}
conns=${CONNS:-100}
streams=${STREAMS:-32}
endpoint=${ENDPOINT:-/plaintext}

net=vortex-stress
srvc=vortex-stress-server
simg=vortex-stress-server-img
cimg=vortex-stress-client-img
pg=http://localhost:9191

if [ "$(uname -m)" = "x86_64" ]; then
  basearg="--build-arg BASE=archlinux:latest"
else
  basearg=""
fi

echo "starting Prometheus + Grafana + Pushgateway..."
docker compose -f "$here/docker-compose.yml" up -d

echo "building h2load client image..."
docker build -f "$root/conformance/h2load/client.Dockerfile" -t "$cimg" "$root/conformance/h2load" >/dev/null

statspid=""
cleanup() {
  [ -n "$statspid" ] && kill "$statspid" >/dev/null 2>&1
  docker rm -f "$srvc" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# Sample the server container with `docker stats` and push CPU (cores) + memory
# (bytes) to the Pushgateway under this backend. Works on Docker Desktop, where
# cAdvisor cannot reach the daemon to name containers. Arg 1 is the backend label.
sample_server_stats() {
  b="$1"
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
      printf "stress_server_cpu_cores %.3f\nstress_server_memory_bytes %d\n", cpu/100, num*m
    }' | curl -s --data-binary @- "$pg/metrics/job/stress_server/backend/$b" >/dev/null 2>&1
  done
}

backend_cfg() {
  case "$1" in
    h1)      bflags="-d:plainHttp";            tls=0; comp=0; port=8080; scheme=http;  proto="--h1"; mflag="" ;;
    h2)      bflags="";                        tls=1; comp=0; port=8443; scheme=https; proto="";     mflag="-m $streams" ;;
    h2-gzip) bflags="-d:httpGzip --passL:-lz"; tls=1; comp=1; port=8443; scheme=https; proto="";     mflag="-m $streams" ;;
    *) echo "unknown BACKEND: $1 (want h1 | h2 | h2-gzip | all)" >&2; exit 2 ;;
  esac
}

run_case() {
  b="$1"
  backend_cfg "$b"
  accept=""; [ "$comp" = 1 ] && accept="-H accept-encoding:gzip"
  echo
  echo "=== stress $b: $scheme://:$port$endpoint, ${dur}s x ${conns} conns${mflag:+ $mflag} ==="

  echo "building server image (protocol: ${bflags:-none})..."
  docker build -f "$here/Dockerfile" -t "$simg" $basearg --build-arg BUILD_FLAGS="$bflags" "$root"

  docker rm -f "$srvc" >/dev/null 2>&1 || true
  docker run -d --name "$srvc" --network "$net" --network-alias server \
    -e STRESS_PORT="$port" -e STRESS_TLS="$tls" -e STRESS_COMPRESS="$comp" \
    "$simg" >/dev/null

  i=0
  until docker logs "$srvc" 2>&1 | grep -q "listening"; do
    i=$((i + 1))
    [ "$i" -gt 100 ] && { echo "server did not start" >&2; docker logs "$srvc"; exit 1; }
    sleep 0.1
  done
  echo "server up: $scheme://server:$port"

  sample_server_stats "$b" &
  statspid=$!

  echo "saturating with h2load for ${dur}s..."
  out=$(docker run --rm --network "$net" "$cimg" \
        h2load $proto -c "$conns" $mflag $accept -D "$dur" "$scheme://server:$port$endpoint" 2>&1) || true
  printf '%s\n' "$out" | grep -E "finished in|^requests:|status codes:" || true

  # Stop the live server sampler; its series ends with the run (history stays).
  { [ -n "$statspid" ] && kill "$statspid" >/dev/null 2>&1; } || true
  statspid=""
  curl -s -X DELETE "$pg/metrics/job/stress_server/backend/$b" >/dev/null 2>&1 || true

  # Push h2load's summary (req/s + request counts) for this backend's stat panels.
  reqps=$(printf '%s\n' "$out" | awk '/finished in/{for(i=1;i<=NF;i++) if($i ~ /req\/s/){v=$(i-1); gsub(/,/,"",v); print v}}')
  total=$(printf '%s\n' "$out" | awk '/^requests:/{print $2}')
  succ=$(printf '%s\n' "$out"  | awk '/^requests:/{for(i=1;i<=NF;i++) if($i=="succeeded,") print $(i-1)}')
  if [ -n "$reqps" ]; then
    printf 'stress_req_per_sec %s\nstress_requests_total %s\nstress_requests_succeeded %s\n' \
      "$reqps" "${total:-0}" "${succ:-0}" \
      | curl -s --data-binary @- "$pg/metrics/job/stress_load/backend/$b" >/dev/null 2>&1
    echo "pushed: $b -> ${reqps} req/s"
  else
    echo "warning: could not parse h2load req/s for $b" >&2
  fi

  docker rm -f "$srvc" >/dev/null 2>&1 || true
}

if [ "$backend" = "all" ]; then backends="h1 h2 h2-gzip"; else backends="$backend"; fi
for b in $backends; do run_case "$b"; done

echo
echo "RESULT: stress run complete."
echo "Charts: http://localhost:3001  (Grafana, dashboard \"vortex stress (h2load)\")."
echo "Stop the stack: sh $0 --down  (add -v to drop history)."
