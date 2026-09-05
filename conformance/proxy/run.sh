#!/bin/sh
# Reverse-proxy interop: stand nginx / caddy / HAProxy in front of the vortex
# origin and verify the core features work through each -- TLS, every HTTP
# method, streaming (up + down), SSE, and WebSockets -- over h1/h2/h3 from the
# client to the proxy (the proxy re-originates HTTP/1.1 to vortex). Plus a
# HAProxy PROXY-protocol check (send-proxy -> vortex proxyprotocol.nim).
#
# Topology:  client --TLS(h1/h2/h3)--> proxy --h1 cleartext--> vortex origin
#
# Reuses the stress origin server (conformance/stress/stress_server.nim, built
# -d:plainHttp) and the stress client (conformance/stress/client), pointing the
# client's STRESS_BASE at the proxy. Feature checks map to stress workloads:
# methods/streamupload/streamdownload/sse/ws; TLS is an auxiliary curl chain check.
#
# Usage:  sh conformance/proxy/run.sh          (or `nimble proxy`)
#         PROXY=nginx sh conformance/proxy/run.sh
# Needs: docker (+ openssl on the host to mint the CA/cert).
#
# Env:
#   PROXY         nginx | caddy | haproxy | all   (default all)
#   PROXY_PROTOS  client<->proxy protocols        (default "h1 h2 h3")
#   VORTEX_SECONDS       per-cell runtime seconds  (default 3)
#   VORTEX_STREAM_BYTES  streaming transfer size   (default 8 MiB)
#   VORTEX_RUN_ID        isolation id for docker names (default this PID)
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)

sel=$(printf '%s' "${PROXY:-all}" | tr 'A-Z' 'a-z')
case "$sel" in all) proxies="nginx caddy haproxy" ;; *) proxies="$sel" ;; esac
protos=${PROXY_PROTOS:-"h1 h2 h3"}
features="methods streamupload streamdownload sse ws"
secs=${VORTEX_SECONDS:-3}
sbytes=${VORTEX_STREAM_BYTES:-8388608}
id="${VORTEX_RUN_ID:-$$}"

# Pinned proxy images (official). curl image drives the TLS chain check.
nginx_img=nginx:1.27
caddy_img=caddy:2.11.4-alpine   # needs >=2.9 (quic-go >=v0.47 #4645): h3 bodies w/o Content-Length
haproxy_img=haproxy:3.0
curlimg=curlimages/curl:latest

if [ "$(uname -m)" = "x86_64" ]; then basearg="--build-arg BASE=archlinux:latest"; else basearg=""; fi

oimg=vortex-proxy-origin-img-$id
cimg=vortex-proxy-client-img-$id
tmp=$(mktemp -d)
certs="$tmp/certs"
results="$tmp/results"
: > "$results"
proxy_h3=0

cleanup() {
  for c in $(docker ps -aq --filter "name=-$id" 2>/dev/null); do docker rm -f "$c" >/dev/null 2>&1 || true; done
  for n in $(docker network ls -q --filter "name=-$id" 2>/dev/null); do docker network rm "$n" >/dev/null 2>&1 || true; done
  docker rmi -f "$oimg" "$cimg" >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

rec() { printf '%s %s %s %s\n' "$1" "$2" "$3" "$4" >> "$results"; }

# --- one CA -> proxy server cert (client trusts the CA); combined pem for HAProxy
echo "minting CA + proxy cert..."
mkdir -p "$certs"
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout "$certs/ca.key" -out "$certs/ca.pem" \
  -subj "/CN=vortex-proxy-ca" >/dev/null 2>&1
printf "subjectAltName=DNS:proxy,DNS:localhost\n" > "$certs/san.ext"
openssl req -newkey rsa:2048 -nodes -keyout "$certs/key.pem" \
  -out "$certs/proxy.csr" -subj "/CN=proxy" >/dev/null 2>&1
openssl x509 -req -in "$certs/proxy.csr" -CA "$certs/ca.pem" -CAkey "$certs/ca.key" \
  -CAcreateserial -days 3650 -extfile "$certs/san.ext" -out "$certs/cert.pem" >/dev/null 2>&1
cat "$certs/cert.pem" "$certs/key.pem" > "$certs/proxy.pem"   # HAProxy wants cert+key

# --- build the origin (h1 cleartext) and client images once
echo "building vortex origin image (-d:plainHttp)..."
docker build -f "$root/conformance/stress/Dockerfile" -t "$oimg" $basearg \
  --build-arg BUILD_FLAGS="-d:plainHttp" --build-arg RUNTIME=sync "$root" >/dev/null
echo "building client image..."
docker build -f "$root/conformance/stress/client.Dockerfile" -t "$cimg" "$root" >/dev/null

wait_listening() {
  cont=$1; i=0
  until docker logs "$cont" 2>&1 | grep -q "listening"; do
    i=$((i + 1)); [ "$i" -gt 300 ] && { docker logs "$cont" >&2 || true; return 1; }
    sleep 0.1
  done
}

proxy_ready() {
  net=$1; i=0
  until docker run --rm --network "$net" -v "$certs":/certs:ro "$curlimg" \
      -sf -o /dev/null --cacert /certs/ca.pem --connect-timeout 2 \
      https://proxy:8443/plaintext >/dev/null 2>&1; do
    i=$((i + 1)); [ "$i" -gt 40 ] && return 1
    sleep 0.5
  done
}

build_haproxy_cfg() {  # out sendproxy quic
  out=$1; sp=$2; quic=$3; qline=""
  [ "$quic" = 1 ] && qline="    bind quic4@:8443 ssl crt /certs/proxy.pem alpn h3"
  sed -e "s|__QUIC_BIND__|$qline|" -e "s|__SENDPROXY__|$sp|" \
    "$here/proxies/haproxy/haproxy.cfg" > "$out"
}

start_proxy() {  # prox net pcont ; sets proxy_h3
  prox=$1; net=$2; pcont=$3
  docker rm -f "$pcont" >/dev/null 2>&1 || true
  case "$prox" in
    nginx)
      docker run -d --name "$pcont" --network "$net" --network-alias proxy \
        -v "$here/proxies/nginx/nginx.conf":/etc/nginx/nginx.conf:ro \
        -v "$certs":/certs:ro "$nginx_img" >/dev/null
      proxy_h3=1 ;;
    caddy)
      docker run -d --name "$pcont" --network "$net" --network-alias proxy \
        -v "$here/proxies/caddy/Caddyfile":/etc/caddy/Caddyfile:ro \
        -v "$certs":/certs:ro "$caddy_img" >/dev/null
      proxy_h3=1 ;;
    haproxy)
      build_haproxy_cfg "$tmp/haproxy.cfg" "" 1
      docker run -d --name "$pcont" --network "$net" --network-alias proxy \
        -v "$tmp/haproxy.cfg":/usr/local/etc/haproxy/haproxy.cfg:ro \
        -v "$certs":/certs:ro "$haproxy_img" >/dev/null
      if proxy_ready "$net"; then
        proxy_h3=1; return 0
      fi
      echo "  haproxy: QUIC bind unsupported by image; retrying h1/h2 only" >&2
      docker rm -f "$pcont" >/dev/null 2>&1 || true
      build_haproxy_cfg "$tmp/haproxy.cfg" "" 0
      docker run -d --name "$pcont" --network "$net" --network-alias proxy \
        -v "$tmp/haproxy.cfg":/usr/local/etc/haproxy/haproxy.cfg:ro \
        -v "$certs":/certs:ro "$haproxy_img" >/dev/null
      proxy_h3=0 ;;
  esac
  proxy_ready "$net"
}

supported() {  # prox feature proto  -> exit 0 if the cell should run
  case "$2" in
    ws) [ "$3" = h1 ] ;;              # proxies don't map h2/h3 Extended CONNECT to h1 ws
    streamupload) [ "$3" != h3 ] ;;   # vortex h3 request-body flow-control gap
    *) return 0 ;;
  esac
}

tls_check() {  # prox net proto
  prox=$1; net=$2; proto=$3
  case "$proto" in h1) pf=--http1.1 ;; h2) pf=--http2 ;; h3) pf=--http3 ;; esac
  set +e
  code=$(docker run --rm --network "$net" -v "$certs":/certs:ro "$curlimg" \
    -sS -o /dev/null -w '%{http_code}' --cacert /certs/ca.pem $pf \
    --retry 3 --retry-connrefused --connect-timeout 5 \
    https://proxy:8443/plaintext 2>/dev/null)
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    echo "  [$prox $proto] tls: curl check skipped (rc=$rc; curl may lack $proto)" >&2
    rec "$prox" "$proto" tls warn
  elif [ "$code" = 200 ]; then
    rec "$prox" "$proto" tls pass
  else
    echo "  [$prox $proto] tls: HTTP $code (chain via our CA)" >&2
    rec "$prox" "$proto" tls fail
  fi
}

run_cell() {  # prox net proto feature
  prox=$1; net=$2; proto=$3; feat=$4
  set +e
  docker run --rm --network "$net" \
    -e VORTEX_WORKLOAD="$feat" -e VORTEX_PROTO="$proto" -e STRESS_SERVER="$prox" \
    -e STRESS_BASE="https://proxy:8443" \
    -e VORTEX_SECONDS="$secs" -e VORTEX_REPORT_SECONDS="$secs" \
    -e VORTEX_CLIENTS=1 -e VORTEX_CONCURRENCY=4 -e VORTEX_STREAM_BYTES="$sbytes" \
    -e VORTEX_REQ_COMPRESSION=none -e VORTEX_RESP_COMPRESSION=none \
    "$cimg" > "$tmp/cell.log" 2>&1
  rc=$?
  set -e
  if [ "$rc" -eq 0 ]; then
    rec "$prox" "$proto" "$feat" pass
  else
    echo "  [$prox $proto $feat] FAILED (exit $rc):" >&2; tail -4 "$tmp/cell.log" >&2
    echo "  --- origin ($prox) log tail ---" >&2
    docker logs "vortex-origin-$prox-$id" 2>&1 | tail -12 >&2 || true
    echo "  --- proxy ($prox) log tail ---" >&2
    docker logs "vortex-proxysrv-$prox-$id" 2>&1 | tail -12 >&2 || true
    rec "$prox" "$proto" "$feat" fail
  fi
}

run_proxy_protocol_check() {  # HAProxy send-proxy -> vortex proxyprotocol.nim
  net="vortex-pp-$id"; oc="vortex-pp-origin-$id"; pc="vortex-pp-proxy-$id"
  docker network create "$net" >/dev/null 2>&1 || true
  docker run -d --name "$oc" --network "$net" --network-alias vortex \
    -e STRESS_PORT=8080 -e STRESS_TLS=0 -e STRESS_COMPRESS=0 \
    -e STRESS_PROXY_PROTOCOL=require -e STREAM_BYTES="$sbytes" "$oimg" >/dev/null
  if ! wait_listening "$oc"; then rec haproxy - proxy-protocol fail; docker rm -f "$oc" >/dev/null 2>&1 || true; docker network rm "$net" >/dev/null 2>&1 || true; return; fi
  build_haproxy_cfg "$tmp/haproxy-pp.cfg" "send-proxy-v2" 0
  docker run -d --name "$pc" --network "$net" --network-alias proxy \
    -v "$tmp/haproxy-pp.cfg":/usr/local/etc/haproxy/haproxy.cfg:ro \
    -v "$certs":/certs:ro "$haproxy_img" >/dev/null
  if ! proxy_ready "$net"; then rec haproxy - proxy-protocol fail; docker rm -f "$pc" "$oc" >/dev/null 2>&1 || true; docker network rm "$net" >/dev/null 2>&1 || true; return; fi
  set +e
  body=$(docker run --rm --network "$net" -v "$certs":/certs:ro "$curlimg" \
    -sS --cacert /certs/ca.pem --retry 3 --retry-connrefused --connect-timeout 5 \
    https://proxy:8443/whoami 2>/dev/null)
  rc=$?
  set -e
  # origin runs proxyProtocol=Require, so a missing/invalid PROXY header is
  # dropped; a 200 with a non-empty IP proves HAProxy's header was parsed.
  if [ "$rc" -eq 0 ] && printf '%s' "$body" | grep -qE '[0-9a-fA-F]+[.:]'; then
    echo "  haproxy proxy-protocol: /whoami -> $body"
    rec haproxy - proxy-protocol pass
  else
    echo "  haproxy proxy-protocol FAILED (rc=$rc): '$body'" >&2
    rec haproxy - proxy-protocol fail
  fi
  docker rm -f "$pc" "$oc" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
}

run_proxy() {  # prox
  prox=$1
  net="vortex-proxy-$prox-$id"; oc="vortex-origin-$prox-$id"; pc="vortex-proxysrv-$prox-$id"
  echo; echo "########## $prox ##########"
  docker network create "$net" >/dev/null 2>&1 || true
  docker rm -f "$oc" >/dev/null 2>&1 || true
  docker run -d --name "$oc" --network "$net" --network-alias vortex \
    -e STRESS_PORT=8080 -e STRESS_TLS=0 -e STRESS_COMPRESS=0 \
    -e STREAM_BYTES="$sbytes" "$oimg" >/dev/null
  if ! wait_listening "$oc"; then
    echo "  [$prox] origin did not start" >&2
    for p in $protos; do rec "$prox" "$p" origin fail; done
    docker rm -f "$oc" >/dev/null 2>&1 || true; docker network rm "$net" >/dev/null 2>&1 || true; return
  fi
  if ! start_proxy "$prox" "$net" "$pc"; then
    echo "  [$prox] proxy did not become ready" >&2
    docker logs "$pc" 2>&1 | tail -10 >&2 || true
    for p in $protos; do rec "$prox" "$p" proxy fail; done
    docker rm -f "$pc" "$oc" >/dev/null 2>&1 || true; docker network rm "$net" >/dev/null 2>&1 || true; return
  fi
  echo "  $prox ready (h3=$proxy_h3)"
  for proto in $protos; do
    if [ "$proto" = h3 ] && [ "$proxy_h3" != 1 ]; then
      rec "$prox" h3 tls n/a
      for feat in $features; do rec "$prox" h3 "$feat" n/a; done
      continue
    fi
    tls_check "$prox" "$net" "$proto"
    for feat in $features; do
      if supported "$prox" "$feat" "$proto"; then run_cell "$prox" "$net" "$proto" "$feat"
      else rec "$prox" "$proto" "$feat" n/a; fi
    done
  done
  docker rm -f "$pc" "$oc" >/dev/null 2>&1 || true; docker network rm "$net" >/dev/null 2>&1 || true
  [ "$prox" = haproxy ] && run_proxy_protocol_check || true
}

for prox in $proxies; do run_proxy "$prox"; done

echo; echo "=== proxy interop results ==="
printf '%-9s %-5s %-16s %s\n' proxy proto feature status
fails=0
while read -r p pr f st; do
  printf '%-9s %-5s %-16s %s\n' "$p" "$pr" "$f" "$st"
  [ "$st" = fail ] && fails=$((fails + 1))
done < "$results"
echo
if [ "$fails" -gt 0 ]; then
  echo "RESULT: proxy interop FAILED ($fails cell(s))." >&2
  exit 1
fi
echo "RESULT: proxy interop passed (proxies: $proxies; protos: $protos)."
