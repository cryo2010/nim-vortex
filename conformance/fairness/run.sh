#!/usr/bin/env bash
# HTTP/2 write-scheduler fairness / tail-latency micro-benchmark (local, no Docker).
#
# Builds the stress server as a cleartext h2c binary, then drives it with h2load
# over ONE connection carrying many concurrent streams and reports the spread of
# per-request completion times. A fair per-connection write scheduler interleaves
# streams so equal-size responses finish close together (low p99/max/sd); draining
# one stream fully at a time staggers them (high spread). Run before and after a
# scheduler change and compare the `req-time` / `spread` columns.
#
# Env knobs (all optional):
#   FAIRNESS_PORT      h2c port                         (default 8399)
#   FAIRNESS_STREAMS   concurrent streams per conn (-m) (default 64)
#   FAIRNESS_REQUESTS  total requests (-n)              (default 512)
#   FAIRNESS_BYTES     /download body size, bytes       (default 2 MiB)
#   FAIRNESS_RUNTIME   sync|async|chronos (handler)     (default sync)
#   FAIRNESS_WINDOWS   ""  or e.g. "-w18 -W20" to constrain flow-control windows
#
# NOTE: on a fast loopback socket the gain may be modest -- this tool surfaces
# whatever it is, honestly. Constrain windows (FAIRNESS_WINDOWS) to make the
# scheduler's ordering matter more.
set -euo pipefail
cd "$(dirname "$0")/../.."                       # repo root

PORT="${FAIRNESS_PORT:-8399}"
M="${FAIRNESS_STREAMS:-64}"
N="${FAIRNESS_REQUESTS:-512}"
BYTES="${FAIRNESS_BYTES:-$((2*1024*1024))}"
RUNTIME="${FAIRNESS_RUNTIME:-sync}"
WINDOWS="${FAIRNESS_WINDOWS:-}"

command -v h2load >/dev/null || { echo "error: h2load not found (brew install nghttp2)"; exit 1; }

rtflag=""
case "$RUNTIME" in
  sync) ;;
  async) rtflag="-d:ltAsync" ;;
  async-await) rtflag="-d:ltAsyncAwait" ;;
  chronos) rtflag="-d:ltChronos"; nimble install -y chronos >/dev/null 2>&1 || true ;;
  chronos-await) rtflag="-d:ltChronosAwait"; nimble install -y chronos >/dev/null 2>&1 || true ;;
  *) echo "unknown FAIRNESS_RUNTIME=$RUNTIME"; exit 1 ;;
esac

bin="$(mktemp -d)/fairness_server"
json="$(mktemp)"
echo "building h2c stress server (runtime=$RUNTIME)..."
nim c --mm:orc --threads:on -d:plainHttp -d:danger $rtflag -p:src -o:"$bin" \
  conformance/stress/stress_server.nim >/dev/null

STREAM_BYTES="$BYTES" STRESS_PORT="$PORT" "$bin" >/dev/null 2>&1 &
srv=$!
trap 'kill -9 $srv 2>/dev/null || true' EXIT
sleep 1

base="http://127.0.0.1:$PORT"
echo "== fairness: -c1 -m$M -n$N, $((BYTES/1024/1024)) MiB/stream, runtime=$RUNTIME ${WINDOWS:+windows=$WINDOWS} =="

# Equal-size concurrent streams: the headline fairness signal (spread should shrink).
h2load -c1 -m"$M" -n"$N" $WINDOWS --output-file="$json" "$base/download" \
  >/dev/null 2>&1
python3 conformance/fairness/summarize.py "$json" "equal $((BYTES/1024/1024))MiB x$M"

# Mixed: small /plaintext interleaved with big /download on one connection -- how
# much does a big transfer delay small requests? (h2load cycles the URIs.)
h2load -c1 -m"$M" -n"$N" $WINDOWS --output-file="$json" \
  "$base/download" "$base/plaintext" "$base/plaintext" "$base/plaintext" \
  >/dev/null 2>&1
python3 conformance/fairness/summarize.py "$json" "mixed big+small x$M"
