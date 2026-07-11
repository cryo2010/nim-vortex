#!/bin/sh
# WebSocket protocol conformance via the Autobahn|Testsuite.
#
# Builds a vortex echo server image, runs it, and points the
# crossbario/autobahn-testsuite fuzzingclient at it over a private docker
# network. Exits non-zero if any executed case reports a failing behavior.
# Compression cases (12-13) are excluded until permessage-deflate lands
# (see the WebSocket roadmap in the README).
#
# Usage:  sh conformance/autobahn/run.sh        (or `nimble autobahn`)
# Needs: docker + python3. The full HTML report lands in
# conformance/autobahn/reports/index.html.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)
net=vortex-autobahn
srvc=vortex-autobahn-server
img=vortex-autobahn-echo

if [ "$(uname -m)" = "x86_64" ]; then
  basearg="--build-arg BASE=archlinux:latest"
else
  basearg=""
fi

echo "building echo server image..."
docker build -f "$here/Dockerfile" -t "$img" $basearg "$root"

cleanup() {
  docker rm -f "$srvc" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
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
echo "echo server up on the docker network"

rm -rf "$here/reports"; mkdir -p "$here/reports"
echo "running autobahn fuzzingclient (this takes a few minutes)..."
docker run --rm --network "$net" \
  -v "$here/fuzzingclient.json:/fuzzingclient.json:ro" \
  -v "$here/reports:/reports" \
  crossbario/autobahn-testsuite \
  wstest -m fuzzingclient -s /fuzzingclient.json

echo
python3 - "$here/reports/index.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
agent = next(iter(data.values())) if data else {}
def num(c): return tuple(int(x) for x in c.split("."))
bad = []
for case in sorted(agent, key=num):
    b = agent[case].get("behavior")
    bc = agent[case].get("behaviorClose")
    if b in ("FAILED", "WRONG CODE") or bc in ("FAILED", "WRONG CODE"):
        bad.append((case, b, bc))
print(f"{len(agent)} cases run, {len(bad)} failing "
      f"(compression cases 12-13 excluded)")
for case, b, bc in bad:
    print(f"  FAIL {case}: behavior={b} close={bc}")
sys.exit(1 if bad else 0)
PY

echo
echo "RESULT: no failing cases. Full report:"
echo "        conformance/autobahn/reports/index.html"
