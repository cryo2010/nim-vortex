#!/bin/sh
# Benchmark driver. Requires the server built via `nimble bench` and one of
# wrk / oha / ab on PATH. h2load (nghttp2) covers HTTP/2.
set -e
PORT="${PORT:-8080}"
URL="http://127.0.0.1:$PORT/plaintext"
DUR="${DUR:-10}"
CONNS="${CONNS:-128}"

echo "== target: $URL (${DUR}s, $CONNS connections)"
if command -v wrk >/dev/null; then
  wrk -t4 -c"$CONNS" -d"${DUR}s" "$URL"
elif command -v oha >/dev/null; then
  oha -z "${DUR}s" -c "$CONNS" --no-tui "$URL"
else
  ab -n 200000 -c "$CONNS" -k "$URL" | grep -E 'Requests per second|Failed'
fi

if command -v h2load >/dev/null; then
  echo "== HTTP/2 (h2c prior knowledge)"
  h2load -n 100000 -c 32 -m 16 "$URL"
fi
