#!/bin/sh
# Manual HTTP conformance check: point REDbot (https://redbot.org) at a
# live vortex server and surface any protocol problems it finds.
#
# Usage:   sh conformance/run.sh [path ...]        (default: / /json)
#          PORT=8123 sh conformance/run.sh
#
# Requires REDbot on PATH (`pipx install redbot`) and curl. REDbot marks
# findings by severity with colour: BAD is red, WARN yellow, INFO/GOOD
# blue/green. This script forces colour through a pty so it can count the
# red (BAD) findings and exit non-zero when any appear; WARN/INFO items
# are advisory and printed for you to read. The full colourised report
# for each URL is also saved under conformance/reports/.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
port=${PORT:-8099}
set -- ${@:-/ /json}

# --- REDbot present? --------------------------------------------------------
if command -v redbot >/dev/null 2>&1; then
  redbot="redbot"
elif python3 -c "import redbot" >/dev/null 2>&1; then
  redbot="python3 -m redbot.cli"
else
  echo "REDbot not found. Install it with:  pipx install redbot" >&2
  echo "(see https://github.com/mnot/redbot)" >&2
  exit 127
fi

# --- build + start the server under test ------------------------------------
bin="$here/redbot_server"
echo "building conformance server..."
nim c --mm:orc --threads:on -d:release -o:"$bin" "$here/redbot_server.nim" \
  >/dev/null

"$bin" "$port" &
srv=$!
trap 'kill "$srv" 2>/dev/null || true' EXIT INT TERM

i=0
until curl -sf -o /dev/null "http://127.0.0.1:$port/"; do
  i=$((i + 1))
  [ "$i" -gt 50 ] && { echo "server did not come up on port $port" >&2; exit 1; }
  sleep 0.1
done
echo "server up on http://127.0.0.1:$port/"

# --- run REDbot against each path -------------------------------------------
mkdir -p "$here/reports"
esc=$(printf '\033')
fail=0
pybin=$(command -v python3 || true)

runpty() {   # runpty <outfile> <cmd...>: capture <cmd> to <outfile>, forcing
             # a pty so REDbot colourises (its severity is colour-only, no
             # text label). python3 is always present because REDbot is
             # Python; if pty allocation fails we fall back to a plain run
             # (report shown, but the BAD/WARN counts below read as 0).
  out=$1; shift
  if [ -n "$pybin" ]; then
    "$pybin" -c 'import pty,sys; pty.spawn(sys.argv[1:])' "$@" >"$out" 2>&1 ||
      "$@" >"$out" 2>&1 || true
  else
    "$@" >"$out" 2>&1 || true
  fi
}

for path in "$@"; do
  url="http://127.0.0.1:$port$path"
  name=$(printf '%s' "$path" | tr -c 'A-Za-z0-9' '_'); [ -n "$name" ] || name=root
  report="$here/reports/$name.txt"

  echo
  echo "=== REDbot: $url ==="
  runpty "$report" $redbot "$url" || true
  cat "$report"

  bad=$(grep -c "${esc}\[1;31m" "$report" 2>/dev/null || true); bad=${bad:-0}
  warn=$(grep -c "${esc}\[1;33m" "$report" 2>/dev/null || true); warn=${warn:-0}
  echo "--- $url: ${bad} BAD, ${warn} WARN (approx, from severity colours)"
  [ "$bad" -gt 0 ] && fail=1 || true
done

echo
if [ "$fail" -ne 0 ]; then
  echo "RESULT: REDbot reported BAD-level findings (red items above). See"
  echo "        conformance/reports/ for the full reports."
  exit 1
fi
echo "RESULT: no BAD-level findings. WARN/INFO items are advisory (e.g. a"
echo "        low-level server leaves compression/ranges to the app)."
