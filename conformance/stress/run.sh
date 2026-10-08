#!/bin/sh
# Stress soak (pass/fail). Builds the vortex server (protocol × server-runtime)
# and a load client, drives the chosen workload (VORTEX_WORKLOAD) at the
# server for VORTEX_SECONDS, and verifies it: checksums and echoes **hard-fail**
# (the client's non-zero exit propagates out). Responses are discarded, so
# memory stays flat; the server's CPU/RSS is printed each
# VORTEX_REPORT_SECONDS. Not a CI gate (Docker, long runtimes, big transfers).
#
# The client is an axis too (VORTEX_CLIENT): the Python httpx/websockets/aioquic
# canary is the default and the interop reference, and the compiled Nim navi
# client is the alternative for the cells where the Python loop, not vortex, is
# the ceiling. Both verify the same contract and print the same line grammar.
#
# One workload per cell, except VORTEX_WORKLOAD=mixed, which drives all five at
# one server at the same time (see the client's w_mixed and VORTEX_MIX).
#
# Usage:  VORTEX_WORKLOAD=streamdownload sh conformance/stress/run.sh
#         (normally via `nimble stressRequests` / `stressWs` / `stressSse` /
#          `stressStreamUpload` / `stressStreamDownload` / `stressMixed`, or
#          `nimble stress`)
# Needs: docker.
#
# Env (mirrors nim-navi's NAVI_*):
#   VORTEX_WORKLOAD  requests | ws | sse | streamupload | streamdownload |
#                    mixed (all five at once)
#   VORTEX_MIX       mixed only: the worker split, e.g.
#                    requests=40,ws=20,sse=20,streamupload=10,streamdownload=10
#                    (the default); 0 drops a workload from the cell
#   VORTEX_PROTO     h1 | h2 | h3 | all           (default h2; all = h1 h2 h3)
#   VORTEX_SERVER    sync | async | async-await | chronos | chronos-await | all
#   VORTEX_CLIENT    python | navi | all          (default python; all runs
#                    every cell twice, python then navi)
#   VORTEX_NAVI_BACKEND  chronos | asyncdispatch  (default chronos). The
#                    navi client backend the image is BUILT with, so it is fixed
#                    per image, not per cell.
#   VORTEX_NAVI_REF  nim-navi git ref the navi client image is built from; empty
#                    uses the sha pinned in client/navi/Dockerfile. Pinned so a
#                    navi change cannot silently move vortex's numbers.
#   VORTEX_NAVI_COLLECT_SECONDS  how often the navi client forces an ORC cycle
#                    collection (default 1; 0 leaves it to the runtime, whose
#                    adaptive trigger stops firing in an async program and let
#                    an sse h1 cell reach 15 GB RSS). navi client only.
#   VORTEX_SECONDS / VORTEX_REPORT_SECONDS / VORTEX_CONCURRENCY / VORTEX_CLIENTS
#   VORTEX_REQ_COMPRESSION / VORTEX_RESP_COMPRESSION   none | gzip | br | zstd
#   VORTEX_STREAM_BYTES   streaming transfer size. Default 1 GiB for a run of
#                    VORTEX_SECONDS >= 1200, else 64 MiB: a 1 GiB h3 transfer
#                    takes ~125-163 s and cannot finish in a short smoke.
#                    `mixed` follows the same rule at its own measured sizes,
#                    16 MiB and 2 MiB, because its streaming slices share a
#                    client event loop with 30 request/ws/sse workers (see the
#                    sbytes block below). An explicit value always wins, and
#                    `nimble stress` inlines a per-cell smoke size.
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
#   VORTEX_CHAOS_GATE_SECONDS  how long to wait for the sidecar's fd baseline
#                    before giving up on the cell (default 180; see run_cell)
#   VORTEX_CHAOS_DRAIN_SECONDS how long to wait for the sidecar to exit after
#                    the canary passed (default 150; see run_cell)
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
# Which load client drives the cells. Case-insensitive like proto/server, so a
# stray capital cannot hard-exit a run before anything starts.
client=$(printf '%s' "${VORTEX_CLIENT:-python}" | tr 'A-Z' 'a-z')
navibackend=$(printf '%s' "${VORTEX_NAVI_BACKEND:-chronos}" | tr 'A-Z' 'a-z')
naviref="${VORTEX_NAVI_REF:-}"
# A git ref is one word of [A-Za-z0-9._/-]. It is spliced into a `docker build`
# argv below unquoted (an EMPTY ref must contribute no argument at all), so a
# value with a space would split into two words and a `*` would glob against
# the repo root -- either way docker dies with a usage error that names neither
# the knob nor the value. Reject anything else here, on stdout, exit 2.
case "$naviref" in
  *[!A-Za-z0-9._/-]*)
    echo "VORTEX_NAVI_REF must be a git ref ([A-Za-z0-9._/-]), got '$naviref'"
    exit 2 ;;
esac
# Validated HERE, before any docker build burns minutes on a run that will not
# produce the cells the operator asked for. On STDOUT with exit 2, the same
# reasoning as need_uint below: a config error on stderr never reaches the log.
case "$client" in
  python|navi|all) ;;
  *) echo "unknown VORTEX_CLIENT: $client (python | navi | all)"; exit 2 ;;
esac
case "$navibackend" in
  asyncdispatch|chronos) ;;
  *) echo "unknown VORTEX_NAVI_BACKEND: $navibackend (chronos | asyncdispatch)"
     exit 2 ;;
esac

# Reject a non-integer VORTEX_SECONDS / VORTEX_STREAM_BYTES HERE, before the
# `-lt` comparison and fmt_stream's `$(( ))` below reach it. Under `set -eu`
# both abort the script with a bare `arithmetic syntax error` / `bad number`
# from /bin/sh, naming neither the knob nor the value -- and `VORTEX_SECONDS=2h`
# (a perfectly natural way to write "two hours") is exactly the shape that
# produces it. Fail fast and say which knob, before any docker build burns
# minutes on a run that cannot size itself.
#
# The message goes to STDOUT, not stderr: the harness is driven as
# `nimble stress | tee stress.log`, which tees stdout only, so a config error on
# stderr never reaches the archived log and the run looks like it simply died
# (the same reason the clients print their causes on stdout -- #387).
need_uint() {
  case "$2" in
    ''|*[!0-9]*)
      echo "$1 must be a non-negative integer (got '$2')"
      exit 2 ;;
  esac
}
need_uint VORTEX_SECONDS "$seconds"
if [ -n "${VORTEX_STREAM_BYTES:-}" ]; then
  need_uint VORTEX_STREAM_BYTES "$VORTEX_STREAM_BYTES"
fi

# Streaming transfer size, used by streamupload / streamdownload / mixed. An
# explicit VORTEX_STREAM_BYTES ALWAYS wins; with none set the default is scaled
# by the run length, because the 1 GiB soak default cannot complete even ONE
# transfer in a short run. Measured: 125 s per transfer on streamupload h3 and
# 163 s on streamdownload h3, versus 4-15 s on h1/h2 (the only reason those
# cells ever passed). So `VORTEX_SECONDS=10 nimble stressStreamUpload` abandoned
# every transfer at the deadline, counted none, and reported
# `FAIL streamupload: no successful iterations` with nothing wrong on either
# side -- a sizing accident that reads as a server defect (#393).
#
# Counting iterations needs a comfortable MULTIPLE of one transfer time, not a
# bare one, so the threshold is 1200 s: about 7x the slowest measured h3
# transfer (163 s on streamdownload) on an IDLE host. The multiple is the whole
# point of the knob -- these soaks are deliberately run oversubscribed (the
# matrix fans 8+ cells at one host, where load averages of 20-50 are normal and
# a transfer takes several times its measured best), and a run that completes
# one or two transfers has measured almost nothing even when it technically
# passes. 300 s, the first cut at this, was 1.84x the measured worst case: under
# its own stated requirement, and an h3 cell at 1.5x host contention would still
# have failed on a size the harness chose for it. At or above 1200 s the default
# stays 1 GiB (a real soak, where the big transfer is the point); below it the
# default drops to 64 MiB, which is exactly what the `nimble stress` smoke has
# always passed explicitly and what passes on all three protocols in a 10 s
# cell.
#
# `mixed` follows the SAME duration rule at its own, much smaller pair of sizes.
# 64 MiB and 1 GiB are both far too big for it, because a mixed cell's streaming
# slices share ONE python event loop with 30 request/ws/sse workers that between
# them drive ~900 echoes/s, ~1900 ws messages/s and ~24000 SSE events/s. The
# download slice gets whatever loop time is left.
#
# MEASURED, h3 + sync server, 10 s, 3x32, chaos on, one upload and one download
# transfer in flight per client (3 each per cell):
#
#   size     up xfers   down xfers   download bytes moved
#   64 MiB      0           0            6.6 MB
#   32 MiB      0           0            6.2 MB
#   16 MiB      0           0            6.3 MB
#    8 MiB      0           0            5.9 MB
#    4 MiB      4           0            6.8 MB
#    2 MiB      6           3            PASS (6 MB, all verified)
#
# The download figure barely moves across a 32x range of body sizes: aggregate
# download throughput in a mixed h3 cell is ~0.6 MB/s over the three in-flight
# transfers, i.e. ~0.2 MB/s each, essentially INDEPENDENT of the body size. So
# the ceiling is per-stream bandwidth under a saturated client loop, not
# per-transfer overhead, and the largest body finishing inside a 10 s cell is
# 2 MiB (~10 s per download; uploads are ~2x faster, since aioquic buffers the
# body and the server drains it). For scale, the DEDICATED h3 download cell on
# the same host moves 42 MB/s -- ~70x -- so what mixed is short of is client
# loop time, not server or network. h1 and h2 are one to two orders of magnitude
# cheaper per transfer and pass far above this; h3 sets the default.
#
# The long default is 16 MiB, also measured: a 300 s h3 mixed cell completed 9
# downloads and 35 uploads, the downloads landing in three clean rounds of three
# at t=90s, t=181s and t=272s -- ~90 s per 16 MiB download (uploads ~25 s). That
# leaves ~13x margin at the 1200 s threshold, the same kind of comfortable
# multiple the 1 GiB/64 MiB pair gets, on a host that is routinely
# oversubscribed. 32 MiB extrapolates to ~180 s per download, under 7x; it
# clears the bar on paper and nothing else, so it is not the default. 1 GiB at
# this rate is ~90 MINUTES per transfer and is simply not a mixed size.
#
# A mixed cell is about the INTERACTION between the five workloads, and 16 MiB
# is a long transfer next to short requests and a real bulk buffer on the
# server's write path, which is what #394 was filed to exercise. For a
# bigger-transfer mixed soak set VORTEX_STREAM_BYTES explicitly and give it the
# seconds to match -- margin comes from VORTEX_SECONDS, not from a smaller body.
stream_long=1073741824          # 1 GiB: the real-soak default
stream_short=67108864           # 64 MiB: short-run default
stream_mixed_long=16777216      # 16 MiB: mixed, real soak (see above)
stream_mixed_short=2097152      # 2 MiB:  mixed, short run (see above)
stream_long_seconds=1200        # below this, 1 GiB leaves no margin on h3
if [ -n "${VORTEX_STREAM_BYTES:-}" ]; then
  sbytes="$VORTEX_STREAM_BYTES"
elif [ "$workload" = mixed ]; then
  if [ "$seconds" -lt "$stream_long_seconds" ]; then
    sbytes="$stream_mixed_short"
  else
    sbytes="$stream_mixed_long"
  fi
elif [ "$seconds" -lt "$stream_long_seconds" ]; then
  sbytes="$stream_short"
else
  sbytes="$stream_long"
fi
chaos=$(printf '%s' "${VORTEX_CHAOS:-all}" | tr 'A-Z' 'a-z')
chaosconc="${VORTEX_CHAOS_CONC:-8}"
chaosseed="${VORTEX_CHAOS_SEED:-1}"
# Chaos sidecar waits, in SECONDS (both loops poll every 0.1 s, so the tick
# counts below are seconds * 10). Named and defaulted here so the caps are
# explicit and overridable instead of buried as bare iteration counts.
#
# gate: how long the sidecar may take to print its fd baseline before we give up
# on the cell. This must cover chaos.py's whole pre-baseline prelude, which is
# NOT quick: warm_baseline() runs up to 10 rounds of VORTEX_CHAOS_WARMUP (64)
# CONCURRENT aborted /download connections, each round followed by a 2 s settle
# plus a 1 s inter-round gap, and the baseline sample then retries up to 10 times
# with a 1 s gap. On h3 each of those connections is a full QUIC handshake, so on
# a loaded host (many cells in parallel) the prelude can take minutes. The old
# 30 s cap was well under that budget and silently killed loaded h3 cells before
# they ran a single request -- lost coverage, not a vortex defect. 180 s clears
# the worst case (10 * (2 + 1) s warm-up + 10 * 1 s sampling + handshake time)
# with slack; exceeding it genuinely still fails the cell.
chaosgate="${VORTEX_CHAOS_GATE_SECONDS:-180}"
# drain: how long to wait for the sidecar to exit AFTER a passing canary, i.e.
# its own drain pause (up to 40 s on h3) plus its settle re-sampling (up to 60 s,
# see chaos.py's SETTLE) plus the final /stats fd sample, plus slack. On cap this
# is a watchdog fail (exit 3). The settle loop normally costs nothing here -- it
# exits on its first sample once the canary is gone, which is exactly when this
# wait begins -- so this cap is only ever approached by a GENUINE leak, where the
# count never comes down; it must clear DRAIN + SETTLE so that leak is reported
# as the leak it is (exit 1) rather than as a sidecar watchdog (exit 3).
chaosdrain="${VORTEX_CHAOS_DRAIN_SECONDS:-150}"

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

# The `stress` smoke runs every workload, short, and fails on any: the five
# single-workload cells plus `mixed`, which drives all five at one server at
# once. `mixed` is in the loop because it is the cell most likely to catch a
# regression the others miss (cross-workload interaction), and it costs one more
# short cell per matrix entry (#394).
#
# Each cell is re-exec'd with the PER-CELL smoke size inlined, and the rule is
# exactly this: the five single-workload cells run at $stream_short (64 MiB) at
# ANY duration, and the mixed cell at $stream_mixed_short, unless the CALLER set
# VORTEX_STREAM_BYTES, which wins everywhere as always (`${VAR:-default}` below,
# evaluated in this shell, so one explicit value still reaches every cell).
#
# 64 MiB at any duration is `nimble stress`'s historical behaviour, kept
# deliberately: the smoke's job is to prove every workload still works end to
# end, in minutes, and it is run at longer durations too (`VORTEX_SECONDS=600
# nimble stress`) without becoming a 1 GiB soak by accident. Letting each cell
# fall through to the duration-scaled default would do exactly that above
# $stream_long_seconds. The mixed cell cannot use 64 MiB at all (see the sbytes
# block above), which is why this is per cell rather than one exported value.
#
# The client images are kept ACROSS the six re-execs and removed once, here,
# when the smoke ends: each child is a full run.sh with its own EXIT trap, and
# left to itself every one of them would `docker rmi` the shared client tags on
# the way out and the next workload would rebuild them -- a cache hit under
# BuildKit, but under the legacy builder removing the tag drops the final
# compile layer too, and six navi compiles per smoke is the per-cell cost the
# build-once rule exists to avoid. The children see STRESS_SMOKE_KEEP_CLIENTS
# and leave the tags alone (see cleanup); the server image is still per cell
# (its flags change with the proto) and stays theirs to remove.
if [ "${STRESS_SMOKE:-0}" = "1" ]; then
  export STRESS_SMOKE_KEEP_CLIENTS=1
  smoke_cleanup() {
    docker rmi -f "vortex-stress-client-img-$id" "vortex-stress-navi-img-$id" \
      >/dev/null 2>&1 || true
  }
  trap smoke_cleanup EXIT INT TERM
  rc=0
  for w in requests ws sse streamupload streamdownload mixed; do
    case "$w" in
      mixed) wbytes="$stream_mixed_short" ;;
      *)     wbytes="$stream_short" ;;
    esac
    echo; echo "########## smoke: $w ##########"
    STRESS_SMOKE=0 VORTEX_WORKLOAD="$w" \
      VORTEX_STREAM_BYTES="${VORTEX_STREAM_BYTES:-$wbytes}" sh "$0" || rc=1
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
# Two client images, one tag each. They are not interchangeable: the python
# image is also the chaos sidecar's image (chaos.py is the misbehaving-CLIENT
# model and is client-independent by design), so a `navi` run with chaos on
# needs both tags, while a `navi` run with VORTEX_CHAOS=none builds no Python
# image at all. `$pimg` keeps the historical tag name so a python-only run is
# unchanged down to the resource names.
pimg=vortex-stress-client-img-$id
nimg=vortex-stress-navi-img-$id

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
  docker rmi -f "$simg" >/dev/null 2>&1 || true
  # Under `nimble stress` the parent smoke loop owns the client tags and removes
  # them once at the end (see the STRESS_SMOKE block), so six re-execs share
  # one build instead of each tearing it down for the next.
  if [ "${STRESS_SMOKE_KEEP_CLIENTS:-0}" != 1 ]; then
    docker rmi -f "$pimg" "$nimg" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

# Client image build phase. Built ONCE before the cell loop, as before: the
# navi image is about a minute with no cache (the -d:naviHttp3 compile itself
# 10-12 s), which is nothing per run and would dwarf a 10 s cell if paid per
# cell. Under `nimble stress` the tags also survive the per-workload re-execs
# (see the STRESS_SMOKE block), so a smoke builds each client image once.
need_python=0
need_navi=0
case "$client" in
  python) need_python=1 ;;
  navi)   need_navi=1 ;;
  all)    need_python=1; need_navi=1 ;;
esac
# The chaos sidecar runs `python chaos.py`, so the python image is needed
# whenever chaos is on, whichever client drives the canary.
if [ "$chaos" != "none" ]; then need_python=1; fi

if [ "$need_python" = 1 ]; then
  echo "building client image..."
  docker build -f "$here/client.Dockerfile" -t "$pimg" "$root" >/dev/null
fi
if [ "$need_navi" = 1 ]; then
  # An empty VORTEX_NAVI_REF means "use the sha pinned in the Dockerfile", so
  # the arg is only passed when it was actually set: passing NAVI_REF="" would
  # override the pin with nothing and fail the checkout.
  refarg=""
  if [ -n "$naviref" ]; then refarg="--build-arg NAVI_REF=$naviref"; fi
  echo "building client image (navi/$navibackend @ ${naviref:-pinned})..."
  docker build -f "$here/client/navi/Dockerfile" -t "$nimg" $basearg $refarg \
    --build-arg NAVI_BACKEND="$navibackend" "$root" >/dev/null
fi

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

# The stream size for the cell banner: MiB when it divides evenly, bytes
# otherwise. Printed so a log says which size the cell actually ran at --
# the size is now a default that depends on VORTEX_SECONDS and the workload
# (see the sbytes block above), so reading it back out of the log is the only
# way to tell a 64 MiB smoke from a 1 GiB soak after the fact (#393).
#
# Never emits an EMPTY segment: `stream=` with nothing after it would read as a
# harness bug in the one line that exists to record the size, and `$(( ))` on a
# non-integer would abort the cell outright under `set -eu`. need_uint above
# already rejects a bad VORTEX_STREAM_BYTES, so this arm is the belt to that
# braces -- it fires only if a future caller routes some other value here.
fmt_stream() {
  case "${1:-}" in
    ''|*[!0-9]*) echo "'${1:-}'(not a byte count)"; return ;;
  esac
  if [ "$1" = 0 ]; then echo "0B"
  elif [ $(( $1 % 1048576 )) = 0 ]; then echo "$(( $1 / 1048576 ))MiB"
  else echo "${1}B"
  fi
}

run_cell() {
  p="$1"; s="$2"; c="$3"
  proto_cfg "$p"; codec_flags
  # Which image the canary runs. The sidecar always runs the python image (see
  # the build phase above), so this is the only place the client axis reaches
  # into run_cell: nothing else about the cell -- readiness, the sidecar gate,
  # the canary-wins rule, the server-log dump, the teardown order -- branches on
  # it, because both clients present the same contract and the same exit codes.
  case "$c" in
    navi) canaryimg="$nimg"; cbanner=" client=navi/$navibackend" ;;
    # No `client=python` segment under python: the python log must stay
    # byte-identical to what it was before the client axis existed, so every
    # archived log and every watcher pattern keeps matching.
    *)    canaryimg="$pimg"; cbanner="" ;;
  esac
  compress=0; [ "$respc" != none ] && [ "$respc" != "" ] && compress=1
  bflags="$pflags$cflags${VORTEX_EXTRA_FLAGS:+ ${VORTEX_EXTRA_FLAGS}}"
  # Only the workloads that actually stream a transfer mention the size; on
  # `requests` / `ws` / `sse` it would be noise. Appended at the END of the
  # banner so anything matching the existing prefix still matches.
  sbanner=""
  case "$workload" in
    streamupload|streamdownload|mixed) sbanner=", stream=$(fmt_stream "$sbytes")" ;;
  esac
  echo
  echo "=== $workload [proto=$p server=$s$cbanner] : ${seconds}s, ${clients}x${conc}${sbanner} ==="

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
      -e VORTEX_STREAM_BYTES="$sbytes" "$pimg" python chaos.py >/dev/null
    # Wait for the sidecar's fd baseline so it is sampled before the canary
    # connects. chaos.py prints "chaos: baseline fds=N" once, before it starts
    # inducing chaos; cap at $chaosgate seconds (see the default above for why it
    # is minutes, not seconds), then give up on this cell.
    i=0
    gateticks=$((chaosgate * 10))
    until docker logs "$chc" 2>&1 | grep -q "chaos: baseline"; do
      i=$((i + 1))
      [ "$i" -gt "$gateticks" ] && { echo "chaos sidecar did not reach baseline within ${chaosgate}s" >&2; docker logs "$chc" 2>&1 || true; docker rm -f "$chc" >/dev/null 2>&1 || true; return 1; }
      sleep 0.1
    done
  fi

  # The client reports RSS/heap (from the server's /stats) and prints the
  # per-cell "== <workload> <server> <proto> passed ==" line on success.
  #
  # `2>&1` merges the client's stderr into the tee'd stream. The harness is run
  # as `nimble stress | tee stress.log`, which tees only stdout, so anything the
  # client wrote to stderr -- an interpreter traceback, an asyncio "Task
  # exception was never retrieved" notice -- never reached the archived log and a
  # cell died with nothing but a bare "FAILED (exit 1)" to show for it (#387).
  # The chaos sidecar is dumped via `docker logs "$chc" 2>&1` and never had the
  # gap; the canary was the only hole.
  set +e
  docker run --rm --network "$net" \
    -e VORTEX_WORKLOAD="$workload" -e VORTEX_PROTO="$p" -e STRESS_SERVER="$s" \
    -e STRESS_BASE="$scheme://server:$port" \
    -e VORTEX_SECONDS="$seconds" -e VORTEX_REPORT_SECONDS="$report" \
    -e VORTEX_CONCURRENCY="$conc" -e VORTEX_CLIENTS="$clients" \
    -e VORTEX_MIX="${VORTEX_MIX:-}" \
    -e VORTEX_NAVI_COLLECT_SECONDS="${VORTEX_NAVI_COLLECT_SECONDS:-}" \
    -e VORTEX_REQ_COMPRESSION="$reqc" -e VORTEX_RESP_COMPRESSION="$respc" \
    -e VORTEX_STREAM_BYTES="$sbytes" "$canaryimg" 2>&1
  crc=$?
  set -e

  # Wait for the chaos sidecar to finish and collect its verdict. It closes
  # everything and waits a drain pause (up to 40 s on h3) before its final
  # /stats fd sample, so the server must stay up until it exits -- hence the
  # server teardown below moves AFTER this wait. Cap at $chaosdrain seconds; on
  # cap, treat it as a watchdog fail (3).
  #
  # Whichever path we take, the sidecar's logs are dumped BEFORE the container is
  # removed: on the watchdog path the sidecar is still mid-soak, and removing it
  # first made `docker logs` print "No such container" and threw away the tally
  # that is the only record of what the sidecar did.
  xrc=0
  if [ "$chaos" != "none" ]; then
    if [ "$crc" != 0 ]; then
      # Canary already failed, and the canary wins: the sidecar's fd verdict is
      # not folded in (see below), so there is nothing to wait for. Keep its logs
      # as evidence, then stop it instead of burning the full drain wait.
      echo "--- chaos sidecar (canary failed; stopped mid-run) ---"
      docker logs "$chc" 2>&1 || true
      docker rm -f "$chc" >/dev/null 2>&1 || true
    else
      # Canary passed, so the sidecar's verdict counts: wait for its drain and
      # final fd sample, which is the whole fd-leak assertion.
      i=0
      drainticks=$((chaosdrain * 10))
      until [ "$(docker inspect -f '{{.State.Status}}' "$chc" 2>/dev/null)" != running ]; do
        i=$((i + 1))
        if [ "$i" -gt "$drainticks" ]; then
          echo "chaos sidecar still running after ${chaosdrain}s; giving up on its verdict" >&2
          xrc=3; break
        fi
        sleep 0.1
      done
      if [ "$xrc" = 0 ]; then xrc=$(docker inspect -f '{{.State.ExitCode}}' "$chc"); fi
      echo "--- chaos sidecar ---"
      docker logs "$chc" 2>&1 || true
      docker rm -f "$chc" >/dev/null 2>&1 || true
    fi
  fi

  # The server's stderr exists only inside its container, and `docker rm -f` is
  # a SIGKILL that takes the log with it. vortex writes its operator lines there
  # -- why the accept path dropped a connection, fd/memory exhaustion, a loop
  # thread that died -- and those are precisely what explains an empty
  # ConnectError at the client (#387, #388). On a failed cell, dump the tail
  # into the tee'd run log BEFORE the container goes away. Only on failure: a
  # clean hour-long cell would bury its own report lines.
  if [ "$crc" != 0 ]; then
    echo "--- server log (last 200 lines) ---"
    docker logs --tail 200 "$srvc" 2>&1 || true
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
# VORTEX_CLIENT=all runs every cell twice, python then navi. The client loop is
# the INNERMOST of the three so the two clients hit the same freshly-built server
# image back to back: that is the only arrangement in which a python/navi
# comparison is a comparison and not a measurement of two different builds on a
# differently-loaded host. The server image build is cached between them, so the
# second cell pays nothing for it.
case "$client" in all) clientlist="python navi" ;; *) clientlist="$client" ;; esac

rc=0
for p in $protos; do for s in $servers; do for c in $clientlist; do
  run_cell "$p" "$s" "$c" || rc=1
done; done; done

echo
[ "$rc" = 0 ] && echo "== $workload: all cells passed ==" \
              || echo "== $workload: FAILURES (see above) =="
exit "$rc"
