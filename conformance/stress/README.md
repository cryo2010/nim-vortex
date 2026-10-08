# Stress soaks (pass/fail)

Focused soak tests that drive **one workload** at a vortex server, sustained,
and **verify** it: streaming transfers are checksummed and any mismatch, echo
mismatch, non-2xx, or missing SSE event **hard-fails** (the client's non-zero
exit propagates out). Responses are discarded, so client and server memory stay
flat over a long run; the server's CPU/RSS is printed each report interval.
`stressMixed` is the exception: it drives **all five workloads at one server at
the same time** (see [The mixed soak](#the-mixed-soak)).

Each task builds the vortex server (a **protocol × server-runtime** matrix) plus
a load client and runs the chosen workload:

```sh
nimble stressRequests        # buffered typed GET/POST/PUT at /echo, with compression
nimble stressWs              # persistent WebSocket echo
nimble stressSse             # SSE subscribe; server drops mid-stream; reconnect + Last-Event-ID
nimble stressStreamUpload    # stream up; the server verifies the SHA-1 (400 on mismatch)
nimble stressStreamDownload  # stream down; the client verifies the SHA-1
nimble stressMixed           # all five of the above at ONE server, concurrently
nimble stress                # short smoke of all six (20 s); fails on any
```

A green run ends with `== <workload>: all cells passed ==`.

The **client is an axis too** (`VORTEX_CLIENT`). The default is the small Python
canary (`client/stress_client.py`, httpx + websockets + aioquic), which is also
the harness's interop reference; `VORTEX_CLIENT=navi` swaps in a compiled Nim
client built on [navi](https://github.com/cryo2010/nim-navi)
(`client/navi/stress_navi.nim`) for the cells where the Python event loop, not
vortex, is the ceiling. Both verify the same contract and print the same lines,
so a watcher written against one works on the other unchanged - see
[Choosing the client](#choosing-the-client).

The `requests` and `methods` workloads drive a **typed payload mix** at `/echo`
(text, JSON object + array, urlencoded + multipart form data, binary, XML, CSV,
HTML), cycled per iteration. Each body is request-compressed and carries its
`Content-Type`; the server decompresses it and echoes both back, and the client
verifies the **body bytes and the `Content-Type` round-trip** verbatim (multipart
boundary included). Each iteration also GETs a typed route (`/plaintext`,
`/json`, `/html`, `/xml`, `/csv`, `/binary`) and asserts its `Content-Type` and
exact body. The sizes cover the 0-length / 1-byte framing paths, the sub-1400 B
no-compress threshold, the compressible large branch per type, and the
incompressible store-fallback.

## Configuration (mirrors nim-navi's `NAVI_*`)

| Var | Default | Meaning |
|-----|---------|---------|
| `VORTEX_PROTO` | `h2` | `h1` \| `h2` \| `h3` \| `all` (`all` = h1 + h2 + h3) |
| `VORTEX_SERVER` | `sync` | `sync` \| `async` \| `async-await` \| `chronos` \| `chronos-await` \| `all` - the handler runtime; `chronos` = `vortex/chronos`, `async` = `vortex/asyncdispatch` |
| `VORTEX_CLIENT` | `python` | `python` \| `navi` \| `all` - which load client drives the cells. `python` = the httpx + websockets + aioquic canary, the default and the interop reference; `navi` = the compiled Nim client; `all` runs every cell **twice**, python then navi. See [Choosing the client](#choosing-the-client) |
| `VORTEX_NAVI_BACKEND` | `chronos` | `chronos` \| `asyncdispatch` - the navi client backend the binary is **built** against (`-d:useChronos` selects `import navi/chronos`). A docker build arg, so it is fixed per image, not per cell |
| `VORTEX_NAVI_REF` | the sha pinned in `client/navi/Dockerfile` (nim-navi `62244a8`) | nim-navi ref the navi client image is built from; empty keeps the pin. Pinned so a navi change cannot silently move vortex's numbers - bump it deliberately and re-run the soaks. Pass a **sha**: a branch or tag name is frozen by the docker build cache at its first build on that host |
| `VORTEX_SECONDS` | `60` | runtime per cell |
| `VORTEX_REPORT_SECONDS` | `60` | server CPU/RSS + tally report cadence |
| `VORTEX_CONCURRENCY` | `32` | in-flight requests per client (async fan-out); under `mixed`, the per-client worker budget that is **split** across the five workloads, and it must be at least the number of workloads in the mix (5 by default) - a smaller value is refused with exit 2 |
| `VORTEX_CLIENTS` | `3` | client workers per cell |
| `VORTEX_REQ_COMPRESSION` | `gzip` | `none` \| `gzip` \| `br` \| `zstd` - client encodes the request body; the server decompresses |
| `VORTEX_RESP_COMPRESSION` | `gzip` | `none` \| `gzip` \| `br` \| `zstd` - the server compresses the response |
| `VORTEX_STREAM_BYTES` | `1073741824`, or `67108864` under 1200 s; `mixed`: `16777216`, or `2097152` under 1200 s | streaming transfer size: 1 GiB for a real soak and 64 MiB for a short run, and the same rule at 16 MiB / 2 MiB for `mixed` - see [Sizing a short streaming smoke](#sizing-a-short-streaming-smoke) and [Sizing a mixed cell](#sizing-a-mixed-cell). An explicit value always wins; `nimble stress` inlines a per-cell smoke size |
| `VORTEX_MIX` | `requests=40,ws=20,sse=20,streamupload=10,streamdownload=10` | `mixed` only: how the worker budget splits across the five workloads. Weights, normalized by the sum of the weights that compete for the same workers; `0` drops a workload. For `streamupload`/`streamdownload` the weight is **presence-only** (they are fixed at one transfer in flight per client) - see [The mixed soak](#the-mixed-soak) |
| `VORTEX_RUN_ID` | this run's PID | isolation id for the docker network / container / image names, so runs can go **in parallel** |
| `VORTEX_CHAOS` | `all` | `none` \| `all` \| CSV of `slowread,slowwrite,idle,abort,vanish` - launches an **unverified misbehaving** sidecar client per cell (see [Chaos sidecar](#chaos-sidecar)); `none` = no sidecar (and no drain pause), the pre-chaos behavior |
| `VORTEX_CHAOS_CONC` | `8` | chaos sidecar worker count |
| `VORTEX_CHAOS_SEED` | `1` | per-worker seeded RNG for reproducible chaos schedules |
| `VORTEX_CHAOS_GATE_SECONDS` | `180` | how long a cell waits for the sidecar's `chaos: baseline fds=N` line before giving up on the cell (the pre-baseline warm-up is minutes on a loaded h3 host) |
| `VORTEX_CHAOS_DRAIN_SECONDS` | `150` | how long a cell waits for the sidecar to exit after a passing canary (its drain pause plus its settle re-sampling); on cap the cell fails as a watchdog (exit 3) |

The matrix is `VORTEX_PROTO` × `VORTEX_SERVER` (× `VORTEX_CLIENT` when that is
`all`); each cell builds its own server image and prints three kinds of line - a
banner on the way in, a per-cell verdict on the way out, and one run verdict at
the end:

```
=== streamdownload [proto=h3 server=sync] : 20s, 3x32, stream=64MiB ===
== streamdownload sync h3 passed (7 transfers) ==
== streamdownload sync h3 FAILED (exit 1) ==
== streamdownload: all cells passed ==
```

The banner carries the duration, `VORTEX_CLIENTS`x`VORTEX_CONCURRENCY`, and
(streaming workloads and `mixed` only) the transfer size the cell resolved. Under
`VORTEX_CLIENT=navi` it carries a third bracket token naming the client and the
backend its image was built against, and nothing else about the line changes:

```
=== requests [proto=h2 server=sync client=navi/chronos] : 10s, 3x32 ===
```

There is deliberately no `client=python` token: a python log stays byte-identical
to what it was before the client axis existed, so every archived log and every
watcher pattern keeps matching.

The per-cell line is `== <workload> <server> <proto> passed (<tally>) ==` from
the client, or `== <workload> <server> <proto> FAILED (exit N) ==` from `run.sh`;
a chaos-only failure on an otherwise-green cell adds
`== <workload> <server> <proto> chaos sidecar FAILED (exit N) ==`. The run ends
with `== <workload>: all cells passed ==` or `== <workload>: FAILURES (see
above) ==` (and `== stress smoke: ... ==` under `nimble stress`). Match those
exact forms in a watcher; there is no `PASS/FAIL` word in any of them.

Capture a soak with `nimble stress | tee stress.log`: `tee` takes stdout only,
so every line that explains a verdict is on stdout, the client containers'
stderr included (`run.sh` merges it, and the clients print a `FAIL <workload>:
<cause>` line with its traceback rather than letting the interpreter put one on
stderr). A cell that fails with nothing but `FAILED (exit N)` in the log is a
harness bug, not a soak to re-run blind.

Runs are isolated by `VORTEX_RUN_ID` (defaults to the PID), so several can run
concurrently without clobbering each other's containers/images, e.g.

```sh
VORTEX_RUN_ID=a VORTEX_PROTO=h1 nimble stress &
VORTEX_RUN_ID=b VORTEX_PROTO=h2 nimble stress &
```

Each run tears down its own network + image tags on exit (shared build-cache
layers survive). Note: many concurrent runs contend for the host, so the
throughput-sensitive streaming/h2 cells may slow down or time out.

### The client images

There are two, one per client, each built **once** per run before the cell loop
and torn down with the run's other image tags. Which ones a run builds follows
from `VORTEX_CLIENT` and `VORTEX_CHAOS`: the chaos sidecar is `chaos.py` and runs
from the **python** image whichever client drives the canary, so a navi run with
chaos on builds both, and `VORTEX_CLIENT=navi VORTEX_CHAOS=none` builds no Python
image at all.

**Python (`client.Dockerfile`).** It **pins** every client library (httpx,
httpcore, anyio, h2, websockets, brotli, zstandard, aioquic) with `==`. A soak is
a measurement, and a floating client silently changes what is being measured:
#390 was a teardown race inside httpcore/anyio that failed a cell roughly one run
in three, and reproducing it meant knowing which versions that day's rebuild had
resolved to. Bump the pins deliberately, and re-run the soaks when you do.

**navi (`client/navi/Dockerfile`).** Same reasoning, same discipline: Arch base
(the bench client image's, which already proves `-d:naviHttp3` links against
Arch's `libngtcp2` / `libnghttp3` / `openssl` packages with no from-source
toolchain) and nim-navi **pinned by sha**, `62244a8` at the time of writing,
overridable per run with `VORTEX_NAVI_REF`. The bench client installs navi latest
instead, and that is exactly what made its numbers move under it: nim-navi #401
doubled its download throughput between two rebuilds of an unchanged Dockerfile.

navi is used from a `git clone` + `git checkout --detach $NAVI_REF` **worktree**
reached with `--path:/navi/src`, not from `nimble install navi@#<sha>`. That is a
navi **packaging gap**, not a preference: navi's package spec ships `.nim` and
`.cpp` but not the HTTP/3 driver's own `h3client.h`, so the installed package's
`h3client.cpp` cannot find its header and a `-d:naviHttp3` build fails at the C++
step. A worktree is the only way to build an h3 client from a pinned ref today,
and it is the stricter pin anyway. Reported as nim-navi #465.

The binary is compiled in the image, once per run and never per cell, with
`-d:release` plus `--stackTrace:on --stackTraceMsgs:on --lineTrace:on
--debugger:native` - **not** `-d:danger`, which is what the bench client uses,
and **not** `--panics:on`, which the server's soak profile does use. This client
is a verifier, so a crash has to say where it died, and it prints its own trace
on **stdout** because stderr is not teed (#387); with `--panics:on` a Defect
would be fatal at the raise site, on stderr only, and never reach the client's
own `FAIL <workload>: unexpected ...` line. All three codecs are always linked,
with exactly `run.sh`'s `codec_flags` defines and link flags, so the client
compresses request bodies with vortex's own encoders and links what the server
links. One binary serves all three protocols (it reads `VORTEX_PROTO` at run
time), so the image is built once per run rather than once per proto. Measured
on a 14-cpu arm64 host, the whole image is about a minute with `--no-cache`, of
which the `-d:naviHttp3` compile is 10-12 s; with the package layer cached a
rebuild is the clone plus the compile. The compile layer depends only on the six
codec modules it imports, not on the whole of `src/`, so a server change does
not rebuild the client. Under `nimble stress` the client tags survive the six
per-workload re-execs and are removed once at the end, so a smoke builds each
client image once. `VORTEX_NAVI_BACKEND` selects `chronos` (the default) or `asyncdispatch`
at **build** time. Pass `VORTEX_NAVI_REF` a **sha**: the clone is one docker
layer keyed on the value, so a branch or tag name is frozen by the build cache
at whatever it pointed to the first time it was built on that host.

### Transfers at the deadline

`streamupload` and `streamdownload` do one whole transfer per iteration, and a
1 GiB transfer can outlive the run, so the last one is **abandoned** at the
deadline rather than waited out: it is neither verified nor counted, and the
cell's verdict rests on the transfers that did complete. Abandoning a transfer
tears a connection down with a request still in flight, which is a path httpx
does not always unwind cleanly (#390: anyio calls `transport.abort()` after
asyncio already cleared the transport's loop, raising
`AttributeError: 'NoneType' object has no attribute 'call_soon'`). The client
treats that teardown artifact as the deadline expiry it is, but **only past the
deadline** - before it, the same error still hard-fails the cell.

### Sizing a short streaming smoke

A transfer that cannot finish inside `VORTEX_SECONDS` is never counted, so a
cell whose transfers are all too big completes **zero** iterations and fails -
with nothing wrong on either side. Measured per 1 GiB transfer, at the **Python
client** (the default; see [Choosing the client](#choosing-the-client) for why
the client is part of the figure on h3):

| Workload | h1 / h2 | h3 (aioquic) |
|----------|---------|--------------|
| `streamupload` | 4-15 s | ~125 s |
| `streamdownload` | 4-15 s | ~163 s |

The same two h3 cells at the **navi client**, same host, 60 s at 64 MiB, python
then navi back to back on one server image:

| Cell (h3, 64 MiB, 60 s) | python (aioquic) | navi |
|-------------------------|------------------|------|
| `streamupload` | 69 transfers, 74 MB/s | 410 transfers, 437 MB/s |
| `streamdownload` | 39 transfers, 42 MB/s | 228 transfers, 245 MB/s |

Scaled to 1 GiB that is roughly **2.5 s per upload and 4.4 s per download under
navi** against 125 s and 163 s under python: on h3 the Python figures above are
statements about aioquic far more than about vortex.

So `VORTEX_SECONDS=10 nimble stressStreamUpload` at the 1 GiB soak default
passed h1 and h2 and failed h3 every time with `no successful iterations`
(#393) - the h1/h2 cells only passed because their transfers happen to be two
orders of magnitude faster.

`run.sh` therefore **scales the default**: with no `VORTEX_STREAM_BYTES` set it
uses 1 GiB for a run of **1200 s** or more and **64 MiB** below that (the size
`nimble stress` has always passed for its smoke cells, and the size that passes
on all three protocols in a 10 s cell). The default and its 1200 s threshold are
deliberately **client-agnostic**: they were measured at the Python client, which
is the slower of the two on h3 and therefore the binding constraint, so a navi
cell inherits a size it can only finish with more margin (the navi table above
puts a 1 GiB h3 transfer at seconds, not minutes). A client-aware default is a
follow-up, not part of this change; set `VORTEX_STREAM_BYTES` explicitly if you
want a navi cell to move more bytes.
Counting iterations needs a comfortable
*multiple* of one transfer, not a bare one, so the threshold is about **7x** the
slowest measured h3 transfer: these soaks are deliberately run oversubscribed -
the matrix fans eight or more cells at one host, load averages of 20-50 are
normal, and a transfer then takes several times its measured best. A run that
completes one or two transfers has measured almost nothing even when it passes.
(The first cut at this was 300 s, 1.84x the measured worst case: under its own
stated requirement, and an h3 cell at 1.5x contention would still have failed on
a size the harness chose for it.) An explicit `VORTEX_STREAM_BYTES` always wins,
and the size each cell ran at is printed in its banner (`stream=64MiB`).

If you do override it and the run is too short for even one transfer, the client
says so instead of printing the generic message - and it distinguishes that from
a server that simply delivered nothing, using the bytes that actually moved:

```
FAIL streamdownload: no transfer of 1073741824 bytes completed within 10 s on h3
(3 abandoned at the deadline, 402653184 bytes moved); the transfers are too big
for this run: lower VORTEX_STREAM_BYTES or raise VORTEX_SECONDS

FAIL streamdownload: no transfer of 67108864 bytes completed within 20 s on h2
(3 abandoned at the deadline, 0 bytes moved): the server delivered nothing, a
stall rather than a sizing problem; check the server log
```

An abandoned transfer on its own proves nothing - a wedged server abandons at
the deadline exactly like an oversized transfer does - so the discriminator is
the byte count, which is in the message either way. The one case the Python
client cannot decide is an **h3 upload** with zero bytes moved: aioquic buffers
the whole body up front, so that workload counts bytes only on completion and a
transfer in flight looks identical to one that never moved. There the message
names both possibilities rather than guessing. That arm does **not** apply under
`VORTEX_CLIENT=navi`: navi streams the request body, so the client counts bytes
as its producer hands them over and its diagnosis is always the decidable one,
on h3 as on h1/h2.

Any of them is still a **failure** (exit 1), not a skip: a soak that verified
zero bytes must not read as a pass.

### Sizing a mixed cell

A `mixed` cell follows the **same duration rule** at its own, much smaller pair
of sizes: **16 MiB** at 1200 s or more, **2 MiB** below that. Its streaming
slices run one transfer in flight per client, but they share one Python event
loop with 30 request/ws/sse workers that between them drive about 900 echoes/s,
1900 WebSocket messages/s and 24000 SSE events/s. The download slice gets
whatever loop time is left.

Measured at the **Python client**, h3 + sync server, 10 s, `3x32`, chaos on
(3 upload and 3 download transfers in flight per cell):

| Size | up xfers | down xfers | download bytes moved |
|------|----------|------------|----------------------|
| 64 MiB | 0 | 0 | 6.6 MB |
| 32 MiB | 0 | 0 | 6.2 MB |
| 16 MiB | 0 | 0 | 6.3 MB |
| 8 MiB | 0 | 0 | 5.9 MB |
| 4 MiB | 4 | 0 | 6.8 MB |
| **2 MiB** | **6** | **3** | **PASS** (6 MB, all verified) |

The download figure barely moves across a 32x range of body sizes: aggregate
download throughput in a mixed h3 cell is about 0.6 MB/s over the three
in-flight transfers, roughly **0.2 MB/s each, independent of the body size**. So
the ceiling is per-stream bandwidth under a saturated client loop, not
per-transfer overhead, and the largest body that finishes inside a 10 s cell is
2 MiB (about 10 s per download; uploads are roughly twice as fast, since aioquic
buffers the body and the server drains it). For scale, the *dedicated* h3
download cell on the same host moves **42 MB/s**, about 70x: what a mixed cell
is short of is client loop time, not server or network. h1 and h2 are one to two
orders of magnitude cheaper per transfer and pass far above this - h3 sets the
default.

The same table at the **navi client** (h3 + sync server, 10 s, `3x32`, chaos
off, the full five-slice mix, one upload and one download in flight per client):

| Size | up xfers | down xfers | download bytes moved |
|------|----------|------------|----------------------|
| 64 MiB | 14 | 0 | 161 MB, **FAIL** (sizing: `the transfers are too big for this run`) |
| 32 MiB | 23 | 3 | 96 MB |
| 16 MiB | 35 | 9 | 144 MB |
| 8 MiB | 65 | 18 | 144 MB |
| 4 MiB | 89 | 36 | 144 MB |
| 2 MiB | 111 | 63 | 126 MB |

The shape is the same and the level is about **24x** higher: aggregate mixed h3
download is ~14 MB/s under navi (roughly 4.8 MB/s per in-flight transfer, again
nearly independent of the body size) against ~0.6 MB/s under python, and it is
still ~17x below the dedicated navi download cell's 245 MB/s. So a mixed cell is
client-loop-bound under navi too, just at a far higher ceiling: the 16 MiB long
default completes nine downloads in 10 s where python completes none, and the
largest body that finishes in a 10 s navi cell is 32 MiB, not 2 MiB. The 64 MiB
row is the sizing diagnosis doing its job (161 MB moved, nothing completed), not
a defect.

The long default is measured too. A 300 s h3 mixed cell completed **9 downloads
and 35 uploads**, the downloads landing in three clean rounds of three at
`t=90s`, `t=181s` and `t=272s`: about **90 s per 16 MiB download** (uploads are
about 25 s, roughly 3.5x faster, for the reason above). That leaves roughly **13x
margin** at the 1200 s threshold - the same kind of comfortable multiple the
1 GiB / 64 MiB pair gets, on a host that is routinely oversubscribed. 32 MiB
extrapolates to about 180 s per download, under 7x: it clears the bar on paper
and nothing else, so it is not the default. 1 GiB at this rate is about
**90 minutes** per transfer and is simply not a mixed size.

16 MiB is still a long transfer running next to short requests and a real bulk
buffer on the server's write path, which is the interaction `mixed` exists to
exercise. For a bigger-transfer mixed soak set `VORTEX_STREAM_BYTES` explicitly
and give it the seconds to match: margin comes from `VORTEX_SECONDS`, not from a
smaller body.

Every figure in this section apart from the navi table is a **Python-client**
figure, and the whole of it is a statement about a saturated client event loop
rather than about vortex. The `mixed` defaults are nevertheless kept
client-agnostic, for the same reason as the single-workload pair above: the
Python client is the default and the slower peer, so a size it can finish is a
size navi finishes with room to spare (nine 16 MiB downloads in 10 s where python
completes none). A navi-aware default (16 MiB short, something larger long) is a
reasonable follow-up now that the table exists; it is not part of this change.

## Choosing the client

`VORTEX_CLIENT` picks which load client drives the cells. Both clients verify the
same contract - the same typed payload catalogue, the same echo and `Content-Type`
round-trip, the same download SHA-1, the same SSE id order and 20-event batches,
the same upload 200-vs-400 - and both hard-fail on the first defect. What differs
is what each one is *evidence of*.

**`python` (the default) is the interop reference.** A green run proves vortex
serves a widely deployed third-party client stack under sustained load: httpx +
h2 + websockets + aioquic, none of it ours, each with its own reading of the
specs. It is also the harness's **only non-ngtcp2 QUIC implementation**. Keep it
as the client of record, and reach for it first when a failure needs a second
opinion.

**`navi` is for throughput, for h3 under a fast peer, and for a second
implementation.** The Python client is one asyncio loop per container behind the
GIL with QUIC crypto and framing done in Python, so on the hot cells the harness
measures aioquic at least as much as it measures vortex (the sizing tables above
are mostly statements about that loop). It also brings its own failure modes into
the log as vortex failures: #390 was a teardown race inside httpcore/anyio that
failed a healthy cell one run in three, and the client's loop watchdog exists
because a wedged Python loop trips the server's idle timeout and reads as a
server stall. navi is compiled, streams its request bodies, and is an independent
HTTP/1.1, HTTP/2, HTTP/3, WebSocket and SSE implementation with its own HPACK, h2
framing and flow control, so where the two clients agree a vortex pass means
more.

Measured, 60 s cells against the sync server, chaos off, python then navi back
to back on one server image on one host (`VORTEX_CLIENT=all`):

| Cell | python | navi | ratio |
|------|--------|------|-------|
| `requests` h2 | 130464 req, 2108 req/s | 673968 req, 11327 req/s | 5.2x |
| `streamdownload` h3, 64 MiB | 39 transfers, 42 MB/s | 228 transfers, 245 MB/s | 5.8x |
| `streamupload` h3, 64 MiB | 69 transfers, 74 MB/s | 410 transfers, 437 MB/s | 5.9x |

That is the first measurement of how much of the harness's h3 numbers was
aioquic: most of them. These are one-minute cells on a shared host - quote them
as the reason a navi cell is worth running, never as vortex's throughput (for
that use `nimble saturate` or `nimble bench`).

**The caveat that matters.** vortex and navi share an author, conventions and the
ngtcp2 + nghttp3 QUIC stack. A cell that passes **only** under navi is not
interop evidence, and a navi h3 pass is not foreign-stack evidence at all: on h3
it is ngtcp2 + nghttp3 talking to ngtcp2 + nghttp3. That is precisely why python
stays the default and why aioquic stays in the harness.

**Triage is two-ended.** A failure under navi has two suspects. Re-run the cell
with `VORTEX_CLIENT=python` first. If it passes there, reproduce the failing
request against the vortex stress server with `curl`, `h2load` or the Python
client **before** touching vortex; if only navi can produce it, file it in
nim-navi with that reproduction and either pin `VORTEX_NAVI_REF` past the fix or
record the cell as blocked on it. The rule runs the other way too: a vortex
defect found by the navi client is reproduced with a second client before it is
filed here.

**The grammar is identical.** The navi client prints the same lines in the same
forms on stdout: the three-token `[<workload> <proto> <server>]` report prefix,
the `final ` line, `== <workload> <server> <proto> passed (<tally>) ==`,
`FAIL <workload>: <cause> (<codes>)`, a config error on stdout with exit 2, and
the exit codes 0 / 1 / 2. The prefix gained no fourth token on purpose, so every
existing `grep` keeps working. The client is named in two places instead: the
cell banner's `client=navi/<backend>` segment, and one header line the binary
prints before anything else, naming the navi build the numbers came from.

```
client: navi/chronos 62244a8b24e38e5d3ec8f25fc38c01eaab5a1c52
```

The one line the navi client prints that the Python one does not is its **own
footprint**, next to every report line and once more after the final one:

```
client: rss 83MB heap 31MB fds 8 t=20s
```

The report line's `RSS` / `heap` / `fds` stay the **server's**, byte for byte, so
watchers keep matching; this is a separate line under the same `client:` prefix
as the header. It exists because of what a 30-minute h3 `mixed` soak looked like
without it: `== mixed chronos h3 FAILED (exit 137) ==` and nothing else. The
kernel had OOM-killed the client container (a SIGKILL prints no `FAIL` line and
leaves no trace), and the only memory in the log was the server's, flat at
114 MB. `rss` is what the OOM killer sees; `heap` (the live Nim heap) beside it
says whether a growth is this program's or the C side's.

**Client memory and the backend default.** That OOM was navi's asyncdispatch
backend, not vortex and not a leak in the usual sense: its total-timeout guard
races a request against `sleepAsync(totalMs)` and never clears the timer when
the request wins, so a completed request stays reachable, response and buffers
included, until the timer fires (nim-navi #468). The memory is therefore
*request rate x timeout window*: a 60 s `requests` client plateaued at ~750 MB
RSS (the Python client holds 95 MB on the same cell), and a download client
whose timer was the time left in the run pinned every transfer's buffers until
the run ended, ~1.1 MB per 64 MiB transfer, 87 to 543 MB of live heap in 120 s,
and the OOM at t=529 s of the soak. `GC_fullCollect` did nothing (reachable, not
cyclic), response compression made no difference, and uploads were flat (their
request state is tiny). The chronos guard cancels its timer and the same
download cell on chronos oscillated between 31 and 147 MB of heap. So
`VORTEX_NAVI_BACKEND` defaults to **`chronos`**, downloads carry no total
timeout at all on either backend (the per-chunk deadline check is their abandon
mechanism), and an `asyncdispatch` build is still available with that caveat,
visible on the `client:` line.

The second thing that line found is the Nim runtime's, not navi's, and it is
why the client forces an ORC cycle collection every second
(`VORTEX_NAVI_COLLECT_SECONDS`, default 1; 0 leaves it to the runtime). ORC
triggers its cycle collector on a root-count threshold that grows by 1.5x every
time a collection frees less than half of what it touched, and in an async
program the roots are mostly live futures, so every collection looks
ineffective, the threshold climbs without bound and the collector effectively
stops. The garbage is collectable: an `sse` h1 cell at ~16k short streams a
second swung between 35 MB and 12.8 GB of live heap and reached **15 GB RSS in
120 s**, and the request-shaped `mixed` h3 mix reached 4.4 GB, both freed
whenever a collection did run. With one explicit collection a second the full
h3 mix holds at ~200 MB RSS with a steady heap for the whole cell. Watch the
`client:` line on any long navi cell; a rising `heap` that never turns over is
the thing to report.

`VORTEX_REQ_COMPRESSION` and `VORTEX_RESP_COMPRESSION` mean exactly what they
mean under python, so there is no skip notice to look for: navi adds its default
`accept-encoding` only when the caller supplied none, and an explicit
`content-type` on a string body survives untouched, multipart boundary included.
Both were confirmed against navi's request builder before the catalogue was
ported. The navi client also runs with **retries and redirects off** - navi
retries 5xx by default, which would mask exactly the failures a soak exists to
catch, and httpx has no retries.

Everything else keeps its meaning: `VORTEX_PROTO`, `VORTEX_SERVER`,
`VORTEX_SECONDS`, `VORTEX_CLIENTS`, `VORTEX_CONCURRENCY`, `VORTEX_STREAM_BYTES`
and its duration rule, `VORTEX_MIX`, `VORTEX_RUN_ID` and the chaos knobs are all
client-independent, and the server image, its build flags and its `STRESS_*`
environment are untouched. **Chaos is unaffected too**: `chaos.py` is the
misbehaving-*client* model and is client-independent by design, so the sidecar
stays Python beside a navi canary - which is why a navi run with chaos on still
builds the Python image (see [The client images](#the-client-images)).

`VORTEX_CLIENT=all` runs every cell twice, python then navi, with the client as
the **innermost** loop so both hit the same freshly built server image back to
back. That is the only arrangement in which a python-vs-navi comparison is a
comparison rather than a measurement of two builds on a differently loaded host.
It doubles the cell count, so it is a deliberate choice, not a default. Note that
the two cells' verdict lines are textually identical (there is no client token
in them, by design); attribute a tally by the cell banner above it, or by the
`client: navi/...` header line that only the navi cell prints.

Two smaller differences worth knowing when reading a navi log. The streaming
workloads open a fresh client per transfer, as the Python canary opens a session
per transfer, which on h3 costs navi one extra Alt-Svc discovery leg per
transfer (navi learns h3 per client; aioquic dials QUIC directly). The `sse`
workload drives `api.stream` and parses the `text/event-stream` framing itself
rather than using navi's `sse()`, because that API builds a private client with
a cold Alt-Svc cache and cannot yield a pinned h3 stream without transparent
reconnect (nim-navi #466); the Python canary reads the raw stream too, so both
clients verify the same framing. And the `methods` workload is python-only: it exists for the reverse-proxy interop suite
(`conformance/proxy`), which builds the Python image itself, and is not part of
the stress matrix.

## The mixed soak

`nimble stressMixed` is the one soak that drives **all five verified workloads
at one server process at the same time**. The per-workload soaks cannot see
interactions between workloads, and that is where several recent fixes lived or
nearly lived: loop-thread starvation and deadline credit (#386) only shows when
a long transfer and short requests compete for the same loop; QUIC idle reap and
h3 keep-alive (#386, #389) behave differently when an idle SSE stream sits next
to a busy upload; h2 flow-control fairness needs one connection carrying a bulk
stream plus many small `/echo` streams. The chaos sidecar has always generated
cross-workload traffic, but it is **unverified by design** - it swallows its
errors and asserts only the fd count - so nothing checked the bytes under
heterogeneous load.

**The split.** A mixed cell runs the same `VORTEX_CLIENTS × VORTEX_CONCURRENCY`
workers as any other cell; they are *split* across the five workloads rather
than each workload getting the lot, so a mixed cell is not a five-times-heavier
cell. The two kinds of slice are allocated differently:

- **The streaming slices are fixed at one worker each** when present, i.e. one
  whole transfer in flight per client, which is exactly what the dedicated
  `stressStreamUpload` / `stressStreamDownload` soaks run (they take their
  parallelism from `VORTEX_CLIENTS`, not from `VORTEX_CONCURRENCY`). Their
  `VORTEX_MIX` weight is therefore **presence-only**: any value `> 0` runs the
  slice, `0` drops it.
- **The request-shaped slices split the rest.** `requests`, `ws` and `sse`
  share `VORTEX_CONCURRENCY` minus one per streaming slice present, by their
  weights (40/20/20 by default, normalized by the sum of just those three),
  allocated by largest remainder so the rounding loss is spread. At the default
  `3x32` that is **15/8/7/1/1** per client. `requests` takes the bulk because
  its workers are the cheapest and its `/echo` + typed-GET path is what every
  other route competes with.

Each request-shaped slice also gets **at least one** worker, taken out of the
largest allocation, because a slice with zero workers would drive nothing and
then fail the cell's own per-slice progress check. And a `VORTEX_CONCURRENCY`
below the number of slices in the mix is **refused** (exit 2, on stdout) rather
than overshot: a mixed cell must neither drop a slice, which would claim
coverage it does not have, nor quietly run wider than it was told to.

The first version of this gave each streaming slice a *tenth* of
`VORTEX_CONCURRENCY`, which is 3 + 3 per client and 9 + 9 per cell at `3x32`:
three times the dedicated soaks' parallelism, and the reason the mixed transfer
size had to drop to 2 MiB at *every* duration. A 2 MiB body is neither of the
interactions the mixed soak exists to find (a long transfer running beside short
requests; a bulk buffer competing for the server's write path), so that
allocation bought nine small transfers at the cost of the thing under test. One
transfer in flight per client, at a size the duration can actually finish, keeps
both.

`VORTEX_MIX` overrides it:

```sh
# SSE-heavy mix: the request-shaped share becomes 10/10/60, i.e. 4/4/22 of the
# 30 workers left after the two streaming slices
VORTEX_MIX=requests=10,ws=10,sse=60 nimble stressMixed

# requests + the two streaming routes only (0 drops a workload from the cell)
VORTEX_MIX=ws=0,sse=0 nimble stressMixed

# no streaming at all: the whole budget goes to requests/ws/sse (16/8/8)
VORTEX_MIX=streamupload=0,streamdownload=0 nimble stressMixed
```

The values are **weights, normalized by the sum of the weights that compete for
the same workers** - not percentages. `VORTEX_MIX=requests=100` does not mean
"100%": `ws` and `sse` keep their defaults, so the request-shaped split becomes
100/20/20, and at `3x32` the 30 workers left over go 22/4/4. They need not add
to 100 (the defaults do, because a reader expects them to). An omitted workload
keeps its default; an explicit `0` drops it, and it is not checked for progress
either. A repeated key is **rejected** (the later value would silently win), as
is any non-integer weight. A malformed `VORTEX_MIX` exits 2 rather than running
something other than what was asked for.

**Connections.** Each slice opens connections exactly as its single-workload
soak does: the streaming slices open their own session per transfer, the
`requests`/`sse` slices hold one per worker, the `ws` slice one socket per
worker. So this is all five workloads at one **server**, not down one
connection - the existing behaviour and the more interesting case.

**Verdict.** "No successful iterations" is checked **per workload**, never on
the sum, so a stalled SSE feed cannot hide behind a healthy `/echo` counter;
every dead slice is named. Any workload hitting a real defect fails the cell
exactly as it would alone (`FAIL mixed: <cause>`, exit 1). The report line keeps
the usual `[mixed <proto> <server>]` prefix and lists each workload instead of a
headline rate:

```
[mixed h3 sync] 200x245807 | req 8820 (+340/s) | ws 17378 msgs (+803/s) | sse 219600 ev (+10052/s) | up 6 xfers 12MB (+0) | down 3 xfers 6.0MB (+3) | RSS 188MB | heap 1MB | fds 60 | t=11s
== mixed sync h3 passed (req 8820 | ws 17378 msgs | sse 219600 ev | up 6 xfers 12MB | down 3 xfers 6.0MB) ==
```

(Real lines, from a 10 s h3 cell against the sync server at the 2 MiB short-run
default.) Each slice carries a **per-interval delta** next to its cumulative
tally - a rate for the request-shaped slices, a raw count for the streaming
ones, where a mixed cell completes single digits and `(+0)` is the thing worth
seeing. A cumulative count only ever goes up, so without the delta a slice that
died at `t=30s` reads as a healthy five-figure total for the rest of the run.
The pass banner keeps the cumulative figures only.

There is deliberately no "stalled for N intervals" verdict on top of the delta.
A wedged slice does not merely stop counting: it blocks the mixed supervisor's
`gather`, the cell overruns the client's `deadline + 60 s` safety net, and that
already fails the run as the stall it is - exactly as for the five
single-workload soaks.

The streaming slices report completed transfers and the bytes those verified; a
partial transfer is never counted, so the byte figure is exactly what moved and
was checksummed. A hard failure (`FAIL mixed: <cause>`) ends the cell before the
final report line, so it appends the per-slice tallies in brackets - the record
of which slices were healthy and which were already dead when the defect hit.

`nimble stress` runs `mixed` as a **sixth** short cell per matrix entry. It
costs one more ~20 s cell and it is the cell most likely to catch a regression
the other five miss.

The smoke sizes its cells **individually**, and the rule is exactly this: the
five single-workload cells run at **64 MiB at any smoke duration**, the mixed
cell at its own 2 MiB short default, and an explicit `VORTEX_STREAM_BYTES` from
the caller still wins everywhere. 64 MiB regardless of duration is
`nimble stress`'s historical behaviour, kept deliberately - the smoke's job is
to prove every workload still works end to end, in minutes, and
`VORTEX_SECONDS=1800 nimble stress` must not silently become a 1 GiB soak.
Letting each cell fall through to the duration-scaled default would do exactly
that above 1200 s; pinning one value for the whole smoke, which is what the task
used to do, applied 64 MiB to the mixed cell too, which cannot finish a transfer
that size. Hence per cell, inlined on each re-exec.

## Examples

```sh
# Quick local check of the download checksum path (8 MiB, 5 s)
VORTEX_STREAM_BYTES=8388608 VORTEX_SECONDS=5 nimble stressStreamDownload

# Exercise the chronos server's WebSocket path under load (the parity soak)
VORTEX_SERVER=chronos nimble stressWs

# Sweep sync/async/chronos for streamed downloads
VORTEX_SERVER=all VORTEX_STREAM_BYTES=8388608 VORTEX_SECONDS=5 nimble stressStreamDownload

# Requests over both protocols with brotli response compression
VORTEX_PROTO=all VORTEX_RESP_COMPRESSION=br nimble stressRequests

# Short streaming smoke over every protocol: no VORTEX_STREAM_BYTES, so the
# 64 MiB short-run default applies and the h3 cell can finish a transfer
VORTEX_PROTO=all VORTEX_SECONDS=10 VORTEX_REPORT_SECONDS=2 nimble stressStreamUpload

# All five workloads at one chronos server for an hour, every protocol. 3600 s
# is past the long-run threshold, so the mixed cells run at their 16 MiB soak
# default rather than the 2 MiB short one
VORTEX_PROTO=all VORTEX_SERVER=chronos VORTEX_SECONDS=3600 nimble stressMixed

# vortex's h3 bytes under a peer that is not the bottleneck: the compiled navi
# client, which streams its request bodies and does QUIC in C rather than Python
VORTEX_CLIENT=navi VORTEX_PROTO=h3 VORTEX_SECONDS=60 nimble stressStreamUpload

# The same cell twice, python then navi, back to back on one server image: the
# only honest way to compare the two clients (and the chronos-backed navi image,
# which is a build-time choice, so this run builds its own)
VORTEX_CLIENT=all VORTEX_NAVI_BACKEND=chronos VORTEX_SECONDS=60 nimble stressRequests
```

## HTTP/3

`VORTEX_PROTO=h3` drives the server's QUIC listener with **aioquic** (httpx has
no h3). All five workloads - `requests`, `ws` (RFC 9220 Extended CONNECT),
`sse`, `streamdownload`, and `streamupload` - run over h3, and so does `mixed`
(all five at once on one QUIC-speaking server). vortex acks HTTP/3
request-body flow control: `deliverBody` auto-acks the QUIC stream/connection
windows as the handler reads the body, and any bytes received but never read are
credited back to the connection window when the stream tears down, so a large h3
upload flows without stalling.

`VORTEX_PROTO=all` includes h3 (h1 + h2 + h3). h3 cells reuse the same server
image as h2 (only the `STRESS_HTTP3` runtime toggle differs), so the extra cost
is one client run per cell, not another build.

Under `VORTEX_CLIENT=navi` an h3 cell is **ngtcp2 + nghttp3 on both ends**: navi
builds on the same QUIC and HTTP/3 libraries vortex does. That is what makes it a
fast h3 peer, and it is also what makes a navi h3 pass worthless as foreign-stack
evidence - aioquic is the harness's only QUIC implementation that is not ngtcp2,
which is one of the reasons python stays the default (see
[Choosing the client](#choosing-the-client)).

### Protocol pinning

Each run is pinned to exactly the requested wire protocol and **cannot fall
back**. h3 uses aioquic with ALPN locked to `h3` (a different transport from
h1/h2, so there is no TCP fallback), and the client asserts h3 was actually
negotiated. For h1/h2 the client verifies every response's negotiated version
(`HTTP/1.1` for `h1`, `HTTP/2` for `h2`) and hard-fails on a mismatch, so an
`h2` run can never quietly measure an `h1` connection.

The navi client pins the same way and checks the same thing: `config.http` is set
to exactly `{H1}`, `{H2}` or `{H3}` for the cell, and **every** response's
`httpVersion` is asserted against the expected string, with the same wording in
the failure. The pin alone is only half the check, because navi reaches HTTP/3 by
upgrading on the origin's `Alt-Svc: h3` and that one bootstrap request is exempt
from the set; so an h3 cell runs a discovery leg at `/plaintext` first and fails
the cell outright if the connection never upgrades, rather than measuring h2
under an h3 banner.

## Chaos sidecar

The verified client is well-behaved by design: it never reads slowly, idles,
aborts mid-transfer, or vanishes, so the server's teardown, backpressure, and
reaping paths carry no load. `VORTEX_CHAOS` adds an **unverified** second client
(`client/chaos.py`) per cell that misbehaves on purpose while the verified
client keeps running unchanged as the **canary**. Behaviors come in two forms,
uniformly weighted in the per-iteration pick pool: the five **generic** styles
below (the fixed all-routes catalog - `/download`, `/upload`, `/ws`, `/sse`,
`/plaintext` - in every cell) plus **workload-targeted** variants selected by
the cell's `VORTEX_WORKLOAD`, so each soak's own protocol paths get targeted
abuse (slow/idle/vanishing SSE clients under `sse`, half-closing WebSocket
clients under `ws`, ...). Enabling a style enables both forms; a style with no
targeted form for the workload just runs generic.

The sidecar is **Python regardless of `VORTEX_CLIENT`**: `chaos.py` models a
misbehaving *client*, which is client-independent by design, so it runs unchanged
from the python image beside a navi canary - and a navi run with chaos on
therefore builds both client images (see
[The client images](#the-client-images)).

**Canary wins.** run.sh consults the sidecar's exit code only when the verified
client passed, so chaos can add a failure but never mask one. A chaos failure on
an otherwise-green cell prints `== <workload> <server> <proto> chaos sidecar
FAILED (exit N) ==`.

The five behaviors (each iteration picks timings from the seeded RNG):

- `slowread` - stream `/download` (sometimes `/sse`), read a chunk, sleep, clean close: write-scheduler stalls and slow-consumer fairness.
- `slowwrite` - `POST /upload` with a wrong `x-sha1`, drip-feed small chunks with sleeps (the 400 is expected and swallowed): long-held streaming request state.
- `idle` - open a WS or keep-alive connection, do nothing for 10-30 s, clean close: keep-alive slot occupancy, ping path, QUIC idle-timeout straddling.
- `abort` - read part of `/download` then cancel cleanly (h2 RST_STREAM; h3 STOP_SENDING), sometimes abort an upload mid-generator: mid-transfer cancellation cleanup.
- `vanish` - abrupt death with no goodbye (h1/h2 `SO_LINGER=0` TCP RST; h3 dropped UDP transport, reaped via idle timeout): abrupt-peer-death cleanup and fd reclamation.

The workload-targeted variants (tally keys `workload:style`, printed next to the
bare generic keys - e.g. `ok: vanish=6 sse:vanish=4 ...` in the report line):

| Workload | Variant | What it does |
|----------|---------|--------------|
| ws | `ws:slowread` | burst echoes, then stop reading the replies for seconds so the server's echo write side backs up |
| ws | `ws:abort` | clean CLOSE frame mid-echo-burst |
| ws | `ws:vanish` | no close handshake: TCP transport abort (h1/h2) / dropped UDP transport (h3) |
| sse | `sse:slowread` | consume events at a crawl until the server batch-closes |
| sse | `sse:idle` | open the stream, read nothing for 10-30 s (server stalls mid-batch), clean close |
| sse | `sse:abort` | drop mid-batch, resume with a garbage `Last-Event-ID` (the server's parseInt-fallback path) |
| sse | `sse:vanish` | mid-stream RST / dropped transport on `/sse` |
| streamupload | `streamupload:slowwrite` | stall-resume: chunks, 5-10 s of dead air mid-body, resume, finish |
| streamupload | `streamupload:vanish` | die mid-request-body: h1 partial-body RST; h3 dropped transport; h2 cancel+abandon |
| streamdownload | `streamdownload:idle` | established download, zero consumption for 10-30 s, clean close |

`requests` has no targeted variants (the generic catalog was designed around
it); `idle@ws` and `abort@streamupload` are intentionally absent, subsumed by
generic `idle`'s ws hold and generic `abort`'s mid-body generator raise.

Under `mixed` the sidecar runs **every** targeted variant of each enabled style,
not one: the canary has WebSocket, SSE, upload and download traffic live
simultaneously, so a generic-only pool would leave the mixed cell with less
route-specific abuse than any single-workload cell. The pool is still built in a
fixed order, so a given `VORTEX_CHAOS_SEED` replays the same schedule.

**Exit codes** (run.sh folds a nonzero code into the cell only when the canary passed):

| Code | Meaning |
|------|---------|
| `0` | ran, connected at least once, fd assertion passed (induced errors tallied + swallowed) |
| `1` | fd leak (`final > baseline + 8`) |
| `2` | internal error / unknown behavior name / missing fd field in `/stats` |
| `3` | self-watchdog fired (also what run.sh reports if the sidecar never exits within its poll cap) |
| `4` | never connected once (must not pass silently) |

**fd-leak assertion.** `/stats` exposes an open-fd count (from `/proc/self/fd`).
The sidecar samples a **baseline before the canary launches** (run.sh waits for
the `chaos: baseline fds=N` log line before starting the verified client),
induces chaos, closes everything, waits a drain pause (15 s; **40 s on h3** to
outlive the 30 s QUIC idle timeout), samples again, and fails on `final >
baseline + slack` where `slack = 8` (a calibrated constant, not a knob).

Two details keep that assertion from measuring the *canary* instead of the
server. The sidecar's `SECONDS` of chaos is timed from the **baseline**, not from
its own process start, because run.sh gates the canary on the baseline line -- so
the two clocks agree to within the canary's launch lag. (Timing it from process
start charged the pre-baseline prelude, up to ~50 s of `warm_baseline`, against
the chaos window, which both under-delivered chaos *and* put the final sample
inside the canary's still-running window: its `CLIENTS*CONC` live sockets then
read as leaked descriptors, e.g. `baseline 61, final 157` = 61 + 96.) And the
final sample **re-samples while the count is still above the threshold**, for up
to 60 s, so the canary's tail drains before the verdict; a leaked descriptor is
never reclaimed, so waiting can only clear a false failure, never hide a real
one.

**Degraded modes.** h3 `slowread` and `ws:slowread` are pacing-only: aioquic
grants flow-control credit on receipt (and the h3 client queues unread frames
locally, unbounded), so neither can exert true backpressure. h2 `vanish` and
`ws:vanish` fall back to abandoning the connection without a clean close when
the raw socket / transport is not reachable for `SO_LINGER=0` / `.abort()`.
h2 `streamupload:vanish` is cancel+abandon by construction (the response object
does not exist mid-request-body, so the socket is unreachable there).

Chaos runs on every cell by default. For a chaos-free run (no sidecar, no
drain pause):

```sh
VORTEX_CHAOS=none nimble stress
```

## Diagnosing a connection that just died (`/drops`)

At the client, a connection the server refused after accepting it is
indistinguishable from a network fault: the socket opens, dies with nothing on
it, and httpx reports an empty `ConnectError`. A 1-hour soak lost a cell to
exactly that, 90 s in, with nothing anywhere saying which (#388). The stress
server therefore exposes vortex's accept-path counters on its own route:

```sh
curl -s http://localhost:8080/drops
cap=0 tls=0 register=0 total=0 acceptSuspend=0
```

| Field | Meaning |
|-------|---------|
| `cap` | `maxConnections` was reached on that loop thread; the connection was accepted and closed at once |
| `tls` | the TLS session could not be created |
| `register` | the selector refused the accepted fd |
| `total` | `cap + tls + register`: every connection accepted and then dropped |
| `acceptSuspend` | `accept()` itself failed on fd/memory exhaustion and the listener backed off for ~1s. Nothing was accepted, so this is **not** in `total`; it counts backoffs, and it means the container is out of descriptors |

Each is process-wide and monotonic, so compare two samples rather than reading
one. The same numbers also go to the server's stderr: one rate-limited `vortex:`
line per cause per 5 s per loop thread, saying which cap, which OpenSSL reason,
which selector message.

Two things to know about it:

- **Nothing polls `/drops` automatically.** Neither the verified client nor the
  chaos sidecar touches it (and it is deliberately a separate route from
  `/stats`, which the client parses as exactly three fields). It is there for
  you to `curl` while a soak runs, or to read out of the log afterwards.
- **A failed cell dumps the server log for you.** `run.sh` prints
  `--- server log (last 200 lines) ---` followed by `docker logs --tail 200` of
  the server container before tearing it down, but only when the cell failed (a
  clean hour-long cell would bury its own report lines). That tail is where the
  `vortex:` lines live, because the container's stderr goes away with it:
  teardown is `docker rm -f`, a SIGKILL, so the server's own
  "accept drops: ..." print on SIGTERM never runs under `run.sh`. It is there
  for hand runs of the binary.

## Gaps

- On Docker Desktop the `docker stats` RSS reflects the shared Linux VM; read it
  as a trend, not an absolute host number.
- Not a CI gate (Docker, long runtimes, 1 GiB transfers). Pass/fail makes a short
  CI smoke possible later.
- The `mixed` cell splits one cell's worker budget, so each workload runs at a
  fraction of the rate its own soak reaches - the streaming slices most of all,
  at one transfer in flight per client against a saturated client event loop
  (0.6 MB/s on h3 where the dedicated download cell does 42 MB/s). It exists to
  find cross-workload interactions, not to measure any one workload's
  throughput; keep the per-workload soaks for that, and read a mixed cell's
  transfer counts as "did the bytes verify", not as a rate.

## The interactive saturation tool (`nimble saturate`)

The former `nimble stress` - an h2load saturation with a live Grafana/Prometheus
dashboard (server CPU/RSS + achieved req/s) - is preserved as
`conformance/stress/saturate.sh` / `nimble saturate`. Use it to *watch* a run;
use the soaks above to *verify* correctness under sustained load.

```sh
nimble saturate                      # BACKEND=h1 by default; Grafana on :3001
BACKEND=all DURATION=60 nimble saturate
sh conformance/stress/saturate.sh --down   # stop the stack
```
