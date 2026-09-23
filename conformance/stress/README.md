# Stress soaks (per-workload, pass/fail)

Focused soak tests that drive **one workload** at a vortex server, sustained,
and **verify** it: streaming transfers are checksummed and any mismatch, echo
mismatch, non-2xx, or missing SSE event **hard-fails** (the client's non-zero
exit propagates out). Responses are discarded, so client and server memory stay
flat over a long run; the server's CPU/RSS is printed each report interval.

Each task builds the vortex server (a **protocol × server-runtime** matrix) plus
a small Python load client (`client/stress_client.py`, httpx + websockets) and
runs the chosen workload:

```sh
nimble stressRequests        # buffered typed GET/POST/PUT at /echo, with compression
nimble stressWs              # persistent WebSocket echo
nimble stressSse             # SSE subscribe; server drops mid-stream; reconnect + Last-Event-ID
nimble stressStreamUpload    # stream up; the server verifies the SHA-1 (400 on mismatch)
nimble stressStreamDownload  # stream down; the client verifies the SHA-1
nimble stress                # short smoke of all five (20 s, 64 MiB); fails on any
```

A green run ends with `== <workload>: all cells passed ==`.

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
| `VORTEX_SECONDS` | `60` | runtime per cell |
| `VORTEX_REPORT_SECONDS` | `60` | server CPU/RSS + tally report cadence |
| `VORTEX_CONCURRENCY` | `32` | in-flight requests per client (async fan-out) |
| `VORTEX_CLIENTS` | `3` | client workers per cell |
| `VORTEX_REQ_COMPRESSION` | `gzip` | `none` \| `gzip` \| `br` \| `zstd` - client encodes the request body; the server decompresses |
| `VORTEX_RESP_COMPRESSION` | `gzip` | `none` \| `gzip` \| `br` \| `zstd` - the server compresses the response |
| `VORTEX_STREAM_BYTES` | `1073741824` | streaming transfer size (1 GiB; lower for a smoke) |
| `VORTEX_RUN_ID` | this run's PID | isolation id for the docker network / container / image names, so runs can go **in parallel** |
| `VORTEX_CHAOS` | `all` | `none` \| `all` \| CSV of `slowread,slowwrite,idle,abort,vanish` - launches an **unverified misbehaving** sidecar client per cell (see [Chaos sidecar](#chaos-sidecar)); `none` = no sidecar (and no drain pause), the pre-chaos behavior |
| `VORTEX_CHAOS_CONC` | `8` | chaos sidecar worker count |
| `VORTEX_CHAOS_SEED` | `1` | per-worker seeded RNG for reproducible chaos schedules |

The matrix is `VORTEX_PROTO` × `VORTEX_SERVER`; each cell builds its own server
image and prints `== <workload> [proto=<p> server=<s>]: PASS/FAIL ==`.

Runs are isolated by `VORTEX_RUN_ID` (defaults to the PID), so several can run
concurrently without clobbering each other's containers/images, e.g.

```sh
VORTEX_RUN_ID=a VORTEX_PROTO=h1 nimble stress &
VORTEX_RUN_ID=b VORTEX_PROTO=h2 nimble stress &
```

Each run tears down its own network + image tags on exit (shared build-cache
layers survive). Note: many concurrent runs contend for the host, so the
throughput-sensitive streaming/h2 cells may slow down or time out.

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
```

## HTTP/3

`VORTEX_PROTO=h3` drives the server's QUIC listener with **aioquic** (httpx has
no h3). All five workloads - `requests`, `ws` (RFC 9220 Extended CONNECT),
`sse`, `streamdownload`, and `streamupload` - run over h3. vortex acks HTTP/3
request-body flow control: `deliverBody` auto-acks the QUIC stream/connection
windows as the handler reads the body, and any bytes received but never read are
credited back to the connection window when the stream tears down, so a large h3
upload flows without stalling.

`VORTEX_PROTO=all` includes h3 (h1 + h2 + h3). h3 cells reuse the same server
image as h2 (only the `STRESS_HTTP3` runtime toggle differs), so the extra cost
is one client run per cell, not another build.

### Protocol pinning

Each run is pinned to exactly the requested wire protocol and **cannot fall
back**. h3 uses aioquic with ALPN locked to `h3` (a different transport from
h1/h2, so there is no TCP fallback), and the client asserts h3 was actually
negotiated. For h1/h2 the client verifies every response's negotiated version
(`HTTP/1.1` for `h1`, `HTTP/2` for `h2`) and hard-fails on a mismatch, so an
`h2` run can never quietly measure an `h1` connection.

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

## Gaps

- On Docker Desktop the `docker stats` RSS reflects the shared Linux VM; read it
  as a trend, not an absolute host number.
- Not a CI gate (Docker, long runtimes, 1 GiB transfers). Pass/fail makes a short
  CI smoke possible later.

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
