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
nimble stressRequests        # buffered GET/POST/PUT at /echo, with compression
nimble stressWs              # persistent WebSocket echo
nimble stressSse             # SSE subscribe; server drops mid-stream; reconnect + Last-Event-ID
nimble stressStreamUpload    # stream up; the server verifies the SHA-1 (400 on mismatch)
nimble stressStreamDownload  # stream down; the client verifies the SHA-1
nimble stress                # short smoke of all five (20 s, 64 MiB); fails on any
```

A green run ends with `== <workload>: all cells passed ==`.

## Configuration (mirrors nim-navi's `NAVI_*`)

| Var | Default | Meaning |
|-----|---------|---------|
| `VORTEX_PROTO` | `h2` | `h1` \| `h2` \| `h3` \| `all` (`all` = h1 + h2; h3 opt-in) |
| `VORTEX_SERVER` | `sync` | `sync` \| `async` \| `async-await` \| `chronos` \| `chronos-await` \| `all` - the handler runtime; `chronos` = `vortex/chronos`, `async` = `vortex/asyncdispatch` |
| `VORTEX_SECONDS` | `60` | runtime per cell |
| `VORTEX_REPORT_SECONDS` | `60` | server CPU/RSS + tally report cadence |
| `VORTEX_CONCURRENCY` | `32` | in-flight requests per client (async fan-out) |
| `VORTEX_CLIENTS` | `3` | client workers per cell |
| `VORTEX_REQ_COMPRESSION` | `gzip` | `none` \| `gzip` \| `br` \| `zstd` - client encodes the request body; the server decompresses |
| `VORTEX_RESP_COMPRESSION` | `gzip` | `none` \| `gzip` \| `br` \| `zstd` - the server compresses the response |
| `VORTEX_STREAM_BYTES` | `1073741824` | streaming transfer size (1 GiB; lower for a smoke) |

The matrix is `VORTEX_PROTO` × `VORTEX_SERVER`; each cell builds its own server
image and prints `== <workload> [proto=<p> server=<s>]: PASS/FAIL ==`.

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
no h3). `requests`, `sse`, and `streamdownload` run over h3; two cells are a
printed skip (exit 0) for now:

- **`ws` over h3** - WebSocket-over-HTTP/3 (RFC 9220 Extended CONNECT) is not yet
  wired into the client.
- **`streamupload` over h3** - vortex does not yet ack HTTP/3 request-body flow
  control (the `h3AckBody` / NG2 gap), so a large h3 upload stalls after the
  initial window. Downloads (server -> client) are unaffected.

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
