# Perf benches (per-workload, throughput + latency)

Focused benchmarks that drive **one workload** at a vortex server at max rate and
**measure** it: throughput (req/s | msg/s | evt/s | MB/s) plus latency
percentiles (p50/p90/p99/max) and the server's RSS/heap, printed each report
interval. Unlike the [stress soaks](../stress/README.md) these do **not** verify
payloads and never fail on data -- a non-2xx is tallied and a transport error is
counted while the loop keeps measuring.

The **server is identical to the stress server**, so these reuse
`../stress/Dockerfile` + `../stress/stress_server.nim` and the shared client
transport (`../stress/client/transport.py`, `../stress/client/h3.py`) directly.
Only the client's workload/reporting differ (`client/bench_client.py`).

```sh
nimble benchRequests        # GET /plaintext + POST/PUT /echo, with compression
nimble benchWs              # persistent WebSocket echo (round-trip latency)
nimble benchSse             # SSE subscribe (event rate + inter-event latency)
nimble benchStreamUpload    # stream up (MB/s); server still validates the SHA-1
nimble benchStreamDownload  # stream down (MB/s)
nimble bench                # short smoke of all five (20 s, 64 MiB)
```

A run ends with `== <workload> <server> <proto> bench: <N> <unit>, <rate> avg, ... ==`.

## Numbers are relative, not absolute peak

The pure-Python client (httpx / aioquic) is itself the bottleneck on cheap
endpoints (aioquic h3 ~50 MB/s; httpx h2 throttles well below the server's
ceiling). Read these numbers for **relative / regression tracking** (did this
change move the needle?) and **cross-runtime comparison** (sync vs async vs
chronos), not as vortex's absolute maximum. For absolute peak use the C load
generators: `nimble saturate` (h2load + Grafana, requests) and `nimble h3load`.

## Configuration (same knobs as the stress soaks)

| Var | Default | Meaning |
|-----|---------|---------|
| `VORTEX_PROTO` | `h2` | `h1` \| `h2` \| `h3` \| `all` (`all` = h1 + h2; h3 opt-in) |
| `VORTEX_SERVER` | `sync` | `sync` \| `async` \| `async-await` \| `chronos` \| `chronos-await` \| `all` - the handler runtime |
| `VORTEX_SECONDS` | `60` | runtime per cell |
| `VORTEX_REPORT_SECONDS` | `60` | throughput/latency + server RSS report cadence |
| `VORTEX_CONCURRENCY` | `32` | in-flight operations per client (async fan-out) |
| `VORTEX_CLIENTS` | `3` | client workers per cell |
| `VORTEX_REQ_COMPRESSION` | `gzip` | `none` \| `gzip` \| `br` \| `zstd` - client encodes the request body |
| `VORTEX_RESP_COMPRESSION` | `gzip` | `none` \| `gzip` \| `br` \| `zstd` - the server compresses the response |
| `VORTEX_STREAM_BYTES` | `1073741824` | streaming transfer size (1 GiB; lower for a smoke) |
| `VORTEX_RUN_ID` | this run's PID | isolation id for the docker network / container / image names, so runs can go **in parallel** |
| `BENCH_SMOKE` | `0` | `1` runs every workload short (set by `nimble bench`) |

The matrix is `VORTEX_PROTO` × `VORTEX_SERVER`; each cell builds its own server
image and prints per-interval lines like:

```
[requests h2 chronos] 48210 req/s | p50 0.62ms p90 1.10ms p99 3.4ms max 41ms | 200x2894301 err0 | RSS 31MB heap 7MB | t=10s
[sse h3 chronos]      9820 evt/s  | p50 0.9ms p90 2.1ms p99 6.0ms max 22ms | 200x589200 err0 | RSS 29MB heap 7MB | t=10s
[streamdownload h2 async] 512MB xfer @ 340MB/s | p50 3.0s p90 3.4s p99 4.0s max 4.1s | 200x14 err0 | RSS 33MB heap 8MB | t=10s
```

Runs are isolated by `VORTEX_RUN_ID`, so several can run concurrently (but they
contend for the host, so throughput-sensitive cells slow down).

## Examples

```sh
# Quick h2 requests check (10 s)
VORTEX_PROTO=h2 VORTEX_SECONDS=10 nimble benchRequests

# Compare all five handler runtimes for requests over h2
VORTEX_SERVER=all VORTEX_SECONDS=15 nimble benchRequests

# Download throughput at 256 MiB transfers
VORTEX_STREAM_BYTES=268435456 nimble benchStreamDownload

# SSE event rate over both protocols
VORTEX_PROTO=all VORTEX_SECONDS=15 nimble benchSse
```

## HTTP/3

`VORTEX_PROTO=h3` drives the server's QUIC listener with **aioquic**. `requests`,
`sse`, `streamdownload`, and `ws` (RFC 9220 Extended CONNECT) all run over h3.
One cell is a printed skip (exit 0):

- **`streamupload` over h3** - vortex does not yet ack HTTP/3 request-body flow
  control (the `h3AckBody` / NG2 gap), so a large h3 upload stalls after the
  initial window. Downloads (server -> client) are unaffected.

## Gaps

- On Docker Desktop the server RSS (from `/stats`) reflects the shared Linux VM;
  read it as a trend, not an absolute host number.
- Latency percentiles for the streaming workloads are coarse (few whole-transfer
  samples at large `VORTEX_STREAM_BYTES`); MB/s is the primary metric there and
  the latency is per full transfer.
- Not a CI gate (Docker, long runtimes, large transfers).
