# Cross-language perf bench (vortex vs Go vs Rust)

Compares vortex against other languages' HTTP servers on the same workloads,
driven by one compiled client so the comparison is uniform. Each server
implements the identical endpoint contract (`/plaintext`, `/json`, `/echo`,
`/sse`, `/upload`, `/download`, `/ws`) with **byte-for-byte** semantics
(deterministic download `byte i = i mod 256`, SHA-1-validated upload, id-ordered
SSE) so the numbers are apples-to-apples.

```sh
nimble benchRequests        # GET/POST/PUT req/s + latency
nimble benchWs              # WebSocket echo msg/s (h1)
nimble benchSse             # SSE evt/s
nimble benchStreamUpload    # stream upload MB/s
nimble benchStreamDownload  # stream download MB/s
nimble bench                # all five, one big table (20s, 64 MiB)
```

Each prints ONE table per workload:

```
workload=requests  (req/s)
  framework proto req/s       p50ms    p90ms    p99ms    err%   RSS
  vortex    h1    65056       1.51     1.69     1.97     0.00   44MB
  vortex    h2    61473       1.59     1.84     2.15     0.00   86MB
  vortex    h3    49136       2.02     2.61     3.23     0.00   83MB
  go        h1    46123       1.70     3.77     6.11     0.00   16MB
  ...
  rust      h1    67154       1.39     2.05     3.08     0.00   9MB
```

## The players

| framework | h1 | h2 | h3 | stack |
|-----------|----|----|----|-------|
| **vortex** (Nim) | ✓ | ✓ | ✓ | this repo (`conformance/stress/stress_server.nim`) |
| **go** | ✓ | ✓ | ✓ | net/http + quic-go (h3) + coder/websocket |
| **rust** | ✓ | ✓ | ✓ | salvo (rustls h1/h2, quinn h3) |

**Load client:** a compiled Nim client on [navi](https://github.com/cryo2010/nim-navi)
(`client/navi/bench_navi.nim`, built `-d:naviHttp3`) — one client that speaks
h1/h2/h3 + ws + sse + streaming, so every cell is measured the same way. Metrics:
throughput, p50/p90/p99/max latency, error/non-2xx tallies; server memory is peak
**container RSS via `docker stats`** (uniform across languages — Nim `heap` would
not be comparable, so it is omitted).

## Configuration

| Var | Default | Meaning |
|-----|---------|---------|
| `VORTEX_PROTO` | `h2` | `h1` \| `h2` \| `h3` \| `all` (all = h1 h2 h3) |
| `BENCH_FRAMEWORKS` | `all` | `vortex` \| `go` \| `rust` \| `all` (or a subset, space-free e.g. `vortex go`) |
| `VORTEX_SECONDS` | `15` | runtime per cell |
| `VORTEX_CONCURRENCY` | `32` | in-flight ops per client |
| `VORTEX_CLIENTS` | `3` | client fan-out |
| `VORTEX_STREAM_BYTES` | `1 GiB` | streaming transfer size |
| `VORTEX_RUN_ID` | PID | isolates parallel runs (docker net/img/results) |

The harness runs in three phases so the report is clean: **build** all images
(output to stderr), **run** each supported cell (server + `docker stats` RSS
sampler + client), then **report** one table (stdout).

Examples:
```sh
VORTEX_PROTO=h3 VORTEX_SECONDS=20 nimble benchRequests            # h3 only, all frameworks
BENCH_FRAMEWORKS="vortex rust" VORTEX_PROTO=all nimble benchSse   # vortex vs rust, all protos
VORTEX_STREAM_BYTES=268435456 nimble benchStreamDownload         # 256 MiB transfers
```

## Sparse matrix (unsupported cells show `n/a`)

- **WebSocket is h1-only** for every framework: no client (navi or Go) dials ws
  over h2/h3 Extended CONNECT (RFC 8441/9220 unimplemented), so ws × {h2,h3} = n/a.
- **vortex streamupload over h3** = n/a (vortex doesn't yet ack h3 request-body
  flow control; Go/Rust h3 upload is measured).

## Caveats

- **Numbers are relative / cross-language, not absolute peak.** The navi client,
  though compiled, can still be the ceiling on trivial endpoints. For vortex's
  absolute peak use `nimble saturate` (h2load) / `nimble h3load`.
- **`docker stats` RSS** is cgroup memory in Docker Desktop's VM (includes page
  cache); read it as a consistent *relative* figure, not an absolute host number.
- **SSE evt/s + latency are reconnect-dominated**: the server closes after each
  20-event batch, so the client's reconnect backoff (a client-side constant,
  equal for all frameworks) dominates. The comparison stays fair; the absolute
  evt/s is low by construction.
- **rust h2** currently shows a ~40ms per-request stall consistent with
  delayed-ACK/Nagle (salvo TCP config, not its ceiling) — treat rust h2 with
  suspicion until a `TCP_NODELAY` tweak lands; rust h1/h3 are representative.
- **rust upload buffers** the request body (`payload_with_max_size`), so its
  upload RSS is not comparable to the streaming servers.
- Not a CI gate (Docker, big transfers). Adding a framework = drop a dir under
  `servers/<name>/` and extend the capability table in `run.sh`.
