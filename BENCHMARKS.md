# Benchmarks

Throughput of vortex against other Nim HTTP servers, and of vortex's own
protocols against each other. The harness lives in `bench/`; every number here
is reproducible with the commands at the end.

> **Read these as relative, not absolute.** The load generator and the server
> share one machine over loopback, so both contend for the same cores and the
> absolute req/s is far below what a dedicated client + NIC would show. The
> point is how the servers compare *under identical conditions*, not the raw
> ceiling.

## Method

- **Workload:** the TechEmpower-style `/plaintext` handler — `200 OK`,
  `Hello, World!`, `text/plain`. No routing, no I/O; this measures the
  server's request/response machinery, not application logic.
- **Harness:** `bench/perf_http1_1.nim` is one binary that spawns each server
  as a subprocess of itself and drives the *same* in-process, multi-threaded
  keep-alive load generator against each, counting complete responses by
  parsing `Content-Length` (so differing header sets don't skew the count).
- **Build:** `-d:danger --threads:on --mm:orc`.
- **Host:** Apple M4 Pro (14 cores), macOS, Nim 2.2.10. Compared against
  httpbeast 0.4.x, guzba/mummy 0.4.8, and Nim's std `asynchttpserver`, plus
  chronos's HTTP server.

### Two important caveats

1. **macOS `SO_REUSEPORT` does not load-balance across listeners** (unlike
   Linux). vortex's multi-thread model relies on the kernel spreading accepts
   across per-thread listeners, so on this host the multi-thread rows perform
   essentially like the single-thread row (`vortex` ≈ `vortex-1thread`). On
   Linux these numbers scale with cores; treat the macOS figures as
   **single-core** framework overhead, not vortex's scaling ceiling.
2. **Pipelining is not universal.** vortex and httpbeast pipeline HTTP/1.1
   (many requests in flight per connection); mummy, `asynchttpserver`, and
   chronos effectively do not. So the deep-pipeline run (below) is a fair
   vortex-vs-httpbeast comparison only; the cross-server comparison uses
   **pipeline depth 1**.

## HTTP/1.1 — cross-server, no pipelining (fair to all)

64 keep-alive connections, pipeline depth 1, 4 s per server:

| Server | req/s | Relative |
|--------|------:|---------:|
| vortex (inline) | 183,258 | 100% |
| vortex (asyncdispatch adapter) | 182,230 | 99% |
| vortex (chronos adapter) | 185,707 | 101% |
| httpbeast (nil-future fast path) | 179,353 | 98% |
| httpbeast (`{.async.}`) | 179,741 | 98% |
| **asynchttpserver** (std) | 125,792 | 69% |
| **mummy** | 106,038 | 58% |
| **chronos** HTTP server | 78,022 | 43% |

vortex and httpbeast are neck-and-neck — expected, since vortex is built on
httpbeast's one-loop-per-thread, inline-handler architecture. vortex leads the
rest of the field: ~1.5× `asynchttpserver`, ~1.7× mummy, ~2.3× chronos's
server, on the same trivial handler.

## HTTP/1.1 — pipelined (vortex vs httpbeast)

32 connections, pipeline depth 8, 5 s per server. Only the pipelining servers
are meaningful here:

| Server | req/s |
|--------|------:|
| vortex (chronos adapter, inline) | 1,451,093 |
| vortex (asyncdispatch adapter, inline) | 1,422,218 |
| vortex (minimal, no Server header) | 1,399,141 |
| vortex (inline) | 1,355,256 |
| httpbeast (nil-future fast path) | 1,325,747 |
| httpbeast (`{.async.}`) | 1,027,614 |

With requests batched, per-request overhead dominates and vortex's inline path
edges httpbeast by a few percent. The suspend-per-request async rows
(`*-async-await`) are intentionally excluded — a forced `await` per request
can't be hidden by pipelining and drops to ~200 k req/s in both servers.

## HTTP/2 (vortex only)

No other Nim server speaks HTTP/2, so this compares vortex's h2c path against
its own HTTP/1.1 on the same server. 32 connections, 64 concurrent streams,
4 s:

| Path | req/s | vs h1 |
|------|------:|------:|
| HTTP/1.1 (pipeline depth 8) | 1,358,786 | 100% |
| HTTP/2 (single thread) | 1,318,272 | 97% |
| HTTP/2 (multi-thread) | 1,295,024 | 95% |

HTTP/2 framing costs a few percent over pipelined HTTP/1.1 for a trivial
response — the multiplexing/flow-control bookkeeping in exchange for real
concurrency and header compression.

HTTP/3 throughput is measured separately with `nimble h3load`
([conformance/h3load](conformance/h3load), Docker): it drives the vortex HTTP/3
server with a real QUIC client — nghttp2's `h2load` built for HTTP/3 (ngtcp2 +
nghttp3 on the same OpenSSL >= 3.5 QUIC API) — and prints req/s. An in-process
hand-rolled QUIC client is client-bound and under-reports the server, so it is
not used.

## Takeaways

- vortex matches httpbeast (its architectural parent) and clearly outperforms
  the async/threaded Nim servers on a trivial handler.
- Its async adapters (asyncdispatch, chronos) add no measurable overhead when
  the handler doesn't actually suspend, so `await`-style code is free until you
  await real I/O.
- HTTP/2 and HTTP/3 trade a few percent of trivial-response throughput for
  multiplexing — the expected shape.
- **These are loopback, single-host, macOS numbers.** For multi-core scaling,
  run the harness on Linux, where `SO_REUSEPORT` spreads load across the
  per-thread listeners.

## Reproduce

```sh
nimble perf     # HTTP/1.1: vortex vs httpbeast, mummy, asynchttpserver, chronos
nimble perf2    # HTTP/2 (h2c) vs HTTP/1.1 on vortex
nimble h3load   # HTTP/3 over QUIC, real client (h2load-http3, Docker)
```

Tunables are compile-time defines, e.g. a fair cross-server run:

```sh
nim c -r -d:danger --threads:on --mm:orc \
  -d:benchConns=64 -d:benchDepth=1 -d:benchSeconds=4 bench/perf_http1_1.nim
```

`-d:benchDepth=1` disables pipelining (fair to non-pipelining servers);
`-d:benchDepth=8` shows the pipelined ceiling for vortex and httpbeast.
