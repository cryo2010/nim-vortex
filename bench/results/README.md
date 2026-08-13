# HTTP/3 QUIC-stack migration: before/after benchmarks

Throughput measured with `nimble h3load` (real ngtcp2/nghttp3 h2load QUIC client
over a private Docker network). The client stack is identical across runs, so the
numbers reflect the server. Host: Apple M4 Pro, Docker Desktop (Linux VM).
Before/after are measured the same way on the same host.

Primary metric is aggregate req/s (the `finished in … req/s` line). The
`req/s : min max mean sd ±` line is h2load's per-connection distribution.

## Baseline — OpenSSL QUIC (commit 94115f0, default build)

| Config              | Requests | Conns | Streams | req/s     | wall   | result   |
|---------------------|----------|-------|---------|-----------|--------|----------|
| A (baseline)        | 100,000  | 32    | 32      | 261,715   | 382 ms | all 2xx  |
| B (stress)          | 500,000  | 100   | 64      | 239,633   | 2.09 s | all 2xx  |

Raw logs: `baseline_h3_100k_32c_32s.log`, `baseline_h3_500k_100c_64s.log`.

## After — ngtcp2 + nghttp3 (`-d:quicNgtcp2`)

Same client and configs. Server built on the ngtcp2/nghttp3 backend.

| Config       | Requests | Conns | Streams | req/s     | wall    | result  |
|--------------|----------|-------|---------|-----------|---------|---------|
| A (baseline) | 100,000  | 32    | 32      | 598,050   | 167 ms  | all 2xx |
| B (stress)   | 500,000  | 100   | 64      | 578,922   | 864 ms  | all 2xx |

Raw logs: `after_h3_100k_32c_32s.log`, `after_h3_500k_100c_64s.log`.

## Comparison

| Config | OpenSSL QUIC | ngtcp2/nghttp3 | speedup |
|--------|--------------|----------------|---------|
| A      | 261,715      | 598,050        | 2.3x    |
| B      | 239,633      | 578,922        | 2.4x    |

ngtcp2/nghttp3 is ~2.3-2.4x faster on these configs (same Apple M4 Pro / Docker
host, same h2load client). Both stacks serve all requests 2xx with zero
failures. The gap is large and consistent across runs; treat the absolute
numbers as Docker-on-macOS figures, not bare-metal.

A stall found only under sustained load (the small handshake smoke missed it):
each HTTP/3 request is a fresh bidi stream, and the server must send MAX_STREAMS
as requests finish or the client is capped at the initial budget (~256/conn) and
then times out. Fixed by extending the bidi stream limit on stream close
(vq_ngtcp2.cpp). This is exactly what the stress config is for.

Notes:
- Latency percentiles (mean/p99) are not in the current `nimble h3load` output
  (run.sh greps only throughput lines). If wanted, extend the harness to emit
  h2load's latency block and re-run both stacks symmetrically.
- h1/h2 controls (`nimble perf`, `nimble perf2`) are expected unchanged since the
  migration is HTTP/3-only.

Notes:
- Latency percentiles (mean/p99) are not in the current `nimble h3load` output
  (run.sh greps only throughput lines). If wanted, extend the harness to emit
  h2load's latency block and re-run both stacks symmetrically.
- h1/h2 controls (`nimble perf`, `nimble perf2`) are expected unchanged since the
  migration is HTTP/3-only.
