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

_Pending (Phase 6). Same two configs; add an `after_h3_*.log` pair and fill the
delta table here._

Notes:
- Latency percentiles (mean/p99) are not in the current `nimble h3load` output
  (run.sh greps only throughput lines). If wanted, extend the harness to emit
  h2load's latency block and re-run both stacks symmetrically.
- h1/h2 controls (`nimble perf`, `nimble perf2`) are expected unchanged since the
  migration is HTTP/3-only.
