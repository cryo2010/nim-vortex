# HTTP/3: ngtcp2 + nghttp3

**Status: shipped.** **ngtcp2** (QUIC transport) + **nghttp3** (HTTP/3
framing/QPACK) is vortex's HTTP/3 implementation. It was first evaluated behind
`-d:quicNgtcp2` alongside the old OpenSSL-QUIC + hand-rolled-codec stack; that
path has since been retired, so ngtcp2/nghttp3 is now the only one (the flag is
gone). This doc records the architecture and the evaluation that justified it.

Building HTTP/3 (any non `-d:plainHttp` build) now requires ngtcp2 + nghttp3 with
the ngtcp2 `ossl` crypto backend (OpenSSL >= 3.5); a `-d:plainHttp` build needs
neither. On Arch: `pacman -S libngtcp2 libnghttp3`; elsewhere build from source
with `--with-openssl` (see `conformance/h3load/deps.Dockerfile`).

## Architecture

- `src/vortex/http3/ngtcp2/vq_ngtcp2.{h,cpp}` — a C++ shim (one `VqEngine` per
  loop thread) owning `ngtcp2_conn` + `nghttp3_conn` and their callbacks, TLS via
  the ngtcp2 `ossl` crypto backend (OpenSSL >= 3.5). Narrow `extern "C"` ABI to
  Nim. Compiled by g++ via `{.compile.}`; vortex itself stays on `nim c` (only
  the shim is C++; `-lstdc++` links the runtime).
- `src/vortex/http3/ngtcp2/backend.nim` — mirrors `http3/codec.nim`'s public
  `H3Conn`/`H3Stream` + proc surface, so `request.nim`/`eventloop.nim` use it via
  an import-swap. Holds per-request state; runs the shim callbacks on the loop
  thread; translates responses to `vq_submit_*`.
- `eventloop.nim` — only the transport *drive* branches (`when defined(quicNgtcp2)`):
  UDP recv -> `vq_engine_recv` -> dispatch -> `vq_engine_pump`; timers folded into
  the selector timeout. Routing, workers, Request/Response, outbox: unchanged.
- Vendoring: `conformance/h3load/deps.Dockerfile` builds ngtcp2 v1.15 + nghttp3
  v1.11 with `--with-openssl`, matching the h2load client.

## Results so far

| Check | ngtcp2/nghttp3 |
|-------|----------------|
| HTTP/3 GET/POST end-to-end (h2load) | pass, all 2xx |
| h3spec (HTTP/3 servers group, 15 error cases) | **15/15 pass** |
| h3websocket (aioquic RFC 9220 conformance) | **pass** (handshake, text/binary echo, ping/pong, subprotocol, fragmented, close) |
| ASan/LSan under h2load (`conformance/memcheck/h3ngtcp2.sh`) | **clean** (no errors, no shim/backend leaks) |
| h3load throughput 100k/32c/32s | **598k req/s vs 262k** (2.3x) |
| h3load throughput 500k/100c/64s | **579k req/s vs 240k** (2.4x) |
| default OpenSSL-QUIC build | still compiles + runs |
| `-d:plainHttp` build | unaffected |

Run the ngtcp2 side of any suite with `NGTCP2=1` (h3load/h3spec/h3websocket) or
`nimble h3loadNgtcp2`; the valgrind memcheck is `conformance/memcheck/h3ngtcp2.sh`.

Throughput is Docker-on-macOS (Apple M4 Pro), same h2load client for both stacks;
see `bench/results/`. The ~2.4x gap is large and consistent.

Two bugs the deeper checks caught (the handshake smoke did not):
- the stress config exposed a stall: each request is a fresh bidi stream, so the
  server must send MAX_STREAMS as requests finish or the client is capped at the
  initial budget (~256/conn) and stalls -- fixed with
  `ngtcp2_conn_extend_max_streams_bidi` on stream close.
- ASan caught a heap-use-after-free at shutdown: the engine frees a `Conn` when
  it reaps a closed connection, but the Nim `H3Conn` still held a pointer to it
  -- fixed by nulling that pointer in the `on_conn_close` callback (and guarding
  the response procs against a freed connection).

## Done

- **Flip + retirement** — ngtcp2/nghttp3 is the only HTTP/3 path; the OpenSSL
  QUIC transport (`transport/quic.nim`) and the hand-rolled `http3/codec.nim` +
  `qpack*.nim` + `frames.nim` are deleted, and the `-d:quicNgtcp2` flag is gone.
- **CI** — the `-d:ssl` unit/conformance jobs install `libngtcp2 libnghttp3`
  (Arch ships the `ossl` crypto backend); the h3 conformance suites build the
  ngtcp2 server directly (no `NGTCP2=1` selector anymore).

## Still open (tracked in todo.txt)

- **Request-body flow-control acks** — `h3AckBody` is a no-op (the shim
  auto-extends stream offsets on receive); real backpressure for large uploads
  is a refinement.
- **helgrind/tsan** — the C++ shim is single-threaded per loop (no locks); worker
  responses cross threads via the existing outbox. Run the race tooling to confirm.

## Why (the evaluation that justified it)

Strongly positive: the ngtcp2/nghttp3 backend is materially faster (~2.4x on the
h3load configs), passes the HTTP/3 error-conformance suite (h3spec 15/15) and RFC
9220 WebSockets (aioquic), is ASan-clean under load, and drops the maintenance
burden of the hand-rolled QUIC peer-address tap and the capacity-0 QPACK codec.
