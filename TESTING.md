# Testing

A registry of every test in vortex, what it verifies, and how it runs. Tests
fall into five groups:

1. [Default unit + integration suite](#default-suite-nimble-test) (`nimble test`)
2. [Opt-in feature tests](#opt-in-feature-tests) (need a build flag or dependency)
3. [Docker conformance & load suites](#docker-conformance--load-suites)
4. [Fuzzing](#fuzzing)
5. [Benchmarks](#benchmarks) (performance, not correctness)

The **CI** column says whether a check runs on every PR (see
`.github/workflows/ci.yml`). "local" means it is not wired into CI and is run on
demand.

## Running at a glance

```sh
nimble test            # default unit + integration suite (orc)
NIM_MM=arc nimble test # same suite under the arc memory manager
NIM_SANITIZE=1 nimble test   # same suite under AddressSanitizer + UBSan

nimble testgzip        # gzip response compression (needs zlib)
nimble teststreamcomp  # streaming (sendHead/write/SSE) gzip+brotli (needs zlib+brotli)
nimble testreqdecomp   # inbound request-body gzip/br decode (needs zlib+brotli)
nimble testzstd        # zstd response compression + negotiation (needs zstd+brotli+zlib)
nimble testdeflate     # WebSocket permessage-deflate (needs zlib)
nimble testrace        # cross-thread race regressions (ThreadSanitizer)
nimble testchronos     # chronos async adapter (needs chronos)

# Docker conformance / load (each builds images and exits non-zero on failure):
nimble h1spec h2spec h3spec h3websocket autobahn redbot \
       zap testssl h2load h3load interop brotli fuzz

nimble bench perf perf2   # benchmarks (not pass/fail)
```

---

## Default suite (`nimble test`)

Compiles and runs every `tests/test_*.nim`. In CI it runs twice in the **`test`**
job (memory-manager matrix: `orc` and `arc`) and again in the **`sanitize`** job
under AddressSanitizer + UBSanitizer (`NIM_SANITIZE=1`, which also switches to
`-d:useMalloc`). All of the tests below are covered by those three CI runs.

Configuration lives in `tests/config.nims` (adds `src` to the path, `--threads:on`,
`-d:ssl`, and reads `NIM_MM` / `NIM_SANITIZE`). Shared helpers: `tests/helper.nim`
(raw-socket client with faithful recv), `tests/h2client.nim` (minimal HTTP/2
client).

### Protocol parsers & decoders (unit, RFC vectors)

| Test | Verifies |
|------|----------|
| `test_http1_parser.nim` | HTTP/1.1 request-line and header parsing |
| `test_http1_codec.nim` | HTTP/1.1 response framing |
| `test_hpack.nim` | HPACK decoding against RFC 7541 Appendix C vectors |
| `test_qpack_dyn.nim` | QPACK dynamic table (RFC 9204 3.2): insertion, byte-size eviction, capacity |
| `test_http3_connect.nim` | HTTP/3 Extended CONNECT header classifier (RFC 9220), without a live QUIC stream |

### HTTP/1.1

| Test | Verifies |
|------|----------|
| `test_http1_server.nim` | HTTP/1.1 integration: keep-alive, pipelining, chunked bodies, 100-continue |
| `test_half_close.nim` | Client half-close (`shutdown(SHUT_WR)`) mid-exchange is handled |
| `test_ipv6.nim` | Dual-stack bind (`::`) accepts both IPv4 and IPv6 clients |

### HTTP/2

| Test | Verifies |
|------|----------|
| `test_http2.nim` | HTTP/2 integration (h2c prior knowledge, via curl) |
| `test_http2_flowcontrol.nim` | Flow-control regression for h2spec 6.9.2 (SETTINGS_INITIAL_WINDOW_SIZE change) |
| `test_http2_websocket.nim` | HTTP/2 Extended CONNECT WebSockets (RFC 8441), frame level |

### HTTP/3

| Test | Verifies |
|------|----------|
| `test_http3.nim` | HTTP/3 integration over QUIC (via an HTTP/3-capable curl; skips if absent) |

### WebSockets

| Test | Verifies |
|------|----------|
| `test_websocket_frames.nim` | Upgrade handshake and frame codec |
| `test_websocket_server.nim` | Server-level WebSocket behavior |
| `test_websocket_conformance.nim` | Regressions for the fixes the Autobahn run drove |
| `test_websocket_subprotocol.nim` | Subprotocol negotiation |
| `test_websocket_timeout.nim` | Idle ping / pong timeout |
| `test_websocket_backpressure.nim` | Backpressure introspection (`bufferedAmount`) |
| `test_websocket_blocking.nim` | Per-connection backpressure for `ws.blocking` |
| `test_websocket_async.nim` | `ws.doAsync` (asyncdispatch adapter) |
| `test_ws_messages.nim` | `ws.messages` async iterator, from a plain async handler / `router.ws` |
| `test_ws_idle.nim` | Idle keepalive sweep for h2/h3 WebSocket streams |
| `test_ws_origin.nim` | Origin allowlisting (SEC4, CSWSH defense) |
| `test_shutdown_ws.nim` | Server-initiated WebSocket close (1001) on graceful shutdown |

### TLS

| Test | Verifies |
|------|----------|
| `test_tls.nim` | TLS termination basics (h1/h2 over TLS) |
| `test_tls_key_options.nim` | In-memory cert/key (`certPem`/`keyPem`) and passphrase-protected keys |
| `test_tls_advanced.nim` | PKCS#12 bundles, mTLS client-cert verification, and SNI |
| `test_tls_polish.nim` | Wildcard SNI, max TLS version cap, OCSP stapling |
| `test_tls_reload.nim` | Certificate hot-reload for new h1/h2 connections (`reloadTls`) |
| `test_tls_reload_h3.nim` | Certificate hot-reload for HTTP/3 (QUIC), cross-thread reload signal |
| `test_tls_helpers.nim` | TLS deployment helpers: `res.redirect`, `req.isSecure` (SEC5) |

### Routing, adapters & core API

| Test | Verifies |
|------|----------|
| `test_router.nim` | Router matching, path params, per-method dispatch, 404/405 |
| `test_adapter.nim` | asyncdispatch async-handler adapter |

### Streaming & static files

| Test | Verifies |
|------|----------|
| `test_streaming.nim` | Response body streaming (`res.sendHead` / `write` / `finish`) |
| `test_sse_streaming.nim` | Streaming API end-to-end over HTTP/1.1 (SSE pattern) |
| `test_streaming_request.nim` | Streaming request bodies via a `router.stream` route |
| `test_streaming_read.nim` | Pull-based request-body streaming (asyncdispatch adapter) |
| `test_streaming_drain.nim` | Awaitable outbound backpressure (producer yields on a full buffer) |
| `test_static_files.nim` | Static file serving (`res.sendFile`): status/headers/body over raw sockets |

### Server lifecycle & concurrency

| Test | Verifies |
|------|----------|
| `test_blocking.nim` | Worker pool / `req.blocking:` escape hatch |
| `test_graceful_shutdown.nim` | `requestShutdown()` drains in-flight requests, frees the port |
| `test_multi_server.nim` | Multiple `Server` instances in one process are independent |
| `test_remote_address.nim` | `req.remoteAddress` (peer IP) and `req.forwardedFor` (SEC1) |
| `test_proxy_protocol.nim` | PROXY protocol v1/v2 parsing + trust gating; overrides `req.remoteAddress` (SEC1) |

### Security

| Test | Verifies |
|------|----------|
| `test_security_parsing.nim` | Request smuggling, integer overflow, pure/fast parser hardening |
| `test_security_dos.nim` | Live-server denial-of-service budgets (asserts the secure behavior) |
| `test_security_headers.nim` | `securityHeaders()` OWASP baseline + `req.isSecure` gating (SEC2) |
| `test_security_headers_toggle.nim` | `settings.securityHeaders` auto-inject toggle |
| `test_ratelimit.nim` | Per-client token-bucket rate limiting (SEC3, OWASP API4:2023) |

> `test_compression.nim` and `test_thread_race.nim` are compiled by the default
> suite too (they match the `tests/t*` glob), but only carry weight under their
> dedicated tasks: `test_compression.nim` skips itself without `-d:httpGzip`, and
> `test_thread_race.nim` only detects the race when built with ThreadSanitizer.
> Both have their own tasks (see [Opt-in feature tests](#opt-in-feature-tests)).

---

## Opt-in feature tests

Separate `nimble` tasks because they need a build flag or an extra dependency.

| Task | CI | Verifies |
|------|----|----------|
| `nimble testgzip` | local | gzip response compression (`settings.compress`, `-d:httpGzip`, links zlib). Runs `test_compression.nim` (compressible body round-trips; identity without `Accept-Encoding`; small bodies and non-compressible types skipped). Gzip is *also* exercised in CI through the `interop` job. |
| `nimble teststreamcomp` | **yes** (`teststreamcomp`) | Streaming response compression: `res.sendHead`/`write`/`finish` (thus SSE and file streaming) compressed with gzip + brotli, over HTTP/1.1 (chunked) and h2c; curl + the gzip/brotli CLIs verify framing and a byte-exact round-trip. |
| `nimble testreqdecomp` | **yes** (`testreqdecomp`) | Inbound request-body decompression (`settings.decompressRequest`): gzip/br bodies decoded into `req.body` over h1 + h2c, a decompression bomb rejected with 413, a corrupt body with 400. |
| `nimble testzstd` | **yes** (`testzstd`) | Zstd response compression, buffered + streamed over HTTP/1.1 and h2c, plus br/zstd/gzip Accept-Encoding negotiation (q-values + tie-break); byte-exact round-trip via the zstd/brotli/gzip CLIs. |
| `nimble testdeflate` | **yes** (`testdeflate`) | WebSocket permessage-deflate (RFC 7692, `-d:wsDeflate`, links zlib) over a live server, plus the h2 (RFC 8441) deflate case. |
| `nimble testrace` | **yes** (`testrace`) | Two ThreadSanitizer regressions: (1) the handler/stream-route closure refcount race across loop threads at `start()`/shutdown; (2) C3/IMP2 -- a `req.blocking:` worker reading a request snapshot rather than live h2 state, under concurrent h2c blocking requests. TSan aborts on any data race. |
| `nimble testchronos` | **yes** (`testchronos`) | The chronos async adapter (`chronos_adapter.nim`); chronos is opt-in so it is kept out of the default suite. |

---

## Docker conformance & load suites

Each builds a vortex server image (and usually a client image), runs a
third-party tool over a private docker network, and exits non-zero on any
finding or failure. All need Docker; `interop` also needs host `openssl`.

| Task | CI | Tool | Verifies |
|------|----|------|----------|
| `nimble redbot` | **yes** (`redbot`) | [REDbot](https://redbot.org) | HTTP/1.1 conformance; fails on any BAD-level finding |
| `nimble h1spec` | **yes** (`h1spec`) | [h1spec](https://github.com/dropseed/h1spec) | HTTP/1.1 request/header/body/framing cases |
| `nimble h2spec` | **yes** (`h2spec`) | [h2spec](https://github.com/summerwind/h2spec) | HTTP/2 conformance over TLS |
| `nimble h3spec` | **yes** (`h3spec`) | [h3spec](https://github.com/kazu-yamamoto/h3spec) | HTTP/3 + QPACK error-case group (QUIC transport group excluded) |
| `nimble h3websocket` | **yes** (`h3websocket`) | [aioquic](https://github.com/aiortc/aioquic) | HTTP/3 WebSockets (RFC 9220) echo/handshake |
| `nimble autobahn` | local (paused) | [Autobahn](https://github.com/crossbario/autobahn-testsuite) | Full RFC 6455 WebSocket suite; paused in CI for runtime (see `ci.yml`) |
| `nimble zap` | **yes** (`zap`) | [OWASP ZAP](https://www.zaproxy.org/) | Passive baseline scan; gates against dropping a security header |
| `nimble testssl` | **yes** (`testssl`) | [testssl.sh](https://testssl.sh/) | TLS protocols/ciphers/vulnerabilities; fails on HIGH/CRITICAL |
| `nimble h2load` | **yes** (`h2load`) | [h2load](https://nghttp2.org/) | h1 + h2c load/stress smoke; fails on any failed/errored/non-2xx |
| `nimble h3load` | **yes** (`h3load`) | h2load (HTTP/3) | QUIC throughput/stress with a real QUIC client; fails on any failed/errored/non-2xx |
| `nimble interop` | **yes** (`interop`, matrix `mtls=0` and `mtls=1`) | Node / Python / Go / Rust / Java clients | Cross-client HTTP/2 + TLS + gzip over every method; asserts h2 negotiation and gzip round-trip; mTLS mode checks the client-cert subject |
| `nimble brotli` | **yes** (`brotli`) | Node / Python / Go / Rust / Java clients | Same harness with `INTEROP_ENCODING=br`: every client requests and asserts `Content-Encoding: br` and decodes it with its ecosystem's brotli library |

Details for each live in the matching `conformance/<name>/README.md`.

---

## Fuzzing

| Task | CI | Verifies |
|------|----|----------|
| `nimble fuzz` | **yes** (`fuzz`) | libFuzzer targets over the HTTP/1.1 parser and the HPACK / QPACK decoders (30s per target in CI); a crash writes a reproducer and exits non-zero. |

---

## Benchmarks

Performance measurement, not pass/fail (CI does not gate on throughput numbers).

| Task | Verifies |
|------|----------|
| `nimble bench` | Builds the release benchmark server (`bench/handlers`) for `bench/run.sh` (wrk/oha/ab/h2load) |
| `nimble perf` | HTTP/1.1 throughput vs httpbeast / chronos / mummy |
| `nimble perf2` | HTTP/2 throughput |

HTTP/3 throughput is measured via `nimble h3load` (a real QUIC client), not a
local `perf` task.
