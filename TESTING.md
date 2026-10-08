# Testing

A registry of every test in vortex, what it verifies, and how it runs. Tests
fall into six groups:

1. [Default unit + integration suite](#default-suite-nimble-test) (`nimble test`)
2. [Opt-in feature tests](#opt-in-feature-tests) (need a build flag or dependency)
3. [Docker conformance & load suites](#docker-conformance--load-suites)
4. [Interactive load & stress tools](#interactive-load--stress-grafana) (k6 / h2load + Grafana)
5. [Fuzzing](#fuzzing)
6. [Benchmarks](#benchmarks) (performance, not correctness)

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

# Stress soaks (pass/fail, checksum-verified; Docker):
nimble stressRequests stressWs stressSse stressStreamUpload stressStreamDownload
nimble stressMixed     # all five at one server at the same time
nimble stress          # short smoke of all six

# Interactive load/stress with live Grafana charts (the stack stays up):
nimble loadtest        # k6: hold a load, chart latency + server CPU/mem  (localhost:3000)
nimble saturate        # h2load: saturate, chart server CPU/mem + req/s   (localhost:3001)

nimble perf perf2   # local throughput comparison vs other servers (not pass/fail)
nimble bench        # Dockerized per-workload perf suite: req/s | MB/s + latency
```

---

## Default suite (`nimble test`)

Compiles and runs every `tests/test_*.nim`. In CI it runs twice in the **`test`**
job (memory-manager matrix: `orc` and `arc`) and again in the **`sanitize`** job
under AddressSanitizer + UBSanitizer (`NIM_SANITIZE=1`, which also switches to
`-d:useMalloc`). Both jobs set `NIM_COMPRESS=1` (and install zlib/brotli/zstd), so
the compression tests build with the codecs and **run** here (rather than
skipping) -- gzip/brotli/zstd get orc, arc, and ASan coverage. All of the tests
below are covered by those three CI runs.

Configuration lives in `tests/config.nims` (adds `src` to the path, `--threads:on`,
`-d:ssl`, and reads `NIM_MM` / `NIM_SANITIZE` / `NIM_COMPRESS`). Shared helpers:
`tests/helper.nim`
(raw-socket client with faithful recv, curl/cert fixtures, `withServer`),
`tests/h2client.nim` (minimal HTTP/2 client), `tests/wsclient.nim` (raw
WebSocket client: upgrade handshake + full RFC 6455 frame codec).

### Protocol parsers & decoders (unit, RFC vectors)

| Test | Verifies |
|------|----------|
| `test_http1_parser.nim` | HTTP/1.1 request-line and header parsing |
| `test_http1_codec.nim` | HTTP/1.1 response framing |
| `test_hpack.nim` | HPACK decoding against RFC 7541 Appendix C vectors |
| `test_http3_connect.nim` | HTTP/3 Extended CONNECT header classifier (RFC 9220), without a live QUIC stream; also the h3 side of the shared `:method` / CONNECT / field-value rules (#240) |

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
| `test_http2_malformed.nim` | Malformed HEADERS answered with RST_STREAM(PROTOCOL_ERROR): bad/duplicate Content-Length (RFC 9113 8.1.1), NUL/CR/LF in field names/values (8.2.1). Plus the #240 conformance follow-ups that are visible on the wire: any frame on a permanently idle even stream id (5.1), the 1*DIGIT Content-Length grammar and the field-value whitespace rule (8.2.1), unknown and non-token `:method` values, the CONNECT pseudo-header rules (8.5), connection-specific response fields (8.2.2), the HPACK dynamic-table-size update (RFC 7541 4.2), and the GOAWAY length check (4.2/6.8) |
| `test_http2_request_body.nim` | Request-body `content-length` reconciliation on a streaming (`onBody`) route (#237): DATA past the declared length rejected on arrival rather than after the terminating frame, a short body and a mismatch revealed by the trailer section rejected at END_STREAM, `content-length` with END_STREAM on the request HEADERS rejected before the handler is dispatched, `content-length: 0` with DATA rejected, matching bodies (with and without trailers) still answered, and a rejected stream still terminating the sink so a suspended handler cannot leak (#232). Plus request trailer-field validation (#238): CR/LF/NUL and edge-whitespace values, uppercase and non-token names, pseudo-headers, the connection-specific and framing fields forbidden in a trailer section (RFC 9113 8.2.2 / RFC 9110 6.5.1), one bad field poisoning the whole block, a valid trailer still reaching `req.trailers` on a buffered and a streaming route, and the `maxHeaderSize` bound on the trailer block |
| `test_http2_stream_errors.nim` | Stream-level conditions stay stream-level instead of GOAWAY-ing the connection (#239): trailers without END_STREAM (RFC 9113 8.1), HEADERS on a half-closed(remote) stream (5.1), and DATA/trailers racing the server's own early final response (5.1 closed-stream tolerance) |
| `test_http2_download.nim` | Streaming-download regressions: the per-stream `pendingBody` buffer stays bounded while the backlog never reaches zero (#331); benign connection-level WINDOW_UPDATEs during a long download do not trip the control-frame budget (#335); a single write larger than the peer window arrives byte-exact across the direct-emit / parked-remainder seam, and a wide window still frames one full-sized DATA per producer chunk (#334); a sendFile download against a small peer window keeps the per-stream backlog within the read-ahead budget plus two chunks and still completes byte-exact (#340) |
| `test_http2_budget.nim` | The `maxControlFrames` budget has no bypass (#234): a flood of PING ACKs, SETTINGS ACKs, received GOAWAYs, unknown frame types, stream-level WINDOW_UPDATEs, self-dependent PRIORITY on a used stream, or DATA on a closed stream ends in GOAWAY(ENHANCE_YOUR_CALM); a self-dependency on an idle stream id is a connection error and never a RST_STREAM (RFC 9113 5.1); SETTINGS entries are charged per entry, not per frame; and a one-GET-per-burst interleave still trips the budget (it used to reset it). The converse too: a few control frames or window updates per request are answered normally |
| `test_http2_backpressure.nim` | The two per-connection backpressure caps (#242, untested until now): un-dispatched buffered request bodies cannot pin more than `max(h2ConnWindow, maxBodySize)` (never below the 64 KiB default receive window) across concurrently trickled POST streams (the stream that crosses it is reset with REFUSED_STREAM, a cancelled stream gives its reservation back, and a single upload up to `maxBodySize` still succeeds because credit stays eager) (#235); and a connection whose requests have all finished while the server owes response bytes parked on an exhausted peer window is closed with a GOAWAY within `bodyTimeout` instead of being pinned, for a buffered response and for a streamed `sendFile` alike, while a client that keeps returning credit is never cut off (#236) |
| `test_http2_priority.nim` | RFC 9218 prioritization: urgency ordering, incremental interleaving, PRIORITY_UPDATE, `res.setPriority` override |
| `test_connect_disconnect.nim` | Half-open stream closed by the read-idle deadline (slowloris, #201); two-step GOAWAY on graceful shutdown (RFC 9113 6.8, #208) |
| `test_http2_websocket.nim` | HTTP/2 Extended CONNECT WebSockets (RFC 8441), frame level; a close queued behind an exhausted send window drains on the next WINDOW_UPDATE instead of RST_STREAM(CANCEL) (#240.9) |

### HTTP/3

| Test | Verifies |
|------|----------|
| `test_http3.nim` | HTTP/3 integration over QUIC (via an HTTP/3-capable curl; skips if absent), including a streaming route's declared `content-length` against the body received |
| `test_h3_idle_keepalive.nim` | `keepAliveTimeout` reaches the QUIC transport parameters, a narrow idle window neither breaks a normal exchange nor truncates a slower-than-idle one, and the server itself PINGs through the quiet gap (>= 3 ACK-less transmitted PINGs, six observed; a fast exchange is held to <= 2) -- counted with the shim's `-d:vortexH3FrameLog` frame-log hook, which the suite's `.nims` sidecar switches on. The count is a lower bound on keep-alives (one coalesced with an ACK is counted apart) and an upper bound including PTO probes (#347) |

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
| `test_ws_messages.nim` | `ws.messages` async iterator, from a plain async handler / `router.ws`; both legs `router.ws` registers (h1 GET upgrade, h2 Extended CONNECT) and `wsToHandler` on a hand-registered route; the refusals on both legs (426 + `Sec-WebSocket-Version` for a bad/missing version, 400 for no handshake intent) and `acceptWebSocket`'s dead handle |
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
| `test_tls_h3_material.nim` | TLS key/cert material matrix (files, in-memory PEM, encrypted keys) actually reaching the HTTP/3 (QUIC) engine, not just h1 |
| `test_tls_helpers.nim` | TLS deployment helpers: `res.redirect`, `req.isSecure` (SEC5) |
| `test_h3_tls_ossl35.nim` | The ngtcp2 shim compiles against OpenSSL 3.5, the documented minimum: the harness rewrites `SSL_OP_SERVER_PREFERENCE` away and checks the context still carries `SSL_OP_BIT(22)` |

### Routing, adapters & core API

| Test | Verifies |
|------|----------|
| `test_router.nim` | Router matching, path params, per-method dispatch, 404/405 |
| `test_router_features.nim` | Automatic OPTIONS (Allow header), duplicate-route detection at registration, an explicit OPTIONS handler wins |
| `test_router_middleware.nim` | `router.use` middleware: ordering/nesting, short-circuit, wraps unmatched (404) routes too |
| `test_router_mount.nim` | Mounting a child router under a path prefix: `:params` carry over, child middleware scoped to its routes |
| `test_router_race.nim` | Concurrent route-trie traversal against a multi-threaded server (the race itself only shows under `nimble testrace` / TSan) |
| `test_app_entry.nim` | `newVortex()` app entry: routes on the app, `start`/`serve` wire the streaming predicate |
| `test_adapter.nim` | Async-handler adapter scenario matrix (streaming reads/writes, `req.blocking`, `ws.doAsync`/`ws.messages`, error paths). Built plain it tests `vortex/asyncdispatch` (this default suite); the same file built with `-d:vortexChronos` is the `nimble testchronos` suite |
| `test_cors.nim` | CORS middleware: Access-Control-* on cross-origin requests, preflight answered with 204, origin allowlist rejects others |

### Request & response API

| Test | Verifies |
|------|----------|
| `test_cookies.nim` | Cookie round-trip (`req.cookies` / `Set-Cookie` building) over h1, h2 and h3, incl. recombining split `cookie` fields (RFC 7540 8.1.2.5 / RFC 9114 4.2.1) |
| `test_signed_cookies.nim` | HMAC-signed cookies (`setSignedCookie` / `cookies.signed`): SHA-256/-1/-512; tamper, wrong secret or wrong algo yield none |
| `test_json.nim` | `req.json` (lazy-parsed + cached, empty body -> `{}`, raises on malformed) and `res.send(json)` |
| `test_content.nim` | `req.form` (application/x-www-form-urlencoded) and content negotiation (`req.accepts` / `acceptsLanguage`) |
| `test_multipart.nim` | multipart/form-data (RFC 7578): pure parser plus `req.form` / `req.files` end-to-end with a real curl `-F` upload |
| `test_response_headers.nim` | `res.headers` pending headers (middleware/handler) merged into the eventual send; the send call's headers win per name |
| `test_early_hints.nim` | 103 Early Hints (`res.earlyHints` / `res.informational`) before the final response, over HTTP/1.1 and HTTP/2 |
| `test_trailers.nim` | Request trailers (`req.trailers`) over h1 chunked framing and an h2 trailing HEADERS frame, plus the framing fields a `res.trailers` section must never carry on either (delivery: `test_streaming.nim`) |

### Streaming & static files

| Test | Verifies |
|------|----------|
| `test_streaming.nim` | Response body streaming (`res.sendHead` / `write` / `finish`) |
| `test_sse_streaming.nim` | Streaming API end-to-end over HTTP/1.1 (SSE pattern); `id` / `event` / comment sanitization (CR, LF, NUL) and the empty-`id` rule, asserted against the exact wire bytes (#265) |
| `test_streaming_request.nim` | Streaming request bodies via a `router.stream` route |
| `test_streaming_read.nim` | Pull-based request-body streaming (asyncdispatch adapter) |
| `test_streaming_drain.nim` | Awaitable outbound backpressure (producer yields on a full buffer) |
| `test_static_files.nim` | Static file serving (`res.sendFile`): status/headers/body over raw sockets |
| `test_serve_content.nim` | `serveContent` + `conditional.nim`: conditional GET (304), write preconditions (412), byte ranges (206 / multipart/byteranges / 416) |

### Server lifecycle & concurrency

| Test | Verifies |
|------|----------|
| `test_blocking.nim` | Worker pool / `req.blocking:` escape hatch |
| `test_blocking_args.nim` | `req.blocking(a, b, ...)`: values moved into the worker, usable by name in the block (the refcount race only shows under `nimble testrace` / TSan) |
| `test_blocking_guard.nim` | Compile-time guard on `req.blocking` captures: value data allowed, ref/ptr/closure rejected, `isolate(...)` may cross |
| `test_blocking_pool.nim` | Worker-pool load shedding: a saturated pool answers 503 (`maxBlockingQueue`); `close()` detaches a wedged worker after `shutdownHardTimeout` (#204) |
| `test_conn_table.nim` | Growth-stable connection table: a slot keeps its address across growth, and a high fd arriving while a `blocking:` worker pins a slot is served instead of silently dropped (#343). Built with `-d:vortexConnBlock=8` from its sibling `tests/test_conn_table.nims` so the growth path needs only a couple of dozen connections |
| `test_graceful_shutdown.nim` | `requestShutdown()` drains in-flight requests, frees the port |
| `test_multi_server.nim` | Multiple `Server` instances in one process are independent |
| `test_remote_address.nim` | `req.remoteAddress` (peer IP) and `req.forwardedFor` (SEC1) |
| `test_forwarded.nim` | X-Forwarded-Proto/-Host/-For and RFC 7239 Forwarded believed only from `settings.trustedProxies`, ignored otherwise (fail-safe) |
| `test_proxy_protocol.nim` | PROXY protocol v1/v2 parsing + trust gating; overrides `req.remoteAddress` (SEC1) |

### Security

| Test | Verifies |
|------|----------|
| `test_security_parsing.nim` | Request smuggling, integer overflow, pure/fast parser hardening |
| `test_security_dos.nim` | Live-server denial-of-service budgets (asserts the secure behavior) |
| `test_security_headers.nim` | `securityHeaders()` OWASP baseline + `req.isSecure` gating (SEC2) |
| `test_security_headers_toggle.nim` | `settings.securityHeaders` auto-inject toggle |
| `test_ratelimit.nim` | Per-client token-bucket rate limiting (SEC3, OWASP API4:2023) |

> The compression tests (`test_compression`, `test_streaming_compression`,
> `test_request_decompression`, `test_zstd_compression`) and the TSan suites
> `test_thread_race` and `test_blocking_race` match the default `tests/test_*.nim`
> glob but only carry weight with the right build: the compression tests skip
> without their `-d:http*` flags (CI's `NIM_COMPRESS=1` supplies them; a plain
> local `nimble test` skips them), and `test_thread_race` / `test_blocking_race`
> only detect their races under ThreadSanitizer. All have dedicated tasks too
> (see [Opt-in feature tests](#opt-in-feature-tests)).

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
| `nimble testrace` | **yes** (`testrace`) | Four ThreadSanitizer regression suites: `test_thread_race` (the handler/stream-route closure refcount race across loop threads at `start()`/shutdown), `test_blocking_race` (C3/IMP2 -- a `req.blocking:` worker reading a request snapshot rather than live h2 state, under concurrent h2c blocking requests -- plus the awaitable-emit double-release race: many concurrent h2 streams whose awaitable `req.blocking` bodies emit their response inside the body, so the prNone response and the prAwait omBlockingDone must not double-release the pkAwait pin), `test_blocking_args` (the `req.blocking(a, b, ...)` box refcount touched on one thread only), and `test_router_race` (concurrent route-trie traversal on a multi-threaded server). TSan aborts on any data race. |
| `nimble testchronos` | **yes** (`testchronos`) | The chronos async adapter: the shared `test_adapter.nim` suite rebuilt with `-d:vortexChronos`; chronos is opt-in so this build is kept out of the default suite. |

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

## Stress soaks (pass/fail)

Focused soak tests that drive **one workload** at a vortex server, sustained, and
**verify** it: streaming transfers are checksummed and any mismatch, echo
mismatch, non-2xx, or missing SSE event **hard-fails**. Responses are discarded
so memory stays flat; the server's CPU/RSS is printed each interval. Each task
builds the server (a **protocol × server-runtime** matrix) and a load client,
which is an axis of its own (`VORTEX_CLIENT`): the Python canary (httpx +
websockets + aioquic) by default, or a compiled Nim navi client. Local-only. See
`conformance/stress/README.md`.

| Task | Workload |
|------|----------|
| `nimble stressRequests` | buffered GET/POST/PUT at `/echo` with req/resp compression |
| `nimble stressWs` | persistent WebSocket echo |
| `nimble stressSse` | SSE subscribe; server drops mid-stream; reconnect + Last-Event-ID |
| `nimble stressStreamUpload` | stream up; the **server** verifies the SHA-1 |
| `nimble stressStreamDownload` | stream down; the **client** verifies the SHA-1 |
| `nimble stressMixed` | **all five of the above at one server at the same time**, with the cell's workers split across them -- one transfer in flight per client for each streaming slice, the rest shared by `requests`/`ws`/`sse` (`VORTEX_MIX`); progress is checked per workload |
| `nimble stress` | short smoke of all six (default 20 s; honors an explicit `VORTEX_SECONDS` / `VORTEX_STREAM_BYTES`); fails on any. `run.sh` inlines a per-cell smoke size: 64 MiB for the five single-workload cells at **any** smoke duration, and the `mixed` short default (2 MiB) for `mixed` |

`nimble stressMixed` is the only soak that drives more than one workload at a
time, so it is the only one that can see interactions *between* workloads: a
bulk transfer competing with short requests for a loop thread, an idle SSE
stream next to a busy upload on one QUIC connection, h2 flow control shared
between one big stream and many small ones. The chaos sidecar has always
generated such traffic but never verified it (it swallows its errors by
design), so the bytes went unchecked. `nimble stress` runs it as a sixth short
cell per matrix entry. Its report line carries a per-interval delta next to each
slice's cumulative tally, so a slice that stops counting is visible without
diffing successive lines; a slice that wedges outright blocks the cell and trips
the client's `deadline + 60 s` stall net, exactly as in a single-workload soak.

Configured by `VORTEX_*` env (mirrors nim-navi's `NAVI_*`); the matrix is
`VORTEX_PROTO` × `VORTEX_SERVER`:

| Var | Default | Description |
|-----|---------|-------------|
| `VORTEX_PROTO` | `h2` | Transport: `h1` \| `h2` \| `h3` \| `all` (`all` = h1 + h2 + h3; h3 drives QUIC via aioquic and runs all six workloads, `mixed` included, with `ws` over RFC 9220 Extended CONNECT; h3 cells reuse the h2 server image, so the extra cost is one client run per cell, see the stress README) |
| `VORTEX_SERVER` | `sync` | Handler runtime: `sync` \| `async` \| `async-await` \| `chronos` \| `chronos-await` \| `all` (`async`/`chronos` = `vortex/asyncdispatch` / `vortex/chronos` without an in-handler `await`; the `-await` variants exercise the `await` path) |
| `VORTEX_CLIENT` | `python` | Which load client drives the cells: `python` \| `navi` \| `all`. `python` is the httpx + websockets + aioquic canary, the default and the harness's interop reference (and its only non-ngtcp2 QUIC stack); `navi` is the compiled Nim client, for the cells where the Python event loop and not vortex is the ceiling; `all` runs every cell **twice**, python then navi, with the client as the innermost loop so both hit the same freshly built server image. The chaos sidecar stays Python either way |
| `VORTEX_NAVI_BACKEND` | `chronos` | `chronos` \| `asyncdispatch`: the navi client backend the binary is **built** against. A docker build arg, so it is fixed per image rather than per cell |
| `VORTEX_NAVI_REF` | the sha pinned in `conformance/stress/client/navi/Dockerfile` (nim-navi `62244a8`) | nim-navi ref the navi client image is built from; empty keeps the pin. Pinned, not latest, so a navi change cannot silently move vortex's numbers. Pass a **sha**: a branch or tag name is frozen by the docker build cache at its first build on that host |
| `VORTEX_SECONDS` | `60` | Runtime per cell, in seconds |
| `VORTEX_REPORT_SECONDS` | `60` | Cadence of the status-code + server-RSS report |
| `VORTEX_CONCURRENCY` | `32` | In-flight requests per client (async fan-out width); under `mixed` this is the per-client worker budget, **split** across the five workloads rather than given to each, and it must be at least the number of workloads in the mix (5 by default) -- a smaller value is refused with exit 2 instead of overshot |
| `VORTEX_CLIENTS` | `3` | Client workers per cell |
| `VORTEX_REQ_COMPRESSION` | `gzip` | Request-body encoding the client sends (server decompresses): `none` \| `gzip` \| `br` \| `zstd` |
| `VORTEX_RESP_COMPRESSION` | `gzip` | Response encoding the server applies: `none` \| `gzip` \| `br` \| `zstd` |
| `VORTEX_STREAM_BYTES` | `1073741824`, or `67108864` when `VORTEX_SECONDS` < 1200; `mixed`: `16777216`, or `2097152` when `VORTEX_SECONDS` < 1200 | Streaming transfer size in bytes: 1 GiB for a real soak, 64 MiB for a short run, because one 1 GiB transfer takes ~125 s on `streamupload` h3 and ~163 s on `streamdownload` h3 (4-15 s on h1/h2) and a cell that finishes none counts none. The 1200 s threshold is ~7x that worst case: counting iterations needs a comfortable multiple of one transfer, and these soaks are run oversubscribed (eight or more cells at one host), where a transfer takes several times its measured best. `mixed` follows the same rule at 16 MiB / 2 MiB: its streaming slices share one client event loop with 30 request/ws/sse workers, so a mixed h3 download moves ~0.2 MB/s whatever the body size, which is ~10 s for 2 MiB and ~90 s for 16 MiB. An explicit value always wins; each cell prints the size it ran at in its banner, and `nimble stress` inlines a per-cell smoke size |
| `VORTEX_MIX` | `requests=40,ws=20,sse=20,streamupload=10,streamdownload=10` | `mixed` only: how one cell's worker budget splits across the five workloads. Weights, normalized by the sum of the weights that compete for the same workers (so `requests=100` alone is not "100%"); an omitted workload keeps its default and an explicit `0` drops it from the cell (and from the progress check). For `streamupload`/`streamdownload` the weight is **presence-only**: they are fixed at one transfer in flight per client. The rest is allocated by largest remainder with a floor of one worker each. A repeated key or a non-integer weight exits 2 |
| `VORTEX_RUN_ID` | this run's PID | Isolation id for the docker network / container / image names, so several runs can go in parallel without clobbering one another |
| `VORTEX_CHAOS` | `all` | Chaos sidecar: `none` \| `all` \| CSV of `slowread` \| `slowwrite` \| `idle` \| `abort` \| `vanish`. Launches a second, **unverified** misbehaving client per cell alongside the verified canary (see below); `none` = no sidecar (and no drain pause), the behavior from before the knob existed |
| `VORTEX_CHAOS_CONC` | `8` | Chaos sidecar worker count |
| `VORTEX_CHAOS_SEED` | `1` | Seed for the sidecar's per-worker RNG, so a failing chaos schedule replays exactly |
| `VORTEX_CHAOS_GATE_SECONDS` | `180` | How long a cell waits for the sidecar's `chaos: baseline fds=N` line before giving up on the cell; its pre-baseline warm-up takes minutes on a loaded h3 host |
| `VORTEX_CHAOS_DRAIN_SECONDS` | `150` | How long a cell waits for the sidecar to exit after a passing canary (drain pause plus settle re-sampling); on cap the cell fails as a sidecar watchdog (exit 3) |

The `VORTEX_SERVER` axis runs each soak against the sync, `vortex/asyncdispatch`,
and `vortex/chronos` servers - e.g. `VORTEX_SERVER=chronos nimble stressWs`
exercises chronos's WebSocket path under load.

`VORTEX_CLIENT` makes the **load client** an axis as well. The Python canary is
the default and stays the interop reference: a green run proves vortex serves a
widely deployed third-party stack (httpx, h2, websockets, aioquic) under load,
and aioquic is the only QUIC implementation in the harness that is not ngtcp2.
`VORTEX_CLIENT=navi` swaps in a compiled Nim client built on navi
(`conformance/stress/client/navi/`) that verifies exactly the same contract and
prints exactly the same line grammar - the same three-token
`[<workload> <proto> <server>]` report prefix, the same pass/`FAIL` banners, the
same exit codes, config errors on stdout with exit 2 - so a watcher written
against a python log works on a navi log unchanged; the client is named by the
cell banner's `client=navi/<backend>` token and by a `client: navi/<backend>
<sha>` header line, never by a fourth prefix token; the navi client also prints
its own `client: rss ... heap ...` footprint beside each report line, and its
backend defaults to chronos because navi's asyncdispatch timeout guard pins
completed requests for the timeout window (nim-navi #468), and it forces an
ORC cycle collection every second because the runtime's adaptive trigger stops
firing in an async program (an `sse` h1 cell reached 15 GB RSS in 120 s without
it). Reach for it when the
question is vortex's own throughput, h3 behaviour under a peer that is not the
bottleneck, or a cross-check against an independent HTTP implementation:
measured back to back in 60 s cells on one host, navi completed 5.2x the h2
`requests` of python (673968 against 130464) and moved 5.8-5.9x the bytes on the
h3 streaming cells (245 and 437 MB/s against 42 and 74 MB/s), so most of the
harness's h3 figures were aioquic's. Two caveats go with it. vortex and navi share an
author and the ngtcp2 + nghttp3 QUIC stack, so a cell that passes only under navi
is not interop evidence and a navi h3 pass is not foreign-stack evidence; and a
failure under navi has two suspects, so re-run the cell with
`VORTEX_CLIENT=python` and reproduce the request with `curl` / `h2load` / the
Python client before touching vortex. The sizing figures above and the 1200 s
`VORTEX_STREAM_BYTES` threshold were measured at the **Python** client, and the
defaults stay client-agnostic until navi figures exist.

`VORTEX_CHAOS` adds a **chaos sidecar**: a second client container that
misbehaves on purpose (slow reads, drip-fed uploads, idle connections,
mid-transfer aborts, abrupt vanishing with no goodbye) while the verified
workload keeps running unchanged as the canary. Its induced transport errors are
expected and swallowed; what it asserts is server health - the canary must still
pass, and the server's open-fd count (a third field on `/stats`) must return to
its pre-run baseline after a drain pause, so teardown leaks fail the cell.
Verdicts merge canary-first: the sidecar can add a failure but never mask one.
On top of the five generic behaviors, the sidecar runs **workload-targeted**
variants selected by `VORTEX_WORKLOAD` (slow, idle, and vanishing SSE clients
for `stressSse`, half-closing WebSocket clients for `stressWs`, mid-body-dying
uploaders for `stressStreamUpload`, ...); enabling a style enables both its
generic and targeted forms, and `stressMixed` gets **every** targeted variant
since it drives every route at once. Chaos is on by default; `VORTEX_CHAOS=none` gives a
chaos-free run (no sidecar, no drain pause). See `conformance/stress/README.md`
for the behavior catalog, exit codes, and per-transport degraded modes.

---

## Interactive load & stress (Grafana)

Two Docker-based tools that drive load at a vortex server and stream metrics to a
local Grafana + Prometheus stack for live charts. Unlike the pass/fail load smokes
above (`h2load`/`h3load`), these are **interactive**: they leave the observability
stack running so you can watch a run and compare runs over time. Not wired into
CI. Each brings up its own stack on its own ports; stop it with the runner's
`--down` (add `-v` to also drop retained history).

| Task | CI | Driver | Grafana | For |
|------|----|--------|---------|-----|
| `nimble loadtest` | local | k6 | http://localhost:3000 | Hold a chosen load; chart client throughput, latency (p50/p95/p99), errors, plus server CPU/memory |
| `nimble saturate` | local | h2load | http://localhost:3001 | Saturate (max req/s); chart the server's own CPU/memory live, with achieved req/s as a summary |

Both build the selected backend(s) (`BACKEND=h1|h2|h2-gzip|all`) from the shared
`conformance/loadtest/loadtest_server.nim` (TechEmpower-style `/plaintext`,
`/json`, `/big`) and show the server's own CPU/memory sampled from `docker stats`
(pushed to a Pushgateway -- cAdvisor can't name containers on Docker Desktop).

**`nimble loadtest` (k6).** Holds a load and charts the client's view. Also
varies the handler runtime (`RUNTIME=sync|async|async-await|chronos|chronos-await|all`)
and the load model (`MODE=throughput|rate`); knobs: `DURATION`, `VUS`, `RATE`,
`ENDPOINT`. Latency is a Prometheus native histogram. k6 cannot drive HTTP/3 or
h2c, and its memory grows with total requests, so long high-rate runs are
memory-bound. See `conformance/loadtest/README.md`.

**`nimble saturate` (h2load).** Saturates the server so the *client* is not the
bottleneck; knobs: `DURATION` (seconds), `CONNS`, `STREAMS` (h2), `ENDPOINT`.
Achieved req/s is a summary stat, not a live curve (h2load reports only at the
end); the live signal is the server's CPU/memory. h2load drives h1/h2c/h2-TLS;
for HTTP/3 saturation use `nimble h3load`. (Formerly `nimble stress`; that name
is now the per-workload soaks above.) See `conformance/stress/README.md`.

---

## Fuzzing

| Task | CI | Verifies |
|------|----|----------|
| `nimble fuzz` | **yes** (`fuzz`) | libFuzzer targets over the HTTP/1.1 parser, the HPACK decoder and the WebSocket permessage-deflate path (30s per target in CI); a crash writes a reproducer and exits non-zero. |

---

## Benchmarks

Performance measurement, not pass/fail (CI does not gate on throughput numbers).

Dockerized per-workload perf suite (same `VORTEX_*` knobs as the stress soaks;
see `conformance/bench/README.md`):

| Task | Measures |
|------|----------|
| `nimble benchRequests` | Buffered GET/POST/PUT throughput (req/s) + latency |
| `nimble benchWs` | WebSocket echo (msg/s) + round-trip latency |
| `nimble benchSse` | SSE (evt/s) + inter-event latency |
| `nimble benchStreamUpload` | Stream upload throughput (MB/s) |
| `nimble benchStreamDownload` | Stream download throughput (MB/s) |
| `nimble bench` | Short smoke of all five above (20 s, 64 MiB) |

Local (non-Docker) throughput tools:

| Task | Measures |
|------|----------|
| `nimble perf` | HTTP/1.1 throughput vs httpbeast / chronos / mummy |
| `nimble perf2` | HTTP/2 throughput |
| `nimble benchServer` | Builds the release TechEmpower server (`bench/handlers`) for `bench/run.sh` (wrk/oha/ab/h2load) |

The Dockerized `bench` suite runs anywhere (builds happen in Linux containers);
its numbers are for relative/regression tracking, not absolute peak (the
Python client caps cheap-endpoint throughput). Use `nimble saturate` (h2load)
for absolute peak req/s and `nimble h3load` for HTTP/3 throughput.
