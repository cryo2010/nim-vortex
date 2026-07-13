# vortex


[![CI](https://github.com/cryo2010/nim-vortex/actions/workflows/ci.yml/badge.svg)](https://github.com/cryo2010/nim-vortex/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A fast HTTP server for Nim speaking **HTTP/1.1, HTTP/2, and HTTP/3** from a
single port and a single handler API.

- **Architecture**: one event loop per thread (`SO_REUSEPORT`,
  kqueue/epoll via `std/selectors`), handlers run inline on the loop:
  the httpbeast model, with the protocol gaps filled in.
- **Blocking escape hatch**: `req.blocking:` moves a handler body to a
  worker pool where synchronous DB drivers, file IO, and CPU work are
  safe; routes that never use it pay zero overhead.
- **Future-agnostic**: handlers are plain procs and responses may be
  deferred: no async runtime dependency, no Future type in the core.
  Optional asyncdispatch and chronos adapters layer `await` support on
  top through the same loop hook.
- **Protocols**: HTTP/1.1 (keep-alive, pipelining, chunked bodies,
  100-continue), HTTP/2 (TLS ALPN and h2c prior knowledge; h2spec-clean),
  HTTP/3 over QUIC (OpenSSL >= 3.5 server API), with automatic `Alt-Svc`
  advertisement, plus **WebSockets** (RFC 6455) over `ws://` and `wss://`.
- **Dual-stack**: binds IPv4 and IPv6 by default (`address = "::"` with
  IPv4-mapped, falling back to IPv4-only where IPv6 is unavailable); set an
  explicit `address` to pin one family.
- **Dependencies**: none beyond OpenSSL >= 3.5 at runtime for TLS/h2/h3.
  Build with `-d:plainHttp` for a zero-dependency cleartext (h1 + h2c)
  server.

## Quick start

```nim
import vortex

proc handler(req: Request, res: Response) {.gcsafe.} =
  case req.path
  of "/":
    res.send(Http200, "Hello, World!", "text/plain")
  of "/report":
    req.blocking:                       # runs on the worker pool
      let data = expensiveBlockingCall()
      res.send(Http200, data, "application/json")
  else:
    res.send(Http404)

run(handler, initSettings(port = Port(8080)))
```

TLS + HTTP/2 + HTTP/3:

```nim
run(handler, initSettings(port = Port(8443),
                          certFile = "cert.pem", keyFile = "key.pem"))
```

Router:

```nim
proc getUser(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "user " & req.param("id"))

var router = newRouter()
router.get("/users/:id", getUser)
router.get("/static/*", serveFile)
run(router.toHandler, initSettings(port = Port(8080)))
```

Async handlers (optional adapter; asyncdispatch drivers like asyncpg):

```nim
import vortex
import vortex/adapters/asyncdispatch

proc getUser(req: Request, res: Response) {.async.} =
  let user = await db.getUser(req.param("id"))   # loop keeps serving
  res.send(Http200, user.toJson)

var router = newRouter()
router.get("/users/:id", getUser)    # async handlers register directly
run(router.toHandler, initSettings(port = Port(8080)))
```

Inside an async handler `req.blocking:` still works for synchronous
libraries, and unlike `blocking:` the async body may capture locals
(it never leaves the loop thread). Without a router, wrap a
`proc (req: Request, res: Response) {.async.}` with the adapter's `toHandler`, or use
`req.doAsync:` inside a plain handler.

For chronos-based drivers, import `vortex/adapters/chronos` instead: it
exposes the identical API (`{.async.}` handlers, `toHandler`,
`req.doAsync:`) over chronos's `Future`. Import only one async adapter
per program.

chronos is **not** a vortex dependency (a bare `import vortex` never
needs it), so using this adapter means adding chronos to your own
project alongside vortex:

```
requires "chronos >= 4.0.0"
```

Without it the adapter import fails to compile (`cannot open file:
chronos`). The asyncdispatch adapter has no such step because
asyncdispatch ships in Nim's stdlib. For the same reason chronos stays
out of the default `nimble test`; its suite runs via `nimble
testchronos`.

Embedded / test usage: `var srv = start(handler, settings)` returns
immediately (`srv.port` has the resolved port); `srv.close()` shuts down.

## WebSockets

A handler detects the upgrade and calls `req.acceptWebSocket()`; set
`onMessage` / `onClose` callbacks that run on the loop thread (they may
capture locals). `ws.send` / `ws.close` are non-blocking and safe to call
from any thread, so you can push to a socket from a worker or a timer.

To negotiate a subprotocol, pass your supported list (in preference order)
to `req.acceptWebSocket(["chat", "json"])`; the first one the client also
offered is echoed in the handshake and available as `ws.subprotocol` ("" if
none matched).

```nim
proc handler(req: Request, res: Response) {.gcsafe.} =
  if req.isWebSocketUpgrade:
    let ws = req.acceptWebSocket()
    ws.onMessage = proc(ws: WebSocket, data: string, kind: WsKind) {.gcsafe.} =
      ws.send(data, kind)                 # echo
    ws.onClose = proc(ws: WebSocket, code: uint16, reason: string) {.gcsafe.} =
      discard
  else:
    res.send(Http200, "…", "text/html")

run(handler, initSettings(port = Port(8080)))
```

`onMessage` runs on the loop thread, so it must not block. For blocking
work in response to a message (a sync DB query, file IO), use
`ws.blocking:` to run it on the same worker pool that backs the HTTP
`blocking:`, no thread of your own required. The message is passed in as
`msg` (the body cannot capture locals, like the HTTP form); reply with
`ws.send`:

```nim
ws.onMessage = proc(ws: WebSocket, data: string, kind: WsKind) {.gcsafe.} =
  ws.blocking(data):
    let rows = db.getAllRows(sql"…")    # blocking is safe here
    ws.send($rows)
```

Like the HTTP `blocking:`, the connection is pinned while the body runs: the
loop holds off dispatching further frames until it returns, so messages from
one connection are handled one at a time and in order, and a slow body
applies backpressure to that client. Different connections still run in
parallel across the pool.

For genuinely async drivers (asyncdispatch/chronos `Future`s), import an
async adapter and use `ws.doAsync:` to `await` on the loop thread. Captures
are allowed; an uncaught exception closes the socket with 1011:

```nim
import vortex/adapters/asyncdispatch   # or vortex/adapters/chronos

ws.onMessage = proc(ws: WebSocket, data: string, kind: WsKind) {.gcsafe.} =
  ws.doAsync:
    let user = await db.getUser(data)   # loop keeps serving during the await
    ws.send(user.toJson)
```

When you push faster than a peer can read, `ws.send` parks the overflow in
the connection's write buffer. `ws.bufferedAmount` reports that backlog in
bytes (queued but not yet written to the socket, like the browser
`WebSocket.bufferedAmount`), and `ws.onDrain` fires on the loop thread once
it empties, so you can pause a producer while the backlog is high and resume
from the drain:

```nim
proc pump(ws: WebSocket) {.gcsafe.} =
  while ws.bufferedAmount < 1 shl 20 and source.hasNext:  # cap the backlog at 1 MiB
    ws.send(source.next)

ws.onMessage = proc(ws: WebSocket, data: string, kind: WsKind) {.gcsafe.} =
  ws.onDrain = pump                       # resume when the write buffer drains
  pump(ws)
```

`bufferedAmount` is a loop-thread snapshot: read it from a handler callback,
not another thread (off-loop `send`s queue on the outbox and are not counted
until the loop picks them up).

Works over `ws://` and, with a cert, `wss://`. Fragmented messages are
reassembled (bounded by `maxWsMessageSize`), ping/pong and the close
handshake are handled for you, and text is validated as UTF-8. Idle
connections are kept alive and half-open ones reaped automatically: after
`wsPingInterval` seconds without a frame the server sends a ping, and if no
reply arrives within `wsPongTimeout` it closes the connection (set
`wsPingInterval = 0` to disable; idle ping/timeout applies to HTTP/1.1
WebSockets). Building with `-d:wsDeflate` (links zlib) adds
permessage-deflate (RFC 7692) message compression, negotiated automatically.

The same handler API also serves WebSockets over **HTTP/2 (RFC 8441)** and
**HTTP/3 (RFC 9220)**: the server advertises
`SETTINGS_ENABLE_CONNECT_PROTOCOL`, and an Extended CONNECT
(`:protocol websocket`) opens a WebSocket on a single stream, multiplexed
with ordinary requests on the connection. `isWebSocketUpgrade` /
`acceptWebSocket` transparently handle all three transports, so the same
`onMessage` / `ws.send` / `ws.blocking:` / permessage-deflate code works over
h1, h2, and h3. (Browsers still use HTTP/1.1 for WebSockets; h2/h3 are for
clients that prefer a single multiplexed connection.)

### Roadmap and Autobahn conformance

WebSocket support is validated against the
[Autobahn|Testsuite](https://github.com/crossbario/autobahn-testsuite),
the reference conformance suite for RFC 6455 (the WebSocket equivalent of
the `h2spec` check used for HTTP/2). `nimble autobahn` runs it in Docker.
The gaps below are tracked as TODO; where a gap is a known difference from
Node's `ws` (the de facto reference implementation), it is noted.

- [x] **Autobahn conformance**: `nimble autobahn` (see
  [conformance/autobahn/](conformance/autobahn/)) runs the full suite
  against a vortex echo server. All cases pass (framing, pings/pongs,
  reserved bits, opcodes, fragmentation, UTF-8, close handling, limits, and
  permessage-deflate: groups 1-13).
- [x] **permessage-deflate** (RFC 7692) message compression, opt-in via
  `-d:wsDeflate` (links zlib). Off by default, so the default and
  `-d:plainHttp` builds are unchanged and take on no compression
  dependency or attack surface; inbound decompression is bounded by
  `maxWsMessageSize` (close 1009) and fuzzed.
- [x] **Subprotocol negotiation**: pass your supported protocols to
  `req.acceptWebSocket(["chat", ...])`; the first that the client also
  offered (server preference) is echoed in the handshake and readable via
  `ws.subprotocol`.
- [x] **Backpressure introspection**: `ws.bufferedAmount` reports the write
  backlog and `ws.onDrain` fires when it empties, so an application pushing
  faster than a slow consumer reads can throttle and resume (see above).
- [x] **Per-connection backpressure for `ws.blocking:`**: the connection is
  pinned while the body runs, so one message is processed at a time and in
  order, matching the HTTP `blocking:` semantics (see above).
- [x] **HTTP/2 WebSockets (RFC 8441)** via Extended CONNECT: message
  send/receive, fragmentation, control frames, close, cross-thread
  `ws.send`, permessage-deflate, and per-stream `ws.blocking` (one stream is
  pinned without stalling the others). Idle ping/timeout over h2 is not yet
  wired (h2 has connection-level PING liveness).
- [x] **HTTP/3 WebSockets (RFC 9220)** via Extended CONNECT over QUIC: the
  same feature set as h2 (send/receive, fragmentation, control frames, close,
  cross-thread `ws.send`, permessage-deflate, per-stream `ws.blocking`).
  Verified end-to-end against aioquic (`nimble h3websocket`), since no browser
  or `curl` speaks WebSockets over HTTP/3. Idle ping/timeout over h3 is not
  wired (QUIC keepalive covers liveness).

## Handler rules

- Handlers run **inline on the event loop**: never block in them (no sync
  DB calls, no `sleep`). Use `req.blocking:` for anything that blocks.
- Inside `blocking:` the request and response are available as `req`
  and `res`; the body cannot capture surrounding locals (it runs on
  another thread); read request data through `req`, which remains valid
  until you send the response.
- Handlers receive the read half (`req`) and the write half (`res`);
  `res.send(...)` may be called after the handler returns (deferred
  responses), and sending through a dead connection is a safe no-op.
  (`std/httpclient` also exports a `Response` type; in modules using
  both, `import std/httpclient except Response`.)
- Route parameters are per-request state: `req.param("id")` /
  `req.params` work anywhere the handle does, including inside
  `blocking:` bodies. (Stored eagerly at match time: the router computes
  them while matching, so there is nothing to defer.)
- `req.path` is the raw request target (query string included, matching
  httpbeast). `req.url` gives the parsed form (`req.url.path` excludes
  the query) and `req.query` a decoded parameter Table; both are lazy
  and cached per request, on any protocol.

## Streaming responses

For bodies you do not want to buffer whole (large downloads, server-sent
events, proxying), stream the response instead of `res.send`:

```nim
proc handler(req: Request, res: Response) {.gcsafe.} =
  res.sendHead(Http200, "text/plain")   # status + headers, no Content-Length
  res.write("first chunk\n")
  res.write("second chunk\n")
  res.finish()                          # terminate the body
```

`sendHead` opens the body (HTTP/1.1 uses `Transfer-Encoding: chunked`; HTTP/2
and HTTP/3 leave the stream open with DATA frames), `write` appends a chunk,
and `finish` ends it (optionally with trailers over HTTP/1.1). The framing is
identical across all three protocols.

For the common "produce it all inline" case (a file download), the `res.stream`
template brackets a block with `sendHead` and `finish` (and closes the stream
even if the block raises):

```nim
proc download(req: Request, res: Response) {.gcsafe.} =
  res.stream(Http200, "application/octet-stream"):
    var f = open("big.bin")
    defer: f.close()
    var buf = newString(64 * 1024)
    while true:
      let n = f.readChars(buf)
      if n == 0: break
      discard res.write(buf.toOpenArray(0, n - 1))
```

It takes an optional headers argument (`res.stream(Http200, ct, headers): ...`).
For a backpressure-driven or async producer, drive `sendHead`/`write`/`finish`/
`onDrain` directly instead.

If the block raises, the template calls `res.abort()` rather than `finish` (and
re-raises). Because the status and headers are already committed once `sendHead`
has run, a failure partway cannot become a `500`; `abort` instead makes the
truncation visible so the client does not mistake a short body for a complete
one: HTTP/1.1 closes the connection before the terminating chunk, and HTTP/2 /
HTTP/3 reset the stream with an internal error. Call `res.abort()` yourself if
you catch an error mid-stream in the manual API.

`write` returns `false` once the unsent backlog reaches `respHighWater`; a
producer that outruns a slow client should pause and resume from `onDrain`,
the same backpressure contract as WebSocket sends:

```nim
proc pump(res: Response) {.gcsafe.} =
  while moreData():
    if not res.write(nextChunk()):
      res.onDrain(pump)               # backed up: resume when it empties
      return
  res.finish()
```

`res.bufferedAmount` reports the current backlog. Streaming is driven on the
loop thread (from the handler or an async/onDrain callback); it composes with
the async adapters.

### Streaming request bodies

To consume a large upload without buffering it whole, register a route with
`router.stream` (or pass a `streamRoute` predicate to `start`). Its handler is
dispatched at headers-complete and reads the body incrementally via
`req.onBody`:

```nim
proc upload(req: Request, res: Response) {.gcsafe.} =
  req.onBody proc(chunk: openArray[char], last: bool) {.gcsafe.} =
    sink(chunk)                     # write to disk, hash, proxy, ...
    if last: res.send(Http200, "ok")

var router = newRouter()
router.stream(HttpPost, "/upload", upload)
start(router.toHandler, settings, router.streamPredicate)
```

Works on HTTP/1.1 (Content-Length and chunked), HTTP/2, and HTTP/3 (`last` is
true on the final chunk: the length boundary, the chunked terminator,
END_STREAM, or FIN). Ordinary routes are unchanged and still get `req.body`;
the `streamRoute` predicate is only consulted when set, so a server with no
streaming routes keeps the buffered fast path at zero cost. HTTP/1.1
Content-Length uploads stream in bounded memory (consumed bytes are dropped);
chunked delivers incrementally, bounded per read.

With the async adapters, `await req.read()` pulls the body chunk by chunk, and
consumption drives **flow control**: HTTP/2 defers the per-stream
`WINDOW_UPDATE` until a chunk is read (the connection window stays eager, so one
slow stream never blocks the others), and HTTP/3 pauses draining the QUIC stream
past a high-water mark so OpenSSL stops extending the peer's window. A slow
consumer therefore throttles the sender end to end. In a plain (synchronous)
`onBody` handler this is automatic (the callback holds the loop while it runs);
`req.onBody(cb, manualAck = true)` + `req.ackBody(n)` expose the same control
directly.

## Build flags

Release builds: `--mm:orc --threads:on -d:danger --passC:-flto`
(`nimble bench` builds the benchmark server this way).

`-d:plainHttp` removes the OpenSSL dependency (and TLS/h2-over-TLS/h3).

`-d:wsDeflate` (link with `--passL:-lz`) enables WebSocket
permessage-deflate compression via zlib. Off by default so the standard
build keeps its OpenSSL-only footprint.

## Verification

- `nimble test`: parser/HPACK/QPACK unit tests (RFC vectors) plus
  integration suites for h1, h2 (curl), h3 (h3-capable curl), TLS,
  worker pool, and router.
- HTTP/2 conformance: `nimble h2spec` runs
  [h2spec](https://github.com/summerwind/h2spec) over TLS in Docker and
  fails on any failed test. See [conformance/h2spec/](conformance/h2spec/).
- HTTP/3 conformance: `nimble h3spec` runs
  [h3spec](https://github.com/kazu-yamamoto/h3spec)'s HTTP/3 + QPACK
  error-case group in Docker (15/15 pass). The QUIC transport group is
  OpenSSL's stack, not vortex, so it is excluded. See
  [conformance/h3spec/](conformance/h3spec/).
- HTTP/3 WebSocket conformance: `nimble h3websocket` runs an
  [aioquic](https://github.com/aiortc/aioquic) RFC 9220 client against a
  vortex echo server in Docker. See
  [conformance/h3websocket/](conformance/h3websocket/).
- HTTP/1.1 conformance: `nimble redbot` runs [REDbot](https://redbot.org)
  against a live server in Docker and fails on any BAD-level finding (or
  `sh conformance/run.sh` with a host REDbot). See
  [conformance/](conformance/). `nimble h1spec` additionally runs
  [h1spec](https://github.com/dropseed/h1spec)'s request/header/body/framing
  cases in Docker (32/32 pass). See [conformance/h1spec/](conformance/h1spec/).
- WebSocket conformance: `nimble autobahn` runs the
  [Autobahn|Testsuite](https://github.com/crossbario/autobahn-testsuite)
  in Docker (301/301 non-compression cases pass). See
  [conformance/autobahn/](conformance/autobahn/).
- Security scan: `nimble zap` runs the [OWASP ZAP](https://www.zaproxy.org/)
  packaged baseline (passive) scan against a hardened vortex site in Docker.
  Its rule config promotes the security-header rules the app satisfies to FAIL,
  so the run gates against a regression that drops one. See
  [conformance/zap/](conformance/zap/).
- `bench/run.sh` drives wrk/oha/ab and h2load against `bench/handlers`.

The chronos adapter is covered by `nimble testchronos` (its dependency is
opt-in, so it is kept out of the default `nimble test`).

## Security

Rapid Reset, framing floods, decompression bombs, request smuggling,
slowloris, and resource exhaustion are defended with configurable limits
and covered by tests and fuzzers. See [SECURITY.md](SECURITY.md).

## Status

Pre-1.0. Streaming response bodies (`res.sendHead`/`write`/`finish`) are
supported on h1/h2/h3; streaming request bodies are the next milestone.
Deferred (planned): streaming request bodies, dynamic QPACK, h2c upgrade,
Windows.

## Thanks

- [httpbeast](https://github.com/dom96/httpbeast) proved the
  architecture this server is built on: one event loop per thread over
  `SO_REUSEPORT` listeners with handlers running inline. This package is
  in many ways a from-scratch continuation of that design with the
  protocol gaps (chunked bodies, HTTP/2, HTTP/3) filled in.
- [mummy](https://github.com/guzba/mummy) made the case that blocking
  handler code deserves first-class support instead of async coloring;
  its worker-pool design directly shaped `blocking:`.
