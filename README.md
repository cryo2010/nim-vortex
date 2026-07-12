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
- `bench/run.sh` drives wrk/oha/ab and h2load against `bench/handlers`.

The chronos adapter is covered by `nimble testchronos` (its dependency is
opt-in, so it is kept out of the default `nimble test`).

## Security

Rapid Reset, framing floods, decompression bombs, request smuggling,
slowloris, and resource exhaustion are defended with configurable limits
and covered by tests and fuzzers. See [SECURITY.md](SECURITY.md).

## Status

Pre-1.0. Deferred (planned): streaming request/response
bodies, dynamic QPACK, h2c upgrade, Windows.

## Thanks

- [httpbeast](https://github.com/dom96/httpbeast) proved the
  architecture this server is built on: one event loop per thread over
  `SO_REUSEPORT` listeners with handlers running inline. This package is
  in many ways a from-scratch continuation of that design with the
  protocol gaps (chunked bodies, HTTP/2, HTTP/3) filled in.
- [mummy](https://github.com/guzba/mummy) made the case that blocking
  handler code deserves first-class support instead of async coloring;
  its worker-pool design directly shaped `blocking:`.
