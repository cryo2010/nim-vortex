# vortex

[![CI](https://github.com/cryo2010/nim-vortex/actions/workflows/ci.yml/badge.svg)](https://github.com/cryo2010/nim-vortex/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A fast HTTP server for Nim speaking **HTTP/1.1, HTTP/2, and HTTP/3** from a
single port and a single handler API.

```nim
import vortex

proc handler(req: Request, res: Response) {.gcsafe.} =
  case req.path
  of "/":       res.send(Http200, "Hello, World!", "text/plain")
  of "/report":
    req.blocking:                       # runs on the worker pool
      let data = expensiveBlockingCall()
      res.send(Http200, data, "application/json")
  else:         res.send(Http404)

run(handler, initSettings(port = Port(8080)))
```

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

**Platform:** POSIX only (Linux and macOS), by design. The core is built on
readiness-based `kqueue`/`epoll` and per-thread `SO_REUSEPORT` listeners, which
have no direct Windows equivalent; a `select()`-backed Windows port would
defeat the performance goal. On Windows, run vortex under WSL2 or a Linux
container (Docker).

## Contents

- [Quick start](#quick-start)
- [Settings](#settings)
  - [Transport Layer Security (TLS)](#transport-layer-security-tls)
- [Handlers](#handlers)
  - [Requests](#requests)
  - [Responses](#responses)
- [Routing](#routing)
- [Static files](#static-files)
- [Streaming](#streaming)
  - [Streaming requests](#streaming-requests)
  - [Streaming responses](#streaming-responses)
- [Compression](#compression)
- [Server-Sent Events](#server-sent-events)
- [WebSockets](#websockets)
- [Build flags](#build-flags)
- [Security](#security)
- [Thanks](#thanks)

## Quick start

`run` starts the server and blocks until a SIGINT/SIGTERM (or
`requestShutdown()`) arrives, then shuts down gracefully:

```nim
run(handler, initSettings(port = Port(8080)))
```

For embedding or tests, `start` returns immediately and `close` stops it:

```nim
var srv = start(handler, initSettings(port = Port(0)))   # port 0 = pick a free port
echo "listening on ", srv.port                           # the resolved port
# ... drive requests against srv.port ...
srv.close()
```

Shutdown is graceful either way: `requestShutdown()` (or a SIGINT/SIGTERM under
`run`, or `srv.close()`) stops accepting and closes the listener so the port
frees for a replacement, sends HTTP/2 and HTTP/3 `GOAWAY`, closes open
WebSockets with a `1001` (going away), and lets in-flight requests and streams
finish before closing. Idle keep-alive connections close promptly; anything
still running is force-closed once `shutdownGrace` seconds elapse.

## Settings

Server configuration is a value built with `initSettings(...)` and passed to
`run` or `start`. Beyond `port` and `address` (dual-stack by default), it
carries the TLS material, timeouts, worker/thread counts, and the feature
toggles used throughout this document:

```nim
run(handler, initSettings(
  port = Port(8080),
  address = "::",                 # dual-stack (default); pin a family with "0.0.0.0"
  numThreads = 0,                 # 0 = one event loop per core (SO_REUSEPORT)
  compress = true,                # response compression (needs a -d:http* build)
  decompressRequest = true,       # transparently decode gzip/br request bodies
  responseTimeout = 30,           # seconds a handler may take before the conn is closed
  shutdownGrace = 10))            # seconds to drain in-flight work on shutdown
```

**Client address behind a proxy.** `req.remoteAddress` is the direct peer.
Behind an L4 / TLS-passthrough load balancer (AWS NLB, HAProxy in TCP mode),
enable the **PROXY protocol** so vortex uses the real client address the
balancer prepends (v1 and v2, TCP over IPv4/IPv6), honored only from a trusted
peer:

```nim
initSettings(proxyProtocol = ppRequire,             # or ppOptional
             trustedProxies = @["10.0.0.0/8"])      # IPs/CIDRs; empty = any peer
```

`ppRequire` drops a connection without a valid header from a trusted peer;
`ppOptional` uses the header when present and otherwise treats the peer as a
direct client. A header from an untrusted peer is never believed. Behind an L7
proxy that sets `X-Forwarded-For`, recover the origin client from
`req.forwardedFor` under a trust policy you control (see [Requests](#requests)).

### Transport Layer Security (TLS)

Providing a certificate turns on TLS, which enables HTTP/2 (via ALPN) and
HTTP/3 (over QUIC):

```nim
run(handler, initSettings(port = Port(8443),
                          certFile = "cert.pem", keyFile = "key.pem"))
```

The cert and key can also come **from memory** instead of files — pass the PEM
directly (e.g. loaded from a secret manager), with `keyPassword` for an
encrypted key:

```nim
run(handler, initSettings(port = Port(8443),
                          certPem = vault.get("tls/cert"),
                          keyPem = vault.get("tls/key"),
                          keyPassword = vault.get("tls/key-pass")))
```

`certPem`/`keyPem` take precedence over `certFile`/`keyFile`; either source works
for HTTP/1.1, /2 and /3, and both compose with `server.reloadTls`. Any key type
OpenSSL accepts (RSA, ECDSA, Ed25519) is supported. `keyPassword` applies to a
file or in-memory key; without it, an encrypted key fails to start (rather than
prompting).

**PKCS#12 (.pfx/.p12)** bundles the cert, key, and chain in one blob — pass the
file or the bytes, with `keyPassword` as the bundle passphrase:

```nim
initSettings(pkcs12File = "server.p12", keyPassword = "…")   # or pkcs12 = bytes
```

**mTLS (client certificates)**: request or require a client cert and verify it
against a CA. `verifyClient = cvOptional` accepts connections with no cert but
validates any that is presented; `cvRequire` refuses the handshake without a
valid one. Inside a handler, `req.clientCertSubject` gives the verified client's
subject DN ("" if none):

```nim
initSettings(certFile = "cert.pem", keyFile = "key.pem",
             verifyClient = cvRequire, clientCaFile = "client-ca.pem")
# ... req.clientCertSubject -> e.g. "/CN=service-a"     (clientCaPem takes in-memory CA)
```

**SNI (per-hostname certificates)**: serve different certs by requested host. The
default cert is the fallback; `sni` adds host-specific certs (each from files,
PEM, or PKCS#12). A `host` of `*.example.com` matches a single leading label
(`api.example.com`, not `example.com` or `a.b.example.com`); an exact host wins
over a wildcard:

```nim
initSettings(certFile = "default.pem", keyFile = "default.key",
             sni = @[SniCertEntry(host: "*.example.com",
                                  certFile: "wild.pem", keyFile: "wild.key")])
```

**TLS version range**: `minTlsVersion` (default `tlsV12`) floors it; `maxTlsVersion`
(default `tlsMaxNone` = no cap) ceils it, e.g. `maxTlsVersion = tlsMax12` to keep
a client on 1.2. (QUIC/HTTP/3 is always 1.3.)

**OCSP stapling**: hand clients a cached OCSP response in the handshake so they
don't query the responder. Provide the DER bytes (refresh them out-of-band and
`reloadTls`); vortex doesn't fetch OCSP itself:

```nim
initSettings(certFile = "cert.pem", keyFile = "key.pem",
             ocspFile = "ocsp.der")        # or ocspResponse = derBytes
```

## Handlers

A handler is a plain `proc (req: Request, res: Response) {.gcsafe.}`. It runs
**inline on the event loop**, so it must never block (no sync DB calls, no
`sleep`). Read the request through `req`, reply through `res`; `res.send` may be
called after the handler returns (deferred), and sending through a dead
connection is a safe no-op.

For synchronous work (a sync DB driver, file IO, CPU-bound work), `req.blocking:`
moves the body to a worker pool. Inside it, `req`/`res` are available but the
body cannot capture surrounding locals (it runs on another thread); read what
you need through `req`:

```nim
proc handler(req: Request, res: Response) {.gcsafe.} =
  req.blocking:
    let rows = db.getAllRows(sql"select …")   # blocking is safe here
    res.send(Http200, $rows, "application/json")
```

**Async handlers** (optional adapter; asyncdispatch or chronos drivers) let a
handler `await` on the loop thread:

```nim
import vortex
import vortex/adapters/asyncdispatch          # or vortex/adapters/chronos

proc getUser(req: Request, res: Response) {.async.} =
  let user = await db.getUser(req.param("id"))   # loop keeps serving
  res.send(Http200, user.toJson, "application/json")

var router = newRouter()
router.get("/users/:id", getUser)               # async handlers register directly
run(router.toHandler, initSettings(port = Port(8080)))
```

Without a router, wrap a `proc (req, res) {.async.}` with the adapter's
`toHandler`, or use `req.doAsync:` inside a plain handler. Import only one async
adapter per program. chronos is **not** a vortex dependency (a bare
`import vortex` never needs it), so using that adapter means adding
`requires "chronos >= 4.0.0"` to your own project.

> `std/httpclient` also exports a `Response` type; in modules using both,
> `import std/httpclient except Response`.

### Requests

`Request` is a small handle (internally: the owning loop, the connection fd, a
generation counter, and an HTTP/2/3 stream id — you never touch these directly).
Everything is read through the accessors below, all valid on any protocol and
from a `blocking:` worker:

| Member | Result | What it gives |
|--------|--------|---------------|
| `req.method` | `HttpMethod` | request method (`HttpGet`, `HttpPost`, …) |
| `req.path` | `string` | raw request target, query string included |
| `req.url` | `Uri` | parsed target — `req.url.path` excludes the query (lazy, cached) |
| `req.query` | `Table[string, string]` | decoded query params, last value wins (lazy, cached) |
| `req.headers` | iterator `(string, string)` | every header pair (pseudo-headers skipped) |
| `req.header(name)` | `string` | one header, case-insensitive; "" if absent |
| `req.body` | `string` | request body (decompressed if `decompressRequest`) |
| `req.contentLength` | `int` | body length in bytes |
| `req.host` | `string` | `:authority` (h2/h3) or `Host` (h1) |
| `req.origin` | `string` | `Origin` header |
| `req.originAllowed(allowed, allowMissing = false)` | `bool` | Origin allowlist check (CSWSH defense) |
| `req.remoteAddress` | `string` | direct peer IP (real client IP under PROXY protocol) |
| `req.forwardedFor` | `seq[string]` | parsed `X-Forwarded-For` chain, client → nearest proxy |
| `req.clientCertSubject` | `string` | mTLS client-cert subject DN; "" if none |
| `req.isSecure` | `bool` | arrived over TLS/HTTPS or QUIC |
| `req.httpVersion` | `int` | `1`, `2`, or `3` |
| `req.params` / `req.param(name)` | `PathParams` / `string` | router path parameters |
| `req.isAlive` | `bool` | connection/stream still open |
| `req.response` | `Response` | the paired write half |
| `req.lastEventId` | `string` | `Last-Event-ID` (SSE reconnect) |
| `req.sendContinue()` | | send `100 Continue` (h1 streaming routes) |
| `req.blocking: body` | template | run `body` on the worker pool (see above) |
| `req.isWebSocketUpgrade` / `req.acceptWebSocket(protocols = [])` | `bool` / `WebSocket` | WebSocket handshake (see [WebSockets](#websockets)) |
| `req.onBody(cb, manualAck = false)` / `req.ackBody(n)` / `req.stream(chunk, last): body` | | inbound body streaming (see [Streaming requests](#streaming-requests)) |
| `req.doAsync: body` / `await req.read()` | | async adapter (see [Handlers](#handlers) / [Streaming](#streaming)) |

```nim
proc handler(req: Request, res: Response) {.gcsafe.} =
  if req.method == HttpGet and req.path.startsWith("/search"):
    let term = req.query.getOrDefault("q")
    let agent = req.header("user-agent")
    echo req.remoteAddress, " ", req.httpVersion, " ", term, " ", agent
    res.send(Http200, "results for " & term, "text/plain")
  else:
    res.send(Http404)
```

### Responses

`Response` is the write half of the pair (the same handle words as `Request`,
carrying only the capability to send). Copy it freely into workers or async
callbacks; sending through a dead connection is a safe no-op.

| Member | What it does |
|--------|--------------|
| `res.send(code, body = "", contentType = "", headers = [])` | queue a buffered response (compressed when eligible). Overloads: `res.send(code)`, and `code` as `int` or `HttpCode` |
| `res.redirect(location, permanent = false, extraHeaders = [])` | 301 (permanent) / 302 redirect |
| `res.sendHead(code, contentType = "", headers = [], contentLength = -1)` | begin a streamed response (see [Streaming responses](#streaming-responses)) |
| `res.write(data): bool` | append a streamed chunk; `false` signals backpressure |
| `res.finish(trailers = [])` | end a streamed response cleanly |
| `res.abort()` | truncate a streamed response (error mid-body) |
| `res.stream(code, ct, headers-or-emit): body` | block form of a streamed response |
| `res.onDrain(cb)` / `res.bufferedAmount` | streamed-response backpressure |
| `res.drained()` | awaitable drain, `Future[void]` (async adapter) |
| `res.sse(headers = [], retry = 0): SseStream` | begin a Server-Sent Events stream (see [SSE](#server-sent-events)) |
| `res.withSse(s): body` | block form of an SSE stream |
| `res.sendFile(path, opts = staticOptions())` | send one file (see [Static files](#static-files)) |

Two helpers build header pairs to pass in `res.send`'s `headers`:
`securityHeaders(...)` (OWASP baseline, see [Security](#security)) and
`setCookie(...)` (a `Set-Cookie` with `Secure`/`HttpOnly`/`SameSite=Lax`
defaults).

```nim
proc handler(req: Request, res: Response) {.gcsafe.} =
  case req.path
  of "/":       res.send(Http200, "hi", "text/plain")
  of "/old":    res.redirect("/new", permanent = true)
  of "/login":
    res.send(Http200, "{}", "application/json",
             @[setCookie("sid", newSession(), maxAge = 3600)])
  else:         res.send(Http404, "not found", "text/plain")
```

## Routing

`newRouter()` gives a path router: register a handler per method, with `:name`
path parameters and a trailing `*` wildcard, then hand `router.toHandler` to
`run`/`start`:

```nim
proc getUser(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "user " & req.param("id"))

var router = newRouter()
router.get("/users/:id", getUser)
router.get("/static/*", staticHandler("public"))
run(router.toHandler, initSettings(port = Port(8080)))
```

Route parameters are stored eagerly at match time, so `req.param` / `req.params`
work anywhere the handle does, including inside `blocking:` bodies. A path with
no matching route gets a 404; a path that matches but not the method, a 405.

## Static files

`staticHandler(rootDir)` returns a handler that serves a directory, keyed off a
route's trailing `*` wildcard. Register it on `/prefix/*` (and the bare
`/prefix` for the directory index):

```nim
let r = newRouter()
let assets = staticHandler("public")
r.get("/assets", assets)     # /assets and /assets/ -> public/index.html
r.get("/assets/*", assets)   # /assets/<path> -> public/<path>
```

`/assets/app.js` maps to `public/app.js`; `/assets/` and `/assets` serve the
directory's `index.html` (configurable). It runs on the worker pool (file I/O
blocks, so it never stalls the event loop), and the same code path serves over
HTTP/1.1, /2 and /3, plaintext or TLS. Each response includes:

- **Content-Type** from a built-in extension → MIME table (text types carry
  `charset=utf-8`); unknown extensions get `application/octet-stream`.
- **Conditional requests**: `ETag` + `Last-Modified`, answering `304 Not
  Modified` to `If-None-Match` / `If-Modified-Since` without resending the body.
- **Byte ranges**: `Range` yields `206 Partial Content` with `Content-Range`
  (single range; `If-Range` honored), `416` when unsatisfiable, and
  `Accept-Ranges: bytes` is always advertised.
- **Traversal safety**: the request path is percent-decoded and normalized, any
  `..` escape or NUL is refused, and the resolved path (symlinks included) must
  stay within `rootDir`.

Tune it with `staticOptions` (index file, `Cache-Control`, ETag/Last-Modified
toggles):

```nim
let assets = staticHandler("public",
                           staticOptions(index = "index.html",
                                         cacheControl = "public, max-age=3600"))
r.get("/assets/*", assets)
```

To serve one specific file from any handler, use `res.sendFile(path)` (a
trusted path — no traversal resolution):

```nim
r.get("/favicon.ico", proc(req: Request, res: Response) {.gcsafe.} =
  res.sendFile("public/favicon.ico"))
```

Large full-file `GET` responses are **streamed** from the worker pool in bounded
chunks — memory stays flat no matter how big the file is — with `Content-Length`
preserved (length-delimited, keep-alive intact). Small files, ranges, and `HEAD`
are read in one shot. `sendfile(2)` is intentionally not used — it composes with
neither TLS nor the readiness event loop.

## Streaming

Stream when a body is too large to buffer whole (large downloads, live feeds,
proxying) or when it should be consumed as it arrives (large uploads). Streaming
is **loop-thread only** — call it from the handler or an async/onDrain callback,
not from inside `req.blocking:` (a worker), where it does nothing.

### Streaming requests

To consume a large upload without buffering it whole, register a route with
`router.stream` (or pass a `streamRoute` predicate to `start`). Its handler is
dispatched at headers-complete and reads the body incrementally via `req.onBody`:

```nim
proc upload(req: Request, res: Response) {.gcsafe.} =
  req.onBody proc(chunk: openArray[char], last: bool) {.gcsafe.} =
    sink(chunk)                     # write to disk, hash, proxy, ...
    if last: res.send(Http200, "ok")

var router = newRouter()
router.stream(HttpPost, "/upload", upload)
start(router.toHandler, settings, router.streamPredicate)
```

The `req.stream` template is the inbound mirror of `res.stream` (its block runs
per chunk, and resets the response if it raises):

```nim
req.stream(chunk, last):
  sink(chunk)
  if last: res.send(Http200, "ok")
```

You don't need the router — `vortex/streaming` builds the same `streamRoute`
predicate directly (`streamPaths(...)`, `streamAll()`, `streamWhen(pred)`). Works
on HTTP/1.1 (Content-Length and chunked), HTTP/2, and HTTP/3 (`last` is true on
the final chunk). Ordinary routes are unchanged and still get `req.body`; the
`streamRoute` predicate is only consulted when set, so a server with no streaming
routes keeps the buffered fast path at zero cost.

Consumption drives **flow control**: with the async adapters, `await req.read()`
pulls the body chunk by chunk, deferring the HTTP/2 `WINDOW_UPDATE` / HTTP/3
stream reads until a chunk is read, so a slow consumer throttles the sender end
to end. In a plain synchronous `onBody` handler this is automatic;
`req.onBody(cb, manualAck = true)` + `req.ackBody(n)` expose the same control
directly.

### Streaming responses

Open the body with `sendHead`, append chunks with `write`, and terminate with
`finish`:

```nim
proc handler(req: Request, res: Response) {.gcsafe.} =
  res.sendHead(Http200, "text/plain")   # status + headers, no Content-Length
  discard res.write("first chunk\n")
  discard res.write("second chunk\n")
  res.finish()                          # terminate the body
```

`sendHead` opens the body (HTTP/1.1 uses `Transfer-Encoding: chunked`; HTTP/2 and
HTTP/3 leave the stream open with DATA frames), `write` appends a chunk, and
`finish` ends it (optionally with HTTP/1.1 trailers). The framing is identical
across all three protocols. Pass `contentLength` to `sendHead` for a
length-delimited body instead of chunked (used by file serving).

For the common "produce it all inline" case, the `res.stream` template brackets a
block with `sendHead`/`finish` — and `abort`s the stream (a visible truncation,
not a clean end) if the block raises:

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

`write` returns `false` once the unsent backlog reaches `respHighWater` (256 KiB);
a producer that outruns a slow client should pause and resume from `onDrain`
(`res.bufferedAmount` reports the current backlog):

```nim
proc pump(res: Response) {.gcsafe.} =
  while moreData():
    if not res.write(nextChunk()):
      res.onDrain(pump)               # backed up: resume when it empties
      return
  res.finish()
```

With an async adapter, pass a fresh identifier to `res.stream` instead of
headers: it is injected as an `emit(chunk)` that writes and `await`s the drain
for you (`await res.drained()` is the explicit form):

```nim
proc download(req: Request, res: Response) {.async.} =
  res.stream(Http200, "application/octet-stream", emit):
    for chunk in source: emit(chunk)          # backpressure handled per chunk
```

Call `res.abort()` yourself if you catch an error mid-stream in the manual API —
HTTP/1.1 closes the connection before the terminating chunk, HTTP/2 and HTTP/3
reset the stream, so the client sees the transfer was cut short.

## Compression

`-d:httpGzip` (`--passL:-lz`), `-d:httpBrotli`
(`--passL:"-lbrotlienc -lbrotlicommon"`), and/or `-d:httpZstd` (`--passL:-lzstd`)
enable **response compression**, turned on per server with `settings.compress`:

```sh
nim c -d:httpGzip -d:httpBrotli --passL:-lz \
      --passL:"-lbrotlienc -lbrotlicommon" --threads:on app.nim
```

```nim
run(handler, initSettings(port = Port(8080), compress = true))
```

An eligible response (the client accepts an encoding we can produce, a
compressible content-type, no existing `Content-Encoding`) is compressed with the
best encoding `Accept-Encoding` offers, adding `Content-Encoding` +
`Vary: Accept-Encoding`. Negotiation honors q-values (`gzip;q=0` opts out); on a
tie the server prefers **br**, then **zstd**, then **gzip**. Build with several
flags to offer several and let the client choose. This covers both buffered
`res.send` (compressed when over ~1400 bytes) and **streamed** responses
(`res.sendHead`/`write`/`finish`, SSE, and file streaming), compressed
incrementally. Off by default, so the standard and `-d:plainHttp` builds link no
zlib/brotli/zstd.

The **inbound** direction is opt-in with `settings.decompressRequest`: a request
whose `Content-Encoding` is `gzip` or `br` is transparently decoded into
`req.body`. It is bounded by `maxBodySize` so a decompression bomb can't exhaust
memory — a body that would exceed the cap is rejected with `413`, a corrupt one
with `400` — and the handler never runs for either.

## Server-Sent Events

`res.sse` opens a `text/event-stream` response over the streaming primitives, so
it inherits chunked/streamed framing and backpressure. It needs no router and no
`streamRoute` predicate (SSE is outbound-only), so it works from any handler:

```nim
proc events(req: Request, res: Response) {.gcsafe.} =
  let s = res.sse(retry = 3000)               # sends the SSE headers
  discard s.send("hi", event = "greet", id = req.lastEventId())
  discard s.comment("keepalive")              # heartbeat; clients ignore it
  s.close()
```

`s.send` emits one event (multi-line `data` splits into multiple `data:` fields;
`event`/`id`/`retry` are optional) and returns `false` under write backpressure;
`s.comment` sends a heartbeat; `s.bufferedAmount` / `s.onDrain` (and
`await s.response.drained()` with an adapter) expose backpressure; `s.alive`
reports client disconnect; `s.close` ends it (`s.abort` truncates).
`req.lastEventId` gives the `Last-Event-ID` a client echoes on reconnect.
`res.withSse(s): body` is a block form that closes (or aborts on exception) for
you:

```nim
res.withSse(s):
  for row in report: discard s.send(row.toJson, event = "row", id = $row.id)
```

The response sets `Cache-Control: no-cache, no-transform` and
`X-Accel-Buffering: no` so intermediary proxies don't buffer or transform the
stream.

## WebSockets

A handler detects the upgrade and calls `req.acceptWebSocket()`; set `onMessage`
/ `onClose` callbacks that run on the loop thread (they may capture locals).
`ws.send` / `ws.close` are non-blocking and safe to call from any thread, so you
can push to a socket from a worker or a timer:

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

To negotiate a subprotocol, pass your supported list (preference order) to
`req.acceptWebSocket(["chat", "json"])`; the first the client also offered is
echoed and readable via `ws.subprotocol` ("" if none).

For blocking work in response to a message (a sync DB query, file IO), use
`ws.blocking:` to run it on the same worker pool that backs the HTTP `blocking:`.
The message is passed in as `msg` (the body cannot capture locals); reply with
`ws.send`:

```nim
ws.onMessage = proc(ws: WebSocket, data: string, kind: WsKind) {.gcsafe.} =
  ws.blocking(data):
    let rows = db.getAllRows(sql"…")    # blocking is safe here
    ws.send($rows)
```

Like the HTTP `blocking:`, the connection is pinned while the body runs, so
messages from one connection are handled one at a time and in order; different
connections still run in parallel. For genuinely async drivers, import an async
adapter and use `ws.doAsync:` to `await` on the loop thread (an uncaught
exception closes the socket with 1011):

```nim
import vortex/adapters/asyncdispatch   # or vortex/adapters/chronos

ws.onMessage = proc(ws: WebSocket, data: string, kind: WsKind) {.gcsafe.} =
  ws.doAsync:
    let user = await db.getUser(data)   # loop keeps serving during the await
    ws.send(user.toJson)
```

For an `await`-per-message flow instead of the two callbacks, the async adapter
gives `ws.messages(msg): body` — a loop over incoming messages (sugar over
`await ws.receive()`). Write a plain `{.async.}` handler and register it with
`router.ws` (a raised exception closes the socket with `1011`, whereas
`router.get` would answer with an HTTP 500):

```nim
import vortex/adapters/asyncdispatch   # or vortex/adapters/chronos

proc chat(req: Request, res: Response) {.async.} =
  let ws = req.acceptWebSocket()
  ws.messages(msg):                    # runs per message until the peer closes
    let user = await db.getUser(msg)   # await mid-stream; loop keeps serving
    ws.send(user.toJson)

router.ws("/chat", chat)
```

When you push faster than a peer can read, `ws.send` parks the overflow in the
write buffer: `ws.bufferedAmount` reports that backlog (bytes) and `ws.onDrain`
fires when it empties, so you can throttle a producer and resume from the drain
(read `bufferedAmount` from a loop-thread callback, not another thread).

Works over `ws://` and, with a cert, `wss://`. Fragmented messages are
reassembled (bounded by `maxWsMessageSize`), ping/pong and the close handshake
are handled for you, and text is validated as UTF-8. After `wsPingInterval`
seconds without a frame the server pings, and closes the connection if no reply
arrives within `wsPongTimeout` (set `wsPingInterval = 0` to disable). Building
with `-d:wsDeflate` (links zlib) adds permessage-deflate (RFC 7692) message
compression, negotiated automatically.

The same handler API also serves WebSockets over **HTTP/2 (RFC 8441)** and
**HTTP/3 (RFC 9220)** via Extended CONNECT (`:protocol websocket`), multiplexed
with ordinary requests on the connection. `isWebSocketUpgrade` /
`acceptWebSocket` transparently handle all three transports, so the same
`onMessage` / `ws.send` / `ws.blocking:` / permessage-deflate code works over h1,
h2, and h3. WebSocket behavior is validated against the
[Autobahn|Testsuite](https://github.com/crossbario/autobahn-testsuite)
(`nimble autobahn`); h2 and h3 WebSockets are covered by `nimble h2spec`-adjacent
suites and `nimble h3websocket` (aioquic).

## Build flags

Release builds use:

```sh
nim c --mm:orc --threads:on -d:danger --passC:-flto app.nim
```

(`nimble bench` builds the benchmark server this way.)

| Flag | Effect |
|------|--------|
| `-d:plainHttp` | Zero-dependency cleartext build (h1 + h2c); removes OpenSSL and TLS/h2-over-TLS/h3 |
| `-d:wsDeflate` (`--passL:-lz`) | WebSocket permessage-deflate compression via zlib |
| `-d:httpGzip` / `-d:httpBrotli` / `-d:httpZstd` | Response + request compression codecs (see [Compression](#compression) for link flags) |

All are off by default, so the standard build keeps its OpenSSL-only footprint.

## Security

See [SECURITY.md](SECURITY.md) for the threat model, mitigations (Rapid Reset,
framing floods, decompression bombs, request smuggling, slowloris, resource
exhaustion), and security-related settings.

Two helpers make secure responses easy — `securityHeaders(...)` returns the OWASP
Secure Headers baseline as a header list, and `setCookie(...)` builds a hardened
`Set-Cookie`:

```nim
proc handler(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, body, "application/json",
           securityHeaders(hsts = req.isSecure))   # enable HSTS only over TLS
```

Gate cross-site WebSocket hijacking with `req.originAllowed`, and drive a
plaintext → HTTPS redirect with `req.isSecure` + `res.redirect`.

## Thanks

- [httpbeast](https://github.com/dom96/httpbeast) proved the
  architecture this server is built on: one event loop per thread over
  `SO_REUSEPORT` listeners with handlers running inline. This package is
  in many ways a from-scratch continuation of that design with the
  protocol gaps (chunked bodies, HTTP/2, HTTP/3) filled in.
- [mummy](https://github.com/guzba/mummy) made the case that blocking
  handler code deserves first-class support instead of async coloring;
  its worker-pool design directly shaped `blocking:`.
