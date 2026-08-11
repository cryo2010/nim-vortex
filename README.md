# vortex

[![CI](https://github.com/cryo2010/nim-vortex/actions/workflows/ci.yml/badge.svg)](https://github.com/cryo2010/nim-vortex/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An HTTP server for Nim with support for HTTP/1.1, HTTP/2, HTTP/3, TLS, WebSockets and more. 

```nim
import vortex/asyncdispatch

proc handler(req: Request, res: Response) {.async.} =
  case req.path
  of "/":
    req.blocking: # runs on the worker pool
      let data = expensiveBlockingCall()
      await res.send(Http200, data, "application/json")
  else:
    await res.send(Http404)

newVortex(handler).serve(8080)
```

## Contents

- [Features](#features)
- [Requirements](#requirements)
- [Install](#install)
- [Build flags](#build-flags)
- [Choose an implementation](#choose-an-implementation)
- [Quick start](#quick-start)
- [Usage](#usage)
  - [Config](#config)
    - [Compression](#compression)
    - [Transport Layer Security (TLS)](#transport-layer-security-tls)
    - [Request size limits](#request-size-limits)
  - [Handlers](#handlers)
    - [Requests](#requests)
    - [Responses](#responses)
    - [Cookies](#cookies)
  - [Middleware](#middleware)
  - [Routing](#routing)
  - [Static files](#static-files)
  - [Streaming](#streaming)
    - [Upload](#upload)
    - [Download](#download)
  - [Server-Sent Events](#server-sent-events)
  - [WebSockets](#websockets)
- [Security](#security)
- [Thanks](#thanks)

## Features

- **HTTP/1.1**: keep-alive, request pipelining, chunked bodies, and
  `100-continue`.
- **HTTP/2**: over TLS (ALPN) and h2c prior knowledge; h2spec-clean, with
  rapid-reset and framing-flood defenses.
- **HTTP/3 over QUIC**: on the OpenSSL >= 3.5 server API, with automatic
  `Alt-Svc` advertisement so clients upgrade.
- **WebSockets** (RFC 6455) over `ws://`/`wss://`, and over HTTP/2 (RFC 8441)
  and HTTP/3 (RFC 9220) via Extended CONNECT, with the same handler API.
- **TLS**: certs from files, memory, or PKCS#12; SNI, mTLS client certs, OCSP
  stapling, configurable version range and ciphers, and hot `reloadTls`.
- **Streaming** requests and responses with end-to-end flow control and
  backpressure, on all three protocols.
- **Server-Sent Events** over the same streaming primitives.
- **Compression**: gzip / brotli / zstd responses and gzip / brotli / zstd request
  decompression, negotiated per request (opt-in build flags).
- **Routing** with `:name` params and `*` wildcards, plus composable
  middleware.
- **Static file serving** with conditional requests, byte ranges, streamed
  large files, and traversal safety.
- **Worker pool** (`req.blocking:`) backed by a worker pool for sync
  DB drivers, file IO, and CPU work.
- **Dual-stack**: binds IPv4 and IPv6 by default, with graceful fallback.
- **PROXY protocol** (v1/v2) and `X-Forwarded-For` support for the real client
  address behind a load balancer.
- **Security-minded**: threat-model-driven defenses plus `securityHeaders` and
  hardened `setCookie` helpers (see [Security](#security)).

## Requirements

- **Linux or macOS** host environment. Windows requires running via Docker.
- **Nim >= 2.2.10**.
- **OpenSSL >= 3.5** at runtime, for TLS, HTTP/2-over-TLS, and HTTP/3 (the QUIC
  server API landed in 3.5). A `-d:plainHttp` build needs no OpenSSL at all (see
  [Build flags](#build-flags)).
- The chronos adapter additionally needs `chronos >= 4.0.0` in your own project
  (it is never a dependency of a bare `import vortex`).

> [!TIP]
> You can run a `vortex` server on Windows via [Docker](https://www.docker.com/).

## Install

```sh
nimble add https://github.com/cryo2010/nim-vortex
```

> [!NOTE]
> If you plan to use `chronos` futures for async you will need to also install `chronos`.

## Build flags

Release builds use:

```sh
nim c --mm:orc --threads:on -d:danger --passC:-flto app.nim
```

| Flag | Default | Effect |
|------|---------|--------|
| `-d:plainHttp` | Off | Zero-dependency cleartext build (h1 + h2c); removes OpenSSL and TLS/h2-over-TLS/h3 |
| `-d:wsDeflate` (`--passL:-lz`) | Off | WebSocket permessage-deflate compression via zlib |
| `-d:httpGzip` / `-d:httpBrotli` / `-d:httpZstd` | Off | Response + request compression codecs (see [Compression](#compression) for link flags) |

They are all off by default, so the standard build keeps its OpenSSL-only footprint.

## Choose an implementation

Vortex is future-agnostic and ships with three server options:

1. A sync server via `import vortex`
2. An async server via `import vortex/asyncdispatch`
3. An async server via `import vortex/chronos`

**Synchronous**
```nim
import vortex

proc handler(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "Hello, World!", "text/plain")

newVortex(handler).serve(8080)
```

**asyncdispatch** - An async server that uses `std/asyncdispatch` futures.
```nim
import vortex
import vortex/asyncdispatch

proc handler(req: Request, res: Response) {.async.} =
  await res.send(Http200, "Hello, World!", "text/plain")

newVortex(handler).serve(8080)
```

**chronos**: An async server that uses `/chronos` futures.
```nim
import vortex
import vortex/chronos

proc handler(req: Request, res: Response) {.async.} =
  await res.send(Http200, "Hello, World!", "text/plain")

newVortex(handler).serve(8080)
```

> [!IMPORTANT]
> You must add `chronos` to your project in order to use the `vortex/chronos` server.

## Quick start

`newVortex(handler).serve(port)` creates and starts the server.

```nim
newVortex(handler).serve(8080)
```

## Usage

### Config

The server's `VortexConfig` can optionally be passed into `newVortex`, or you can simply 
edit `vortex.config` before serving. It carries the TLS material, timeouts, worker/thread
counts, and the feature toggles used throughout this document.

```nim
let config = initVortexConfig(
  address = "::",                 # dual-stack (default); pin a family with "0.0.0.0"
  numThreads = 0,                 # 0 = one event loop per core
  compress = true,                # response compression
  decompressRequest = true,       # transparently decode gzip/br/zstd request bodies
  responseTimeout = 30,           # seconds a handler may take before the conn is closed
  shutdownGrace = 10))            # seconds to drain in-flight work on shutdown
let vortex = newVortex(handler, config)
vortex.config.serverHeader = "acme"   # config is mutable until you start serving requests
vortex.serve(8080)
```

**Client address behind a proxy.** `req.remoteAddress` is the direct peer.
Behind an L4 / TLS-passthrough load balancer (AWS NLB, HAProxy in TCP mode),
enable the **PROXY protocol** so vortex uses the real client address the
balancer prepends (v1 and v2, TCP over IPv4/IPv6), honored only from a trusted
peer:

```nim
initVortexConfig(proxyProtocol = ProxyProtocol.Require,   # or ProxyProtocol.Optional
                 trustedProxies = @["10.0.0.0/8"])        # IPs/CIDRs; empty = any peer
```

`ProxyProtocol.Require` drops a connection without a valid header from a trusted peer;
`ProxyProtocol.Optional` uses the header when present and otherwise treats the peer as a
direct client. A header from an untrusted peer is never believed. Behind an L7
proxy that sets `X-Forwarded-For`, recover the origin client from
`req.forwardedFor` under a trust policy you control (see [Requests](#requests)).

#### Compression

Vortex supports gzip, brotli and zstd compression for requests and responses whenever the libraries are linked. **Request decompression** is generally not recommended but handled transparently. **Response compression** is recommended and enabled via `VortexConfig.compress` (boolean).

An eligible response is compressed with the best encoding `Accept-Encoding` offers, 
adding `Content-Encoding` + `Vary: Accept-Encoding`. Negotiation honors q-values (`gzip;q=0` opts out);
on a tie the server prefers **br**, then **zstd**, then **gzip**. 

The **inbound** direction is opt-in with `config.decompressRequest`: a request
whose `Content-Encoding` is `gzip`, `br`, or `zstd` is transparently decoded into `req.body`. 

```nim
let server = newVortex(handler)
server.config.compress = true # Enables response compression
server.config.maxBodySize = 8*1024*1024 # Defends against decompression bomb attacks
server.config.decompressRequest = true # Enables request decompression
```

| Algorithm | Compiler Flags | 
|-----------|---------------|
| brotli    | `-d:httpBrotli --passL:"-lbrotlienc -lbrotlicommon"` |
| gzip      | `-d:httpGzip --passL:-lz` |
| zstd      | `-d:httpZstd --passL:-lzstd`|

**Example Command:**
```sh
nim c -d:httpBrotli -d:httpGzip -d:httpZstd --passL:"-lbrotlienc -lbrotlicommon" \
  --passL:-lz --passL:-lzstd --threads:on app.nim
```

> [!TIP]
> Build with multiple compression options and let the client choose.

> [!CAUTION]
> Vortex disables request decompression by default in accordance with OWASP guidelines for attack-surface reduction. Enable at your own risk.

#### Transport Layer Security (TLS)

Providing a certificate turns on TLS, which enables HTTP/2 (via ALPN) and
HTTP/3 (over QUIC):

```nim
newVortex(handler, initVortexConfig(
  certFile = "cert.pem", keyFile = "key.pem")).serve(8443)
```

The cert and key can also come **from memory** instead of files. Pass the PEM
directly (e.g. loaded from a secret manager), with `keyPassword` for an
encrypted key:

```nim
newVortex(handler, initVortexConfig(
  certPem = vault.get("tls/cert"),
  keyPem = vault.get("tls/key"),
  keyPassword = vault.get("tls/key-pass"))).serve(8443)
```

`certPem`/`keyPem` take precedence over `certFile`/`keyFile`; either source works
for HTTP/1.1, /2 and /3, and both compose with `server.reloadTls`. Any key type
OpenSSL accepts (RSA, ECDSA, Ed25519) is supported. `keyPassword` applies to a
file or in-memory key; without it, an encrypted key fails to start (rather than
prompting).

**PKCS#12 (.pfx/.p12)** bundles the cert, key, and chain in one blob; pass the
file or the bytes, with `keyPassword` as the bundle passphrase:

```nim
initVortexConfig(pkcs12File = "server.p12", keyPassword = "…")   # or pkcs12 = bytes
```

**mTLS (client certificates)**: request or require a client cert and verify it
against a CA. `verifyClient = ClientVerify.Optional` accepts connections with no cert but
validates any that is presented; `ClientVerify.Require` refuses the handshake without a
valid one. Inside a handler, `req.clientCertSubject` gives the verified client's
subject DN ("" if none):

```nim
initVortexConfig(certFile = "cert.pem", keyFile = "key.pem",
                 verifyClient = ClientVerify.Require, clientCaFile = "client-ca.pem")
# ... req.clientCertSubject -> e.g. "/CN=service-a"     (clientCaPem takes in-memory CA)
```

**SNI (per-hostname certificates)**: serve different certs by requested host. The
default cert is the fallback; `sni` adds host-specific certs (each from files,
PEM, or PKCS#12). A `host` of `*.example.com` matches a single leading label
(`api.example.com`, not `example.com` or `a.b.example.com`); an exact host wins
over a wildcard:

```nim
initVortexConfig(certFile = "default.pem", keyFile = "default.key",
                 sni = @[SniCertEntry(host: "*.example.com",
                                      certFile: "wild.pem", keyFile: "wild.key")])
```

**TLS version range**: `minTlsVersion` (default `TlsVersion.V12`) floors it; `maxTlsVersion`
(default `TlsVersion.None` = no cap) ceils it, e.g. `maxTlsVersion = TlsVersion.V12` to keep
a client on 1.2. (QUIC/HTTP/3 is always 1.3.)

**OCSP stapling**: hand clients a cached OCSP response in the handshake so they
don't query the responder. Provide the DER bytes (refresh them out-of-band and
`reloadTls`); vortex doesn't fetch OCSP itself:

```nim
initVortexConfig(certFile = "cert.pem", keyFile = "key.pem",
                 ocspFile = "ocsp.der")        # or ocspResponse = derBytes
```

#### Request size limits

Inbound requests are bounded so a malformed or hostile client can't exhaust
memory. Each limit is a `VortexConfig` field with a default and a specific
rejection when exceeded, and the handler never runs for a rejected request:

| Field | Default | Enforcement |
|-------|---------|-------------|
| `maxHeaderSize` | 16 KiB | request line + headers combined; `431` when exceeded (also bounds the URI/path) |
| `maxHeaderCount` | 100 | number of header fields; `400` when exceeded |
| `maxBodySize` | 8 MiB | request body (post-decompression); `413` when exceeded |
| `maxWsMessageSize` | 1 MiB | largest inbound WebSocket message; close `1009` over it |
| `initialBufferSize` | 8 KiB | per-connection read/write buffer starting size (grows as needed) |
| `maxConcurrentStreams` | 256 | open HTTP/2 or HTTP/3 streams per connection |
| `maxResetStreams` | 512 | HTTP/2 peer resets before `GOAWAY` (rapid-reset defense) |
| `maxControlFrames` | 1000 | HTTP/2 PING/SETTINGS/etc. between stream progress (flood defense) |

```nim
newVortex(handler, initVortexConfig(
  maxBodySize = 64 * 1024 * 1024,     # allow 64 MiB uploads
  maxHeaderSize = 32 * 1024)).serve(8080)
```

To accept a large upload without buffering it whole (so `maxBodySize` isn't the
constraint), stream it instead; see [Upload](#upload).

### Handlers

A handler is a plain `proc (req: Request, res: Response)` or `proc (req: Request, res: Response) {.async.}`. It runs
**inline on the event loop**, so it must never block (no sync DB calls, no
`sleep`). Read the request through `req`, reply through `res`.

For synchronous work (a sync DB driver, file IO, CPU-bound work), `req.blocking:`
moves the body to a worker pool. Inside it, `req`/`res` are available but the
body cannot capture surrounding locals (it runs on another thread); read what
you need through `req`:

```nim
proc handler(req: Request, res: Response) {.async.} =
  req.blocking:
    let rows = db.getAllRows(sql"select …")   # blocking is safe here
    res.send(Http200, $rows, "application/json")
```

#### Requests

The `Request` object passed into the handler contains the content and metadata related to each request.

| Member | Type | Description |
|--------|--------|---------------|
| `req.method` | `HttpMethod` | request method (`HttpGet`, `HttpPost`, …) |
| `req.path` | `string` | raw request target, query string included |
| `req.url` | `Uri` | parsed target; `req.url.path` excludes the query (lazy, cached) |
| `req.query` | `Table[string, string]` | decoded query params, last value wins (lazy, cached) |
| `req.headers` | `iterator (string, string)` | every header pair (pseudo-headers skipped) |
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
| `req.params` | `PathParams` | all router path parameters |
| `req.param(name)` | `string` | one router path parameter; "" if absent |
| `req.isAlive` | `bool` | connection/stream still open |
| `req.response` | `Response` | the paired write half |
| `req.lastEventId` | `string` | `Last-Event-ID` (SSE reconnect) |
| `req.sendContinue()` | `void` | send `100 Continue` (h1 streaming routes) |
| `req.blocking: body` | `template` | run `body` on the worker pool (see above) |
| `req.isWebSocketUpgrade` | `bool` | is this request a WebSocket handshake (see [WebSockets](#websockets)) |
| `req.acceptWebSocket(protocols = [])` | `WebSocket` | complete the WebSocket handshake (see [WebSockets](#websockets)) |
| `req.onBody(cb, manualAck = false)` | `void` | register an inbound body sink (see [Upload](#upload)) |
| `req.ackBody(n)` | `void` | grant flow-control credit for consumed body bytes (see [Upload](#upload)) |
| `req.stream(chunk, last): body` | `template` | consume the request body chunk by chunk (see [Upload](#upload)) |
| `req.doAsync: body` | `template` | run an `{.async.}` body on the loop thread (async adapter) |
| `req.read()` | `Future[string]` | pull the next request-body chunk (async adapter; see [Upload](#upload)) |

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

#### Responses

The `Response` object paired with each request is the write half: use it to send
the reply. Copying it into workers or async callbacks is free, and sending
through a dead connection is a safe no-op.

| Member | Type | Description |
|--------|--------|---------------|
| `res.send(code, body = "", contentType = "", headers = [])` | `void` | queue a buffered response (compressed when eligible); also `res.send(code)` and an `int`-code overload |
| `res.redirect(location, permanent = false, extraHeaders = [])` | `void` | 301 (permanent) / 302 redirect |
| `res.sendHead(code, contentType = "", headers = [], contentLength = -1)` | `void` | begin a streamed response (see [Download](#download)) |
| `res.write(data)` | `bool` | append a streamed chunk (sync); `false` signals backpressure |
| `await res.write(chunk)` | `Future[void]` | append a chunk and await the drain (async adapter) |
| `res.finish(trailers = [])` | `void` | end a streamed response cleanly |
| `res.abort()` | `void` | truncate a streamed response (error mid-body) |
| `res.stream(code = Http200, contentType, headers = []): body` | `template` | block form of a streamed response |
| `res.onDrain(cb)` | `void` | fire `cb` when the streamed-response write backlog empties |
| `res.bufferedAmount` | `int` | bytes queued but not yet written to the socket |
| `res.drained()` | `Future[void]` | awaitable drain (async adapter) |
| `res.sse(headers = [], retry = 0)` | `SseStream` | begin a Server-Sent Events stream (see [SSE](#server-sent-events)) |
| `res.withSse(s): body` | `template` | block form of an SSE stream |
| `res.sendFile(path, opts = staticOptions())` | `void` | send one file (see [Static files](#static-files)) |

Two helpers build header pairs to pass in `res.send`'s `headers`:
`securityHeaders(...)` (OWASP baseline, see [Security](#security)) and
`setCookie(...)` (see [Cookies](#cookies)).

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

#### Cookies

`setCookie(...)` builds a `Set-Cookie` header as a `(name, value)` pair to pass
in `res.send`'s `headers`. It defaults to the OWASP session-management baseline
(`Secure`, `HttpOnly`, `SameSite=Lax`), so a plain call is already hardened:

```nim
proc login(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "{}", "application/json",
           @[setCookie("sid", newSession(), maxAge = 3600)])   # session cookie
```

The full signature is
`setCookie(name, value, maxAge = -1, path = "/", domain = "", secure = true,
httpOnly = true, sameSite = "Lax")`. `maxAge < 0` omits `Max-Age` (a browser
session cookie); set `secure = false` only for local plaintext development. Emit
several cookies by passing several pairs:

```nim
res.send(Http200, body, "text/html",
         @[setCookie("sid", sid, maxAge = 3600),
           setCookie("theme", "dark", httpOnly = false, maxAge = 31536000)])
```

Reading cookies is left to the handler: the raw header is `req.header("cookie")`
(a `name=value; name2=value2` string), which you parse as your app needs.

### Middleware

`router.use(mw)` wraps every route (and the 404/405 responses) with a
`Middleware`: `proc(next: RequestHandler): RequestHandler`. Run code before or
after `next(req, res)`, or skip `next` to short-circuit. Middleware run in
registration order: the first `use`d is outermost (runs first in, last out).

```nim
proc logging(next: RequestHandler): RequestHandler =
  let inner = next
  proc(req: Request, res: Response) {.gcsafe.} =
    let t0 = getMonoTime()
    inner(req, res)
    echo req.method, " ", req.path, " ", getMonoTime() - t0

proc requireAuth(next: RequestHandler): RequestHandler =
  let inner = next
  proc(req: Request, res: Response) {.gcsafe.} =
    if req.header("authorization").len == 0:
      res.send(Http401, "unauthorized")   # short-circuit: never calls inner
    else:
      inner(req, res)

var router = newRouter()
router.use(logging)         # outermost
router.use(requireAuth)
router.get("/users/:id", getUser)
newVortex(router.toHandler).serve(8080)
```

`use` is sugar over closure composition, so it is not required: since a handler
is a plain proc, you can wrap one directly without a router:
`newVortex(logging(requireAuth(handler))).serve(8080)`.

### Routing

`newRouter()` gives a path router: register a handler per method, with `:name`
path parameters and a trailing `*` wildcard, then hand `router.toHandler` to
`serve`/`start`:

```nim
proc getUser(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "user " & req.param("id"))

var router = newRouter()
router.get("/users/:id", getUser)
router.get("/static/*", staticHandler("public"))
newVortex(router.toHandler).serve(8080)
```

Route parameters are stored eagerly at match time, so `req.param` / `req.params`
work anywhere the handler does, including inside `blocking:` bodies. A path with
no matching route gets a 404; a path that matches but not the method, a 405.

### Static files

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
trusted path, no traversal resolution):

```nim
r.get("/favicon.ico", proc(req: Request, res: Response) {.gcsafe.} =
  res.sendFile("public/favicon.ico"))
```

Large full-file `GET` responses are **streamed** from the worker pool in bounded
chunks (memory stays flat no matter how big the file is) with `Content-Length`
preserved (length-delimited, keep-alive intact). Small files, ranges, and `HEAD`
are read in one shot. `sendfile(2)` is intentionally not used: it composes with
neither TLS nor the readiness event loop.

### Streaming

Stream when a body is too large to buffer whole (large downloads, live feeds,
proxying) or when it should be consumed as it arrives (large uploads). Streaming
is **loop-thread only**: call it from the handler or an async/onDrain callback,
not from inside `req.blocking:` (a worker), where it does nothing.

#### Upload

To consume a large upload without buffering it whole, register a route with
`router.stream` (or pass a `streamRoute` predicate to `newVortex`). Its handler is
dispatched at headers-complete and reads the body incrementally via `req.onBody`:

```nim
proc upload(req: Request, res: Response) {.gcsafe.} =
  req.onBody proc(chunk: openArray[char], last: bool) {.gcsafe.} =
    sink(chunk)                     # write to disk, hash, proxy, ...
    if last: res.send(Http200, "ok")

var router = newRouter()
router.stream(HttpPost, "/upload", upload)
newVortex(router.toHandler, streamRoute = router.streamPredicate).serve(8080)
```

The `req.stream` template is the inbound mirror of `res.stream` (its block runs
per chunk, and aborts the response if it raises):

```nim
req.stream(chunk, last):        # sync: `last` marks the final chunk
  sink(chunk)
  if last: res.send(Http200, "ok")
```

With an async adapter the pull-loop form drops `last` and **auto-acks with an
empty `200`** on a clean exit, unless the handler responded from inside the
block (a `res.send(Http201, id)`/4xx *inside* wins), or the block raises (then
`500`, never `200`):

```nim
proc upload(req: Request, res: Response) {.async.} =
  req.stream(chunk):
    await save(chunk)            # -> empty 200 on success
```

You don't need the router: `vortex/streaming` builds the same `streamRoute`
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

#### Download

The recommended way to stream a response is the `res.stream` template: it opens
the body with `sendHead` on entry and ends it with `finish` on a clean exit (or
`abort`, a visible truncation, if the block raises). With an async adapter,
`await res.write` writes each chunk and awaits the drain, so backpressure is
handled for you:

```nim
proc download(req: Request, res: Response) {.async.} =
  res.stream(Http200, "text/csv"):
    for chunk in source: await res.write(chunk)   # backpressure handled per chunk
```

The same block works synchronously (`discard res.write(...)` inside it).
`res.stream` also takes lighter forms: `res.stream(contentType): ...` and
`res.stream(): ...`, which defaults to `application/octet-stream` (pass a
`text/*` type to keep compression on).

**Backpressure.** `res.write` returns `false` once the unsent backlog reaches
`respHighWater` (256 KiB). `await res.write` awaits the drain for you; a sync
producer that outruns a slow client should instead pause and resume from
`res.onDrain` (`res.bufferedAmount` reports the current backlog).

**Producing chunks over time.** When chunks are produced over time rather than
in one straight-line block (from a timer, a worker-pool completion, an upstream
you are proxying, or an `onDrain` resume), drive the stream directly: `sendHead`
to open it, `write` per chunk, and `finish` when done. The response outlives the
handler, which is why file serving and SSE are built on these primitives:

```nim
proc handler(req: Request, res: Response) {.gcsafe.} =
  res.sendHead(Http200, "text/plain")   # status + headers, no Content-Length
  discard res.write("first chunk\n")
  discard res.write("second chunk\n")
  res.finish()                          # terminate the body
```

`sendHead` uses `Transfer-Encoding: chunked` on HTTP/1.1 and open DATA frames on
HTTP/2 and HTTP/3 (identical framing across all three); pass `contentLength` for
a length-delimited body instead (as file serving does), and `finish` may carry
HTTP/1.1 trailers. On a mid-stream error call `res.abort()` rather than `finish`:
HTTP/1.1 closes the connection before the terminating chunk, HTTP/2 and HTTP/3
reset the stream, so the client sees the transfer was cut short.

### Server-Sent Events

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

### WebSockets

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

newVortex(handler).serve(8080)
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
import vortex/asyncdispatch   # (or vortex/chronos)

ws.onMessage = proc(ws: WebSocket, data: string, kind: WsKind) {.gcsafe.} =
  ws.doAsync:
    let user = await db.getUser(data)   # loop keeps serving during the await
    ws.send(user.toJson)
```

For an `await`-per-message flow instead of the two callbacks, the async adapter
gives `ws.messages(msg): body`, a loop over incoming messages (sugar over
`await ws.receive()`). Write a plain `{.async.}` handler and register it with
`router.ws` (a raised exception closes the socket with `1011`, whereas
`router.get` would answer with an HTTP 500):

```nim
import vortex/asyncdispatch   # (or vortex/chronos)

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

## Security

See [SECURITY.md](SECURITY.md) for the threat model, mitigations (Rapid Reset,
framing floods, decompression bombs, request smuggling, slowloris, resource
exhaustion), and security-related settings.

Two helpers make secure responses easy: `securityHeaders(...)` returns the OWASP
Secure Headers baseline as a header list, and `setCookie(...)` builds a hardened
`Set-Cookie` (see [Cookies](#cookies)):

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
