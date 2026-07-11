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
  An optional asyncdispatch adapter layers `await` support on top
  (a chronos adapter can follow the same hook).
- **Protocols**: HTTP/1.1 (keep-alive, pipelining, chunked bodies,
  100-continue), HTTP/2 (TLS ALPN and h2c prior knowledge; h2spec-clean),
  HTTP/3 over QUIC (OpenSSL >= 3.5 server API), with automatic `Alt-Svc`
  advertisement.
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

Embedded / test usage: `var srv = start(handler, settings)` returns
immediately (`srv.port` has the resolved port); `srv.close()` shuts down.

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

## Verification

- `nimble test`: parser/HPACK/QPACK unit tests (RFC vectors) plus
  integration suites for h1, h2 (curl), h3 (h3-capable curl), TLS,
  worker pool, and router.
- HTTP/2 conformance: `h2spec -t -k -p <port>` passes 145/146 (1 skipped,
  0 failed) against a TLS server.
- `bench/run.sh` drives wrk/oha/ab and h2load against `bench/handlers`.

## Security

Rapid Reset, framing floods, decompression bombs, request smuggling,
slowloris, and resource exhaustion are defended with configurable limits
and covered by tests and fuzzers. See [SECURITY.md](SECURITY.md).

## Status

Pre-1.0. Deferred (planned): WebSockets, streaming request/response
bodies, a chronos adapter, dynamic QPACK, h2c upgrade, Windows.

## Thanks

- [httpbeast](https://github.com/dom96/httpbeast) proved the
  architecture this server is built on: one event loop per thread over
  `SO_REUSEPORT` listeners with handlers running inline. This package is
  in many ways a from-scratch continuation of that design with the
  protocol gaps (chunked bodies, HTTP/2, HTTP/3) filled in.
- [mummy](https://github.com/guzba/mummy) made the case that blocking
  handler code deserves first-class support instead of async coloring;
  its worker-pool design directly shaped `blocking:`.
