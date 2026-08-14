# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `req.blocking(a, b, ...): body` moves the named values into the worker pool,
  where they are usable by name inside the block (any movable type; they ride in
  as a tuple). Replaces the old capture-free-only body: instead of "read
  everything via `req`", you name what crosses. `req.blocking:` (no values) still
  works, and capturing an unnamed local remains a compile error (the guardrail
  that keeps loop-thread state off the worker).
- In an async handler (`vortex/asyncdispatch` / `vortex/chronos`), `req.blocking`
  is awaitable and returns the block's value: the handler suspends until the
  worker finishes and resumes with the result moved back (`let x =
  req.blocking(user): compute(user)`; the `await` is implicit). A sync handler
  keeps the terminal form (the block sends the response).

- `newVortex()` (no arguments) returns an app (a router) you register routes on,
  then `serve` (blocks) or `start` (non-blocking): `var app = newVortex();
  app.get("/", h); app.serve(8080)`. `serve`/`start` on a router build the server
  and wire the streaming-route predicate automatically, so `streaming = true`
  routes work without passing `streamRoute` by hand. `newVortex(handler)` still
  works for a single handler with no routing.

- Router composition: `parent.use(prefix, childRouter)` mounts a child router's
  routes under `prefix` (e.g. `root.use("/users", userRouter)` makes the child's
  `/:id` reachable at `/users/:id`). Routes merge into the parent tree at
  registration time; the child's own `use` middleware scopes to just its routes,
  and `:param`/`*` carry over.

- `req.json` parses the request body as JSON (cached per request; empty body is
  `{}`, raises `JsonParsingError` on malformed input), and `res.send(code, json)`
  replies with `application/json`. vortex now re-exports `std/json`, so
  `JsonNode`/`%`/`%*`/`parseJson` come with `import vortex`.
- `res.send` accepts `headers` as a JSON object (`res.send(Http200, body,
  %*{"X-Trace": "abc"})`).
- `res.send` accepts any `%`-able value as a JSON body: an object, `ref object`,
  string-keyed `Table`/`OrderedTable`, `seq`, `enum`, `Option`, or a named tuple
  (`res.send(Http200, user)`, `res.send(Http200, (ok: true, n: 3))`).
  `Content-Type` defaults to `application/json`. Anonymous tuples are rejected at
  compile time (use a named tuple, an object, or `%*{...}`).
- `res.headers` accumulates response headers to send with the eventual `send`
  (`res.headers["X-Request-Id"] = id`; `add` keeps duplicates like Set-Cookie).
  Set it from middleware or a handler; the `send` call's `headers` win per name.
  Buffered `send` only, loop-thread only.
- `req.headers[name]` reads request headers (case-insensitive, "" if absent),
  matching the `res.headers[name]` shape: `name in req.headers` tests presence
  and `for (n, v) in req.headers` iterates. A zero-copy read-only view;
  `req.header(name)` is now an alias.

### Changed

- **HTTP/3 now runs on ngtcp2 + nghttp3** (with OpenSSL >= 3.5 as ngtcp2's `ossl`
  crypto backend) instead of OpenSSL's QUIC server API. The OpenSSL-QUIC path and
  the hand-rolled HTTP/3 codec/QPACK are removed. **New build dependency:**
  building HTTP/3 (any non `-d:plainHttp` build) now requires ngtcp2 + nghttp3
  (`pacman -S libngtcp2 libnghttp3` on Arch; build from source with
  `--with-openssl` elsewhere). `-d:plainHttp` needs neither.
- `dispatchBlockingData` is no longer part of the public API (`import vortex`);
  it stays as an internal building block. Use `req.blocking(...)`.
- **Breaking:** the router's `stream` registrar is replaced by a `streaming`
  parameter on the route registrars: `router.get/post/put/...` and `addRoute`
  now take `streaming = false`. Migration:
  `router.stream(HttpPost, path, h)` -> `router.post(path, h, streaming = true)`.
  Same for the async adapters. This aligns streaming-route registration with the
  per-verb shape (no more passing `HttpPost` positionally).
- **Breaking:** `res.send` no longer takes a `contentType` parameter; set the
  content type through `headers` instead. When `headers` has no `Content-Type`,
  one is injected automatically: `text/plain` for a string body,
  `application/json` for a `JsonNode` body. A `Content-Type` in `headers` always
  wins (no more duplicate header when it was passed both ways). Migration:
  `res.send(code, body, "text/plain")` -> `res.send(code, body)`;
  `res.send(code, body, "text/html")` -> `res.send(code, body,
  %*{"Content-Type": "text/html"})` (or a `@[("Content-Type", "text/html")]`
  seq). `res.sendHead` (streaming) still takes `contentType`.

## [0.1.0] - 2026-08-10

Initial release: a fast, POSIX HTTP server for Nim speaking HTTP/1.1, HTTP/2,
and HTTP/3 from a single port and a single handler API. This is a 0.x release;
the public API may still change before 1.0.

### Added

#### Protocols

- **HTTP/1.1**: keep-alive, request pipelining, chunked transfer encoding, and
  `100-continue`.
- **HTTP/2**: over TLS (ALPN) and h2c prior knowledge; h2spec-clean, with
  rapid-reset and framing-flood defenses.
- **HTTP/3 over QUIC** on the OpenSSL >= 3.5 server API, with automatic
  `Alt-Svc` advertisement so clients upgrade.
- **WebSockets** (RFC 6455) over `ws://` and `wss://`, and over HTTP/2
  (RFC 8441) and HTTP/3 (RFC 9220) via Extended CONNECT; optional
  permessage-deflate (RFC 7692) with `-d:wsDeflate`.

#### Architecture

- One **event loop per thread** over `SO_REUSEPORT` listeners (kqueue/epoll via
  `std/selectors`); handlers run inline on the loop.
- **`req.blocking:`** escape hatch runs a handler body on a worker pool for sync
  DB drivers, file I/O, and CPU work; routes that never use it pay no overhead.
- **Future-agnostic core** (handlers are plain procs, responses may be deferred)
  with optional **asyncdispatch** and **chronos** adapters that add `await` on
  the loop thread without a runtime dependency in the core.
- **Dual-stack** IPv4/IPv6 by default, with graceful fallback.

#### TLS

- Certificates from files, in-memory PEM, or PKCS#12; **SNI** per-hostname
  certs; **mTLS** client-certificate verification; **OCSP stapling**;
  configurable TLS version range and ciphers; and hot `reloadTls`.

#### Routing and handlers

- Path **router** with `:name` parameters and a trailing `*` wildcard,
  composable **middleware**, and automatic 404 / 405 (with `Allow`).
- `Request` / `Response` API: buffered `send`, redirects, header helpers, and a
  hardened `setCookie` (Secure / HttpOnly / SameSite defaults).

#### Static files

- `staticHandler` / `res.sendFile`: extension-to-MIME typing, conditional
  requests (`ETag` / `Last-Modified`, `304`), byte ranges (`206` / `416`),
  bounded-memory streaming of large files, and path-traversal safety.

#### Streaming

- Inbound (upload) streaming with end-to-end flow control and outbound
  (download) streaming with backpressure, across HTTP/1.1, /2, and /3.
- **Server-Sent Events** over the same streaming primitives.

#### Compression

- gzip / brotli / zstd **response compression** with q-value negotiation, and
  gzip / brotli / zstd **request-body decompression** bounded against
  decompression bombs. Opt-in via `-d:httpGzip` / `-d:httpBrotli` / `-d:httpZstd`.

#### Operations and security

- **PROXY protocol** (v1/v2) and `X-Forwarded-For` for the real client address
  behind an L4/L7 load balancer.
- Per-IP token-bucket **rate limiting**; OWASP `securityHeaders` helper;
  `req.originAllowed` (cross-site WebSocket hijacking defense).
- Configurable request size limits (headers / body / WebSocket message) and
  per-phase timeouts; DoS budgets for rapid reset and framing/control-frame
  floods.
- **Graceful shutdown**: stop accepting, send HTTP/2 and HTTP/3 `GOAWAY`, close
  WebSockets with `1001`, drain in-flight work, then force-close after a grace
  window.

#### Conformance and testing

- Conformance / interop CI: h1spec, h2spec, h3spec, Autobahn (WebSocket),
  REDbot, OWASP ZAP, testssl.sh, and cross-client interop
  (Node / Python / Go / Rust / Java).
- Safety CI: AddressSanitizer + UBSan, ThreadSanitizer, a valgrind
  memcheck/helgrind race-and-leak matrix, and libFuzzer fuzzing of the
  parser / HPACK / QPACK decoders.

[Unreleased]: https://github.com/cryo2010/nim-vortex/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/cryo2010/nim-vortex/releases/tag/v0.1.0
