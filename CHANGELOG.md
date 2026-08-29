# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Trailers, both directions, shaped like `req.headers` / `res.headers`.
  `req.trailers` is a read-only view of the header fields a client sent after a
  chunked (HTTP/1.1) or streamed (HTTP/2, HTTP/3) request body:
  `req.trailers["checksum"]` ("" if absent), `"x" in req.trailers`, and
  iteration, populated once the body has fully arrived. `res.trailers` sets the
  trailers emitted after a streamed response body (`res.trailers["X-Checksum"]
  = digest`); `res.finish` sends them as the chunked trailer section on
  HTTP/1.1 or a trailing `HEADERS`+`END_STREAM` frame on HTTP/2. Previously
  received request trailers were discarded and there was no typed response-side
  API.

### Changed

- `res.finish` no longer takes a `trailers` argument; set response trailers via
  `res.trailers` before calling `res.finish()` instead. (Migration:
  `res.finish({"X-Checksum": v})` becomes `res.trailers["X-Checksum"] = v;
  res.finish()`.)

### Known limitations

- HTTP/3 does not emit response trailers yet (a request's trailers are still
  read via `req.trailers`): `res.trailers` set on an h3 response are dropped by
  `res.finish`. Emitting them needs an nghttp3 `submit_trailers` path in the
  QUIC C++ shim.

## [0.4.0] - 2026-08-29

### Added

- Request-side cookie parsing: `req.cookies[name]` reads an incoming cookie
  (a view matching the `req.headers[name]` shape; "" when absent), and
  `req.cookies.all(name)` iterates every value. Names are case-sensitive
  (RFC 6265), and all `cookie` header fields are scanned so cookies that HTTP/2
  and HTTP/3 split across several fields are recombined. On a duplicate name,
  `[]` returns the first occurrence (RFC 6265 §5.4 most-specific-path first), the
  safer pick against cookie shadowing; `all` exposes every value for detection.
  A single matched pair of surrounding double quotes is stripped from a value
  (RFC 6265 §4.1.1); interior/unbalanced quotes and any other encoding are left
  as-is.
- Forms and file uploads. `req.form` returns the submitted form fields from an
  `application/x-www-form-urlencoded` body OR the text parts of a
  `multipart/form-data` body (RFC 7578), and `req.files` returns the uploaded
  files. Both are shaped like `req.headers`: `req.form["email"]` is the first
  value ("" if absent), `req.files["avatar"]` is the first `UploadedFile`
  (`.filename`/`.contentType`/`.content`; raises `KeyError` if absent, so check
  `"avatar" in req.files` first), each with `in` and iteration. `req.mediaType`
  exposes the Content-Type media type without parameters.
- Content negotiation: `req.accepts`, `req.acceptsLanguage`, and
  `req.acceptsCharset` choose the best of the server-offered values against the
  corresponding `Accept*` header, honoring q-values and wildcards (`type/*`,
  `*/*`, and language prefix ranges). Returns "" if none is acceptable, or the
  first offer when the client sends no such header.
- CORS middleware: `cors(initCorsOptions(...))` (register with `app.use`) sets
  the `Access-Control-*` headers for allowed origins and answers preflight
  `OPTIONS` requests directly with 204 (403 for a disallowed origin). Supports a
  wildcard or exact-allowlist of origins, credentials, exposed headers, and
  Max-Age.
- Signed (tamper-proof) cookies: `setSignedCookie(name, value, secret, ...)`
  writes an HMAC signed value and `req.cookies.signed(name, secret)` returns it
  only if the signature verifies (constant-time), else `none`. The HMAC hash
  defaults to SHA-256 and is selectable via `CookieMac` (`macSha256`/`macSha512`/
  `macSha1`). Signing uses nimcrypto (pure Nim), so it works in every build mode
  including `-d:plainHttp` (no OpenSSL). This is integrity, not confidentiality.
  `sign`/`verify` are exported for other uses. Adds a `nimcrypto` dependency.
- Router: an unhandled `OPTIONS` on a known path is now answered automatically
  with a 204 and an `Allow` header (an explicit `options` handler still wins;
  `OPTIONS` is also added to the `Allow` header on 405 responses).
- Cookie attributes: `setCookie` gains `expires` (an absolute IMF-fixdate,
  alongside Max-Age), `partitioned` (CHIPS), and a name `prefix`
  (`cpSecure`/`cpHost`) that prepends `__Secure-`/`__Host-` and forces the
  attributes the browser requires (`__Host-`: Secure, Path=/, no Domain).
- Redirects: `res.redirect(location, preserveMethod = true)` sends 307/308
  (method and body preserved), in addition to the default method-droppable
  301/302.
- `req.serveContent(res, body, contentType, etag, lastModified, cacheControl)`
  serves an in-memory body with full conditional-request handling (If-Match /
  If-Unmodified-Since → 412, If-None-Match / If-Modified-Since → 304, If-Range)
  and byte ranges (206 for one range, `multipart/byteranges` for several, 416),
  the analog of Go's `http.ServeContent`. The static-file handler also honors
  If-Match / If-Unmodified-Since.
- Trusted forwarded-header resolution. Behind a reverse proxy, `req.scheme`,
  `req.host`, `req.isSecure`, and `req.clientIp` reflect `X-Forwarded-Proto` /
  `-Host` / `-For` and RFC 7239 `Forwarded` — but only from a peer in the new
  `trustedProxies` setting (ignored entirely otherwise, so a direct client can't
  forge them). `req.clientIp` peels only trusted hops. Also
  `req.forwardedProto` / `req.forwardedHost` / `req.fromTrustedProxy`.
- 103 Early Hints: `res.earlyHints(links)` (RFC 8297, `Link` preload/preconnect)
  and the general `res.informational(code, headers)` send a 1xx response ahead
  of the final one (HTTP/1.1 and HTTP/2; a best-effort no-op over HTTP/3 for now).
- Configurable HTTP/2 and HTTP/3 receive (upload) flow-control windows:
  `h2StreamWindow` / `h2ConnWindow` (default 1 MiB each) and
  `h3StreamWindow` / `h3ConnWindow` (1 MiB / 4 MiB). Larger windows raise upload
  throughput on higher-latency links; the connection window bounds total
  un-consumed upload buffer per connection (like Go's
  `MaxUploadBufferPerConnection`).

### Changed

- **`req.form` now returns a `FormFields` view instead of
  `Table[string, string]` (breaking).** It also covers `multipart/form-data`
  text parts, not just urlencoded; `req.form["x"]` returns "" for a missing key
  (was a `Table` `KeyError`) and the first value wins on a duplicate key (was the
  last). Uploaded files moved to the new `req.files`.
- `bodyTimeout` is now an *idle* timeout — re-armed on every read that carries
  body bytes — rather than a total deadline, so a large upload on a slow link is
  no longer cut off while it is actively transferring. A genuine stall (no bytes
  for `bodyTimeout`) still fires, and `maxBodySize` still bounds the total.
- TLS: a session-id context is set on the server `SSL_CTX`, so connections using
  client certificates (mTLS) can now resume instead of paying a full handshake
  each time. (Non-mTLS resumption already worked via OpenSSL defaults.)
- HTTP/2: outbound `WINDOW_UPDATE` frames are batched — emitted once the returned
  credit reaches half the window — instead of one per consumed DATA frame,
  cutting control-frame overhead on large uploads (matching nghttp2 and Go).
- Router: registering the same `(method, path)` twice, directly or via a
  sub-router mount, now raises `RouteConflictError` at registration instead of
  silently overwriting the earlier handler.

### Fixed

- HTTP/1.1: a fast `Transfer-Encoding: chunked` streaming upload (`req.onBody` /
  `req.read`) no longer retains the whole raw body in the connection receive
  buffer — it is compacted as it is consumed — so a large chunked upload can no
  longer drive the server to gigabytes of RSS and OOM (a denial of service).
- HTTP/2: a streamed response is bounded by the connection receive buffer, not
  just the per-stream flow-control window, so a slow client can't drive
  unbounded server memory during a large streamed download.
- Routing: the router trie is traversed with non-owning pointers/cursors,
  fixing a cross-thread ORC refcount race (a SIGSEGV under concurrent requests
  on a multi-threaded server).

## [0.3.0] - 2026-08-20

### Added

- `req.blocking(...)` accepts a value wrapped in `isolate(...)` to move a
  *uniquely-owned* reference into the worker; inside the block it is the plain
  type (`var u = isolate(load()); req.blocking(u): use(u)`). vortex re-exports
  `std/isolation`, so `isolate`/`extract`/`Isolated` come with `import vortex`.

### Changed

- **`req.blocking(...)` now rejects `ref`/`ptr`/`closure` arguments at compile
  time** (top-level or nested in a field). Such a value would be *shared* with
  the worker thread, not copied, and mutating it there races the loop thread (a
  silent data race). Value data still crosses freely -- numbers, `string`,
  `seq`, `Table`, and objects/tuples built from them are deep-copied. Migration:
  pass the value data the block needs and return the result, or move a
  uniquely-owned reference in with `isolate(...)`. Note that a value which
  transitively holds a `ref` is rejected too -- e.g. `std/times.DateTime` (it
  carries a `ref Timezone`), whose cross-thread use was already unsafe.

## [0.2.0] - 2026-08-19

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

- **Security docs split:** `SECURITY.md` is now a focused vulnerability-reporting
  policy (GitHub private vulnerability reporting); the threat analysis moved to a
  new STRIDE-based `THREAT_MODEL.md`, and defensive configuration to a new
  `HARDENING.md`.
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

### Fixed

- HTTP/3 now loads encrypted and in-memory-PEM (`keyPem` / PKCS#12) TLS keys
  without prompting on the controlling tty, which previously blocked h3 startup.
- Static file serving streams large byte ranges and answers `HEAD` from the file
  size, instead of reading the whole file or slice into memory.
- The event loop no longer busy-spins at 100% CPU when a client half-closes
  (`SHUT_WR`) while a worker or async response is still in flight.
- HTTP/3 responses larger than the peer's per-stream flow-control window no
  longer stall permanently: blocked streams are unblocked when the window
  reopens. Also fixes a flaky streamed-response drain on large-file responses.
- A `req.blocking:` worker that calls `res.send` more than once is now idempotent
  (the first response wins) instead of corrupting the connection pipeline.
- Response headers set via `res.headers[...]` before a streaming or file response
  (`res.sendHead`) are no longer dropped.
- permessage-deflate handles an empty message and a compressor error without
  crashing or emitting a corrupt frame.
- HTTP/3 emits a `CONNECTION_CLOSE` on transport errors (instead of forcing the
  peer to idle-time-out) and honors UDP send backpressure.
- Fixed several teardown and lifecycle leaks: an HTTP/3 connection on a failed
  accept, the OCSP staple buffer on a set failure, a WebSocket reader entry on an
  abnormal close, and an accept-path fd/counter leak; a raise while accepting a
  connection or applying a worker response no longer tears down the loop thread.
- Fixed a cross-thread reference-count race in `req.blocking(a, b, ...)` that
  could corrupt an ORC refcount under the worker pool.

### Security

Following a package-wide security review, this release closes:

- **HTTP/2 request smuggling and header injection:** reject duplicate and
  negative `Content-Length`, and validate header names/values for `CR`/`LF`/`NUL`,
  matching the strict HTTP/1 parser.
- **Rate-limiter denial of service:** the per-thread token-bucket table is now
  size-capped, so a distinct-key flood (spoofed or rotated source addresses)
  cannot grow it without bound.
- **Static-file path traversal:** a directory whose index is a symlink pointing
  outside the served root is now refused (containment is re-checked after the
  index is appended).
- **Memory-amplification denial of service:** a large-file `Range` or `HEAD`
  request no longer buffers the whole file or slice into memory.

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

[Unreleased]: https://github.com/cryo2010/nim-vortex/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/cryo2010/nim-vortex/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/cryo2010/nim-vortex/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/cryo2010/nim-vortex/releases/tag/v0.1.0
