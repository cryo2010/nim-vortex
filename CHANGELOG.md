# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2026-09-24

### Added

- Worker-pool load shedding: `maxBlockingQueue` (default 0 = unbounded) caps the
  number of `blocking:` tasks that may wait for a free worker. Once every worker
  is busy and the queue is at the cap, new `blocking:` dispatches fail fast with
  `503 Service Unavailable` (the synchronous `blocking:` template) or raise
  `PoolSaturatedError` in the awaitable `req.blocking(...)` form, instead of
  queuing without bound behind slow/stuck work. `blocking:` bodies should do
  bounded work and carry their own timeouts.
- Bounded, non-hanging shutdown: `close`/`waitFor` now wait at most
  `shutdownHardTimeout` seconds (default `shutdownGrace + 5`) for the event loops
  and workers to finish, then **detach** any thread still inside a
  never-returning `blocking:` handler and return, intentionally leaking only what
  that thread references. Nim cannot cancel a running thread, so this mirrors
  Go's `Server.Shutdown(ctx)` returning on its deadline and tokio's
  `Runtime::shutdown_timeout` abandoning stuck blocking threads: a misbehaving
  handler can no longer wedge `close()` forever.
- `writeTimeout` config (seconds, 0 = off, default off): closes a connection
  whose socket stays unwritable with output pending for that long, bounding a
  slow-reading client that never drains its response (a slow-read DoS the
  read-side `bodyTimeout` did not cover). Idle-style: re-armed on send progress,
  so a legitimately long streamed response is never cut off.
- Trailers, both directions, shaped like `req.headers` / `res.headers`.
  `req.trailers` is a read-only view of the header fields a client sent after a
  chunked (HTTP/1.1) or streamed (HTTP/2, HTTP/3) request body:
  `req.trailers["checksum"]` ("" if absent), `"x" in req.trailers`, and
  iteration, populated once the body has fully arrived. `res.trailers` sets the
  trailers emitted after a streamed response body (`res.trailers["X-Checksum"]
  = digest`); `res.finish` sends them as the chunked trailer section on
  HTTP/1.1 or a trailing `HEADERS` section on HTTP/2 and HTTP/3. Previously
  received request trailers were discarded and there was no typed response-side
  API.
- HTTP/2 per-connection write scheduler with RFC 9218 extensible
  prioritization. Concurrent streams are now served from a ready queue one
  `DATA` frame at a time instead of draining one stream fully before the next,
  with 8 urgency levels (lowest urgency first). Within a level, *incremental*
  streams interleave round-robin and non-incremental streams are delivered one
  at a time. Clients signal via the `Priority` request header (`u=N, i`) or a
  `PRIORITY_UPDATE` frame (one arriving ahead of the stream's `HEADERS` is
  buffered, capped); `res.setPriority(urgency, incremental)` overrides the
  client signal server-side. `SETTINGS_NO_RFC7540_PRIORITIES=1` is advertised.
  Bounded by the connection send window and the write-buffer cap, so no stream
  buffers a whole response in memory. On the fairness micro-benchmark (64
  concurrent 2 MiB streams, constrained windows) p99 completion fell from
  1006 ms to 77 ms with throughput and RSS unchanged. `nimble fairness` runs it.
  No-op over HTTP/1.1 and HTTP/3 (nghttp3 owns its own scheduling).
- OCSP staple rotation at runtime: `reloadTls(ocspFile = ...)` or
  `reloadTls(ocspResponse = derBytes)` swaps the stapled response without a
  restart (an unreadable explicit path rejects the whole reload, like a bad
  cert), `reloadTls(clearOcsp = true)` drops it, and a bare `reloadTls()`
  re-reads a configured `ocspFile` best-effort so a certbot-style renewal picks
  up a refreshed staple. Previously the staple was frozen at startup. SNI
  contexts and HTTP/3 still do not staple.
- `maxResetStreams` now also applies to HTTP/3: a per-connection rapid-reset
  budget (CVE-2023-44487 class) tears the QUIC connection down with
  `H3_EXCESSIVE_LOAD` once a client's `RESET_STREAM` churn exceeds it.
- `PoolSaturatedError` (raised by the awaitable `req.blocking(...)` when
  `maxBlockingQueue` is hit) and `res.setPriority` are new public API.
- Test infrastructure: a reverse-proxy interop suite (`nimble proxy`, nginx /
  Caddy / HAProxy in front of the origin over h1/h2/h3, incl. a PROXY-protocol
  check), a Dockerized cross-language benchmark suite (`nimble bench*`, vortex
  vs Go vs Rust via the navi client), a chaos sidecar for the stress soaks
  (`VORTEX_CHAOS`: slow readers, drip-fed and stalling uploads, idle and
  vanishing clients, with an open-fd leak check), and a `methods` workload.

### Changed

- `res.finish` no longer takes a `trailers` argument; set response trailers via
  `res.trailers` before calling `res.finish()` instead. (Migration:
  `res.finish({"X-Checksum": v})` becomes `res.trailers["X-Checksum"] = v;
  res.finish()`.)
- Graceful shutdown now performs the RFC-standard two-step GOAWAY drain on both
  HTTP/2 and HTTP/3 (matching Go/Node): an initial `GOAWAY(2^31-1)` "shutting
  down" notice so in-flight and racing streams still complete, followed by the
  final `GOAWAY(last-accepted-id)` cutoff. `maxConnections` now also caps
  concurrent HTTP/3 (QUIC) connections.

- HTTP/1.1 request methods are matched case-sensitively (RFC 9110 9.1): a
  mis-cased method such as `delete /x` is now a `501` like on HTTP/2 and
  HTTP/3, instead of dispatching the handler. Over HTTP/2 an unknown or
  non-token `:method` (previously silently mapped to `GET`) and any `CONNECT`
  request are rejected; this server does not tunnel.
- Handler-supplied framing and hop-by-hop headers (`Content-Length`,
  `Transfer-Encoding`, `Connection`, `Keep-Alive`, `Upgrade`, `Proxy-Connection`)
  are dropped from responses and trailers on all three protocols; the codec
  generates its own framing. Previously HTTP/1.1 echoed them (a second
  `Content-Length`, or `Transfer-Encoding` alongside `Content-Length`, that a
  downstream intermediary reads as smuggling) and HTTP/2 and HTTP/3 encoded the
  connection-specific ones verbatim.
- A plaintext HTTP/1.1 connection that closes after a response now always
  linger-closes (`shutdown(SHUT_WR)` then drain) instead of a bare `close()`,
  so a slow-reading peer never sees a `RST` discard the untransmitted tail of
  the response (a truncated ~4 KiB echo behind Caddy under load).
- `Expect: 100-continue` from an HTTP/1.0 client is ignored (RFC 9110 10.1.1)
  instead of eliciting an unsolicited `100 Continue`.
- Signed-cookie HMAC and the WebSocket `Sec-WebSocket-Accept` SHA-1 run through
  OpenSSL EVP (hardware SHA-NI / ARMv8 crypto) in TLS builds; output is
  byte-identical so existing signed cookies keep verifying. The pure-Nim paths
  (nimcrypto, the bundled SHA-1) remain the fallback under `-d:plainHttp`.
- Streamed file downloads (`res.sendFile`) read 256 KiB per hop (was 128 KiB)
  with a two-chunk read-ahead so disk and socket I/O overlap; file-chunk
  buffers come from a loop-owned pool (no per-chunk cross-thread allocation)
  capped at 16 idle buffers per loop. The per-connection streaming write
  high-water drops from 256 KiB to 64 KiB, and a closed connection frees its
  read/write buffers instead of pinning peak capacity for the server's life.
- `validateConfig` names the offending field and value in its error instead of
  a bare "settings must not be negative".

### Fixed

- HTTP/1.1 use-after-free: an awaitable `req.blocking` on a keep-alive
  connection could decrement the connection pin twice (once for the response,
  once for the task completion) and, with a pipelined follow-up request, release
  a different request's pin -- letting the receive buffer be reallocated under a
  running worker. The pin is now released exactly once, by the task completion.
- HTTP/2 slowloris hold-open: a connection with a stream still awaiting the
  client's request head/body (no `END_STREAM`) had its read deadline cleared, so
  a silent client held it forever. Such a stream is now bounded by `bodyTimeout`
  (a stream the client has finished while the server streams a long response is
  excluded, so SSE/downloads are unaffected).
- HTTP/3 graceful shutdown now actually transmits the final `GOAWAY` and a
  `CONNECTION_CLOSE` on a clean close: previously the connection was freed in the
  same pass that queued them, so neither reached the wire and peers waited out
  their idle timeout.
- HTTP/3 now replies to an unsupported QUIC version with a Version Negotiation
  packet (RFC 9000 6.1) instead of dropping the datagram.
- The accept loop no longer busy-spins at 100% CPU on `EMFILE`/`ENFILE` (fd
  exhaustion): it backs off and re-arms the listener, mirroring Go's handling of
  temporary accept errors.
- Graceful shutdown blocked by a `blocking:` handler that never returns now logs
  a clear diagnostic (Nim cannot safely cancel a running thread, so such a
  handler still blocks shutdown; the wedge is now visible instead of silent).
- HTTP/2 `sendFile` over a small peer flow-control window (httpx, nghttp2
  clients) wedged at 0 bytes/s: the connection was pinned for every chunk read
  so the peer's `WINDOW_UPDATE`s were never processed mid-stream. Flow control
  is now processed while only file-chunk reads are in flight.
- HTTP/2 keep-alive: a connection serving one stream at a time (e.g. a client
  consuming SSE batches) was closed `keepAliveTimeout` seconds after it
  *opened* regardless of traffic, because the idle deadline was armed once and
  never refreshed. It is re-armed after every request, as on HTTP/1.1.
- HTTP/2 flow control: the advertised receive window is now enforced
  (`FLOW_CONTROL_ERROR` on overrun; previously a streaming route could buffer
  without bound), the first frame after the preface must be `SETTINGS`, a
  zero-increment `WINDOW_UPDATE` on an idle stream is a connection error, and a
  `PRIORITY` self-dependency is a stream error rather than a `GOAWAY` that kills
  every concurrent stream.
- HTTP/2 correctness review (#230-#240): a use-after-move in the compressed
  streaming `finish()` path (the stream table could be mutated under a captured
  pointer); deferred connection-window credit leaked on every abnormal stream
  end (a few client cancels drained the connection window and every later
  upload deadlocked); a parked `await res.drained()` producer stranded forever
  when the client disconnected mid-stream (its `finally` cleanup never ran);
  refused `HEADERS` (max streams, drain, self-dependency) skipped HPACK decoding
  and stream accounting so a `REFUSED_STREAM` degraded into connection
  teardown; `maxControlFrames` bypasses (uncharged PING ACK / GOAWAY / unknown
  frames / closed-stream `WINDOW_UPDATE` and `DATA`, `SETTINGS` charged per
  frame not per entry, budget reset on every request) closed and `RST_STREAM`
  is no longer sent on idle stream ids; a connection whose peer absorbed the
  initial window then went silent while the server owed response bytes pinned
  its slot forever and is now reaped via `bodyTimeout`; a declared
  `content-length` is reconciled against `DATA` received on streaming routes
  (stream `PROTOCOL_ERROR` on mismatch, an upstream-desync vector); trailer
  names and values are validated (CR/LF/NUL injection through `req.trailers`);
  trailers without `END_STREAM`, `HEADERS` on a half-closed stream, and
  `HEADERS` racing a server early-close are stream-level errors instead of
  connection errors (h2spec 5.1 cases stay connection errors); frames on
  even (server-push space) stream ids are rejected; a synchronous response
  produced while resuming buffered input after a `blocking:` task is flushed;
  the encoder emits the HPACK dynamic-table-size update after the peer lowers
  `SETTINGS_HEADER_TABLE_SIZE`; WebSocket-over-h2 no longer `RST_STREAM`s a
  merely slow peer; a short `GOAWAY` is a `FRAME_SIZE_ERROR`; field values with
  leading or trailing whitespace are rejected.
- HTTP/2: a connection error raised while growing the receive buffer (e.g. a
  frame larger than `SETTINGS_MAX_FRAME_SIZE`) left the queued `GOAWAY` unsent
  and the socket open until the peer's timeout (h2spec 4.2). Pending output is
  flushed before unwinding. A deferred worker apply (outbox message, sendFile
  chunk) racing HTTP/2 teardown under a client abort could dereference freed
  codec state and crash the loop thread; the codec entry points now degrade to
  the documented no-op. Tearing down a connection with a parked file-chunk read
  no longer pins the connection being freed.
- HTTP/1.1 review fixes (#243-#257): the receive buffer is bounded to
  `maxHeaderSize` while parsing the head (a header flood without a terminating
  blank line pinned up to `maxHeaderSize + maxBodySize` per connection);
  `res.informational` / `res.earlyHints` header names and values are sanitized
  (CRLF response splitting); a streamed response opened with
  `sendHead(contentLength = N)` that writes a different number of bytes now
  closes the connection instead of desyncing the next keep-alive response.
- HTTP/1.1 framing conformance with Go and llhttp: more than one
  `Transfer-Encoding` field line is rejected (a TE-desync / smuggling vector),
  `gzip, chunked` is framed as chunked instead of `501` (only a coding list
  without a final `chunked` is unsupported), framing / routing / control field
  names are dropped from the trailer section so they can never reach
  `req.trailers`, and chunk-extension bytes carrying C0 controls or a bare CR
  are rejected.
- HTTP/1.1 async streaming uploads (`await req.read`) buffered whole request
  bodies: the loop read every connection's body far faster than the handler
  consumed it, so the streamupload soak (96 concurrent 64 MiB uploads) pinned
  ~1.3-1.5 GB RSS and was OOM-killed. Delivered-but-unacked bytes now apply
  socket-level backpressure (high/low water marks, TCP does the rest); RSS on
  that soak drops to ~480 MB. Sync auto-ack handlers are unaffected.
- HTTP/3 with PKCS#12-only TLS material advertised h3 via `Alt-Svc` but every
  QUIC handshake failed: the bundle was never forwarded to the QUIC context,
  which also accepted a certless context. It is forwarded and the context fails
  closed. A failed HTTP/3 setup is now logged instead of silently leaving a
  bound-but-unpolled UDP socket.
- HTTP/3 `res.trailers` were dropped on send and request trailers were never
  delivered (nghttp3's trailer callbacks were unregistered); both now work over
  HTTP/3. The final `GOAWAY` narrowing the accepted-stream range is issued on
  graceful shutdown (RFC 9114 5.2).
- HTTP/3 QUIC flow control leaked the shared connection window: buffered
  request bodies were never credited back, consumed WebSocket tunnel bytes were
  not credited, and a streaming body the handler never read was not credited at
  teardown. After ~4 MiB of cumulative body bytes on a long-lived connection
  the peer stalled flow-control-blocked and the connection closed with
  application error code 1 (the direct-h3 `requests` and `ws` soaks). All three
  paths credit correctly. `maxBodySize` is now enforced on buffered HTTP/3
  bodies: an oversized body is reset with `H3_MESSAGE_ERROR` immediately
  instead of stalling until the idle timeout.
- HTTP/3 review fixes (#250-#257): a single `onBody` EOF on normal completion
  (a raw consumer got a spurious second `last=true`); the configured
  `maxHeaderSize` is advertised to nghttp3 as `max_field_section_size`
  (previously unlimited); connections in the draining period after a
  peer-initiated `CONNECTION_CLOSE` are reaped instead of living until the idle
  timeout (a connection-slot leak); a rejected accept is honored; a parked
  `await res.drained()` producer is woken on stream or connection teardown;
  per-connection un-dispatched buffered request-body memory is capped at
  `max(h3ConnWindow, maxBodySize)` (mirroring HTTP/2); inbound trailers,
  outbound response headers / trailers and `content-length` get the same
  validation as HTTP/2, and a declared length is reconciled against `DATA`
  received.
- WebSocket: the 64-bit extended frame length is parsed into `uint64` before
  the `maxWsMessageSize` check (latent on 64-bit targets).
- Graceful shutdown could orphan an in-flight async `req.blocking` future when
  the response and task completion landed in the shutdown window, leaking the
  suspended continuation (a rare valgrind CI flake). The drain now waits for
  outstanding async-blocking completions.
- Worker-pin accounting: a refused `sendFile` chunk read under a saturated
  pool left a pin counter permanently skewed, a raising chunk reader's fallback
  `500` released the wrong counter, and a reused worker could drop an awaitable
  body's send. The pins are now typed per kind with explicit release ownership
  and asserted on the loop thread. Under load shedding a refused mid-stream
  file-chunk read now aborts the streamed response cleanly (the client sees a
  cut-short transfer) and returns its buffer instead of stalling until timeout.
- The worker pool is shut down before its outboxes are freed on both the clean
  and the startup-unwind teardown paths (Helgrind flagged the race).

### Security

- Request smuggling / response splitting hardening across the three protocols:
  duplicate `Transfer-Encoding` rejection, strict RFC 9110 `1*DIGIT`
  `Content-Length` grammar (no `+`/`-`/underscore forms, no duplicate-differing
  values) shared by h1/h2/h3, content-length reconciliation on HTTP/2 and
  HTTP/3 streaming routes, handler framing / hop-by-hop headers filtered from
  responses, CRLF sanitization of 1xx interim responses, and trailer field
  validation. See Changed / Fixed above for the individual items.
- HTTP/2 denial-of-service budgets: the `maxControlFrames` bypasses are closed,
  the per-connection un-dispatched buffered request-body memory is capped at
  `max(h2ConnWindow, maxBodySize)` (was up to `maxBodySize x maxConcurrentStreams`,
  ~2 GiB at defaults), a peer that absorbs the send window and goes silent is
  reaped, and a slow reader that never drains its response can be bounded with
  `writeTimeout`.
- HTTP/3 denial-of-service: `maxResetStreams` rapid-reset budget, the same
  buffered-body cap as HTTP/2, `max_field_section_size` advertised, and
  draining connections reaped.
- The bounded gzip/brotli/zstd request-body decode loop (decompression-bomb
  cap) and the zlib FFI bindings are now single shared implementations instead
  of three copies that could drift.

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

[Unreleased]: https://github.com/cryo2010/nim-vortex/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/cryo2010/nim-vortex/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/cryo2010/nim-vortex/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/cryo2010/nim-vortex/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/cryo2010/nim-vortex/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/cryo2010/nim-vortex/releases/tag/v0.1.0
