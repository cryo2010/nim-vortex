# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- SSE: `s.send("")` (a payload-free event) now reaches the client. An empty
  `data` goes on the wire as two empty `data:` fields rather than one: a client
  appends an LF to its data buffer per `data:` field and strips a single
  trailing LF before dispatch, so one field left the buffer empty and the
  WHATWG EventSource dispatch step discarded the event, firing no listener.
  `s.send("", event = "ping")` now dispatches with `event.data == "\n"`. (#266)
- SSE: `send` splits `data` on the three terminators the wire format defines
  (CRLF, LF, CR) explicitly instead of leaning on `splitLines`. Behaviour is
  unchanged, and the lossiness it implies is now documented: the format has no
  escape for a literal CR, so a CR in `data` is a field boundary that the
  client rebuilds as an LF (`send("a\r\nb")` arrives as `"a\nb"`). Encode the
  payload (base64, or JSON) when it must survive byte for byte. (#267)
- SSE, streaming: `req.isAlive`, `res.bufferedAmount` and the `SseStream`
  `alive` / `bufferedAmount` that delegate to them are now guarded by the same
  loop-thread check every mutating call takes, so an off-thread read reports
  false / 0 instead of racing the loop over the connection table, the h2/h3
  stream maps and the write buffers. A `blocking:` worker still sees
  `req.isAlive == true`: its connection is pinned for the body's duration. This
  matches the WebSocket handles, which already guarded both. (#268)
- SSE: `res.withSse` forwards `res.sse`'s arguments, so the block form can set
  the reconnect delay and extra response headers:
  `res.withSse(s, headers = [("X-Stream", "report")], retry = 3000): ...`. It
  hardcoded `res.sse()`, which meant reaching for the handle constructor and
  hand-writing the close/abort pairing to get either. The existing
  `res.withSse(s): ...` form is unchanged. (#269)
- SSE: `s.send` and `s.comment` called from off the loop thread now assert
  (`res.headers`-style, so compiled out under `--assertions:off` / `-d:danger`)
  instead of returning false. False is the producer's "backlog full, pause and
  wait for `onDrain`", so a worker pushing events got a silent no-op that read
  as backpressure, and a producer waiting on a drain that could never come.
  `res.write`, `res.onDrain` and their SSE wrappers document that false, and a
  dropped `onDrain` registration, mean an off-thread call too. (#270)
- HTTP/2 and HTTP/3: a streamed response that declared a `Content-Length` and
  then ended at a different length is now reset (RST_STREAM / RESET_STREAM with
  INTERNAL_ERROR) instead of closed with a clean END_STREAM / FIN. Only HTTP/1
  reconciled the declared length against the body written (#248, where the
  mismatch forces the connection closed); on h2/h3 a short streamed body -- a
  truncated file read, a producer that stopped early -- was a well-formed lie
  that only the client could notice, and the server logged nothing. HEAD, which
  declares a length and writes no body by design, stays exempt. (#345)
- HTTP/2: a stream's response buffer (`pendingBody`) is now compacted once the
  sent prefix passes the high-water mark, not only when the backlog reaches
  zero. A long streamed download with a client that kept the backlog non-zero
  grew the buffer without bound (tens of MB per stream; ~768 MB RSS on the
  cross-language download bench). (#331)
- HTTP/2: legitimate flow control on a long download no longer trips
  `maxControlFrames`. A WINDOW_UPDATE that unblocks nothing (connection-level
  credit while nothing waits on the connection window, or credit for a closed
  stream) now spends credit earned by response DATA sent (one per 256 bytes,
  capped at 4x the budget) and is charged only past that; the budget also
  decays per 64 KiB of response DATA sent. A peer we send nothing to still
  trips GOAWAY(ENHANCE_YOUR_CALM) after the budget, as before. (#335)
- HTTP/2: a connection the server closes on its own account (an expired idle,
  header, body or pong deadline, the receive-buffer cap, or the end of the
  shutdown grace) now sends GOAWAY first, NO_ERROR for a timeout or shutdown
  and ENHANCE_YOUR_CALM for the cap, so a client can tell a server-side close
  from a network fault and retry what was never processed. (#342)
- HTTP/1 streaming: every clear of a paused body read now releases the loop's
  paused-connection slot. A response applied from a worker or async completion
  while the read was still paused leaked the count and pinned that loop thread
  at the 2 ms paused-body selector cadence for good; a debug build now audits
  the count every second. (#344)
- A connection whose fd lands beyond the connection table is now served rather
  than refused. The table was one flat `seq[Connection]`, so growing it moved
  every slot and would have dangled the `addr conns[fd]` a running `blocking:`
  worker holds; `handleAccept` therefore scanned for a pinned slot and, on
  finding one, accepted the connection and immediately closed it, which from the
  client is an empty connect error indistinguishable from a network fault or a
  stalled loop. It is now a segmented table: fixed-size blocks (1024 slots,
  ~712 KiB each) that are never resized or moved once allocated, so growth
  appends a block and leaves every outstanding `ptr Connection` valid. The pinned
  scan, the refusal and its drop counter are gone, growth is unconditional, and
  the fd rlimit remains the real bound on the table (the accept path still backs
  off on EMFILE/ENFILE). `maxConnections` is unchanged. (#343)
- HTTP/3 WebSockets: frames the client pipelines with the Extended CONNECT
  handshake are handed to the accepted WebSocket instead of being lost; a
  client that half-closes before the handler accepts now gets `onClose`
  delivered; a send or close issued on the loop thread outside the input path
  (a timer, an async continuation) drives QUIC egress instead of stalling until
  an unrelated packet; pre-accept bytes are bounded by the WebSocket message
  limit and no longer counted against the request-body aggregate. (#259, #261,
  #262, #263)
- WebSocket: `ws.subprotocol` is loop-thread only like the other accessors (it
  reports "" off-loop) instead of resolving the connection ref across threads;
  the permessage-deflate contexts are freed exactly once, so a second teardown
  of the same WebSocket is a no-op. (#260, #264)
- Regression coverage for fixes that had already landed without tests: the
  HTTP/2 stream-level error scope and racing-frame tolerance (#239), the HTTP/2
  conformance follow-ups (#240), and the HTTP/1 streaming read-ahead bound for
  async `req.read()` consumers (#271).
- TLS: an in-memory certificate chain (`certPem`, and the same bytes on the
  HTTP/3 side) that does not parse in full is now rejected instead of loaded
  up to the point of damage. `PEM_read_bio_X509` returns nil for every failure,
  not only end-of-data, so a mangled or truncated block after the leaf left a
  silently leaf-only chain: the server started, `reloadTls` returned true, and
  clients without the intermediate cached failed the handshake with "unable to
  get local issuer certificate". The loaders now read the OpenSSL error queue
  and accept the stop only on PEM's benign "no start line", exactly as
  OpenSSL's own `SSL_CTX_use_certificate_chain_file` does. (#367)
- TLS: a `clientCaPem` bundle must now parse in full. The loader treated any
  read failure as clean end-of-data and reported success whenever at least one
  CA had loaded, so a bundle truncated or corrupted part-way through (a
  ConfigMap or Vault render, a non-atomic `curl` fetch) silently installed a
  partial trust store: the server started healthy and every client issued by a
  CA after the damage was rejected at handshake time with an unable-to-get-issuer
  alert, with no startup failure to correlate against. A trust-anchor set is now
  accepted only when the whole bundle was consumed cleanly and held at least one
  CA. (#368)
- TLS: `verifyClient` other than `None` with neither `clientCaFile` nor
  `clientCaPem` is now rejected at startup instead of arming client-certificate
  verification against an empty trust store (OpenSSL 3 does not populate a new
  context's store, and the system trust store is never loaded). Under `Require`
  that rejected every connection with "unable to get local issuer certificate";
  under `Optional` clients that sent no certificate still connected, so the
  deployment looked healthy while client-cert auth was non-functional and
  `clientCertSubject` was always "". `validateConfig` names the missing setting,
  and the context build refuses it too, so direct `TlsConfig` users and rebuilds
  fail closed as well. (#369)
- TLS: an ALPN offer that overlaps nothing the server supports now gets the
  fatal `no_application_protocol` alert RFC 7301 3.2 requires, instead of
  completing the handshake with no ALPN extension. The callback returned
  `SSL_TLSEXT_ERR_NOACK`, which OpenSSL implements as "behave as if no callback
  were set", so an HTTP/3-only or legacy client that reached the TCP port got a
  successful handshake, was framed as HTTP/1, and answered 400 or hung until the
  idle timeout. The QUIC shim already alerted; the two paths now agree. A client
  that sends no ALPN extension at all is unaffected (OpenSSL does not invoke the
  callback for it) and still gets HTTP/1.1. (#370)
- TLS: `reloadTls(keyFile = ...)` against a server whose certificate came from
  a PKCS#12 bundle now returns false instead of reporting a rotation that never
  happened. The `keyFile` branch did not clear `pkcs12`/`pkcs12File` the way the
  `certFile` branch does, and `loadCertKey` gives a bundle unconditional
  precedence, so the context was rebuilt from the old bundle, the cert/key
  consistency check passed (they match each other), and an operator rotating a
  disclosed key got positive confirmation while the server kept presenting it. A
  lone key cannot apply to a bundle that carries both halves, so the call is
  rejected outright, and the ignored path is no longer recorded in the stored
  material (which used to let a later cert-only reload pair a new certificate
  with it). Rotate both halves together. (#363)
- TLS: every context is now built with `SSL_OP_NO_RENEGOTIATION`, so
  renegotiation is refused as this server's own policy rather than inherited
  from a library default. A renegotiation is a full ECDHE key agreement plus a
  server signature run inline on the loop thread for a few hundred bytes of
  client effort, unmetered (the CVE-2011-1473 shape). OpenSSL 3.0 already
  refuses client-initiated renegotiation unless
  `SSL_OP_ALLOW_CLIENT_RENEGOTIATION` is set, but that default can be flipped by
  a system `openssl.cnf` and does not exist in a pre-3.0 libssl, which the
  Linux dynlib pattern can still resolve. TLS 1.3 has no renegotiation and is
  unaffected. (#376)
- TLS: `reloadTls` is now serialised by a lock, so two threads reloading at
  once (a SIGHUP loop plus an admin endpoint, say) can no longer interleave the
  bookkeeping that retires the displaced `SSL_CTX`. Both could claim the same
  retire slot, which either freed one context twice (memory corruption) or
  dropped the other thread's entry and leaked it. The documented contract
  ("call from an ordinary thread") always implied concurrent calls were fine;
  now they are. (#360)
- TLS: a certificate hot-reload now releases the displaced `SSL_CTX` right
  away and `newTlsSession` holds a reference to the context it hands to
  `SSL_new`, replacing the four-slot retire ring and its 5 s grace window. The
  ring had to evict, and free, a context once a fifth reload arrived inside the
  window, which by construction is the moment every retained context was still
  within its grace period: a renewal hook or config-file watcher firing a few
  times in a few seconds could free a context a loop thread had loaded but not
  yet up-ref'd, along with the OCSP staple attached to it. A reference per
  session makes a displaced context live exactly as long as the last connection
  using it, so both the slot cap and the window are gone. (#364)
- HTTP/3: a connection error from nghttp3 is now terminal for nghttp3 before
  control returns to ngtcp2. The QUIC shim deleted nothing and reported success
  when `nghttp3_conn_read_stream` failed, so ngtcp2 kept decoding the rest of
  the datagram and every remaining STREAM frame, stream close, ack and window
  update re-entered a connection the library documents as usable only for
  `nghttp3_conn_del`: one hostile datagram (a malformed frame sequence on one
  stream, any bytes on a second) could crash the loop thread and every
  connection on it. The poisoned connection is now freed on the spot, the
  callback fails so ngtcp2 abandons the datagram, and the CONNECTION_CLOSE
  still carries the HTTP/3 error code. (#362)
- HTTP/3: `tlsCipherSuites` now applies to QUIC. The engine hardcoded TLS 1.3
  and never called `SSL_CTX_set_ciphersuites`, so a suite restriction held on
  HTTP/1.1 and HTTP/2 and was silently ignored on every HTTP/3 connection,
  which negotiated whatever OpenSSL's defaults allowed. `tlsCipherList` stays
  TCP-only by definition (no QUIC handshake is TLS 1.2), and `minTlsVersion` is
  clamped up to TLS 1.3 for QUIC as before. `maxTlsVersion = TlsVersion.V12`
  together with `http3 = true` is now rejected at startup, naming
  `http3 = false` as the fix, instead of applying the ceiling on TCP and
  ignoring it on HTTP/3. (#359)
- HTTP/3: `verifyClient` (mTLS) is now enforced on QUIC. The engine never
  called `SSL_CTX_set_verify`, so a server that required client certificates
  advertised `h3` via Alt-Svc and then completed the QUIC handshake with a
  client that presented none: the mTLS requirement held on TCP and was absent
  on HTTP/3. The client CA (`clientCaFile` / `clientCaPem`) is loaded the same
  way as on the TCP path, and an in-memory bundle that is truncated or damaged
  fails the configuration instead of installing a partial trust store.
  `req.clientCertSubject` now also reports the client certificate over h3
  (it was always ""), and the QUIC connection teardown clears the SSL's app
  data before `SSL_free` as ngtcp2's OpenSSL backend requires, which a
  handshake rejected for a missing client certificate would otherwise turn into
  a use-after-free. (#351)
- HTTP/3: `sni` (per-hostname certificates) is now served over QUIC. The engine
  had one `SSL_CTX` and one certificate per loop and no servername callback at
  all, so a browser that followed the server's own Alt-Svc advertisement for an
  SNI host was handed the *default* certificate and aborted with a name
  mismatch, while the identical request over TCP got the right certificate. Each
  host now gets its own QUIC context, built through the same path as the default
  one (so it inherits the verify mode, cipher suites and TLS 1.3 pinning), and
  the servername callback switches to it: an exact host wins over a wildcard,
  matched case-insensitively. A certificate reload rebuilds the per-host
  contexts from their own material, and they are freed with the engine. (#374)
- TLS: a handshake that blocked on a full socket send buffer (`WANT_WRITE`) and
  then went back to waiting for the peer now drops write interest. The
  handshake driver's `WANT_READ` arm left it armed, and since the selector is
  level-triggered and every event on a handshaking connection re-enters the
  driver, a writable socket re-entered `SSL_do_handshake` on every selector
  pass: a client that stalls its handshake there pinned a loop thread at 100%
  CPU (0.98 s of CPU per second, measured) for the whole `headerTimeout`
  window, starving every other connection on that thread. (#365)
- TLS: the `SSL_write` `WANT_READ` arm of the response flush now drops write
  interest and notifies the producers parked on the write buffer. It returned
  with write interest still armed from the preceding `WANT_WRITE`, so a
  writable socket re-entered the flush on every selector pass (the same
  level-triggered spin as the handshake case above), and it skipped the
  WebSocket backpressure signal and the HTTP/2 buffer-drain resume that both
  neighbouring stall arms perform. The write-stall deadline
  (`writeTimeout`) is kept, since such a flush is stalled rather than
  finished. (#371)
- TLS: an `SSL_read` that returns `WANT_WRITE` is now retried from the write
  event. OpenSSL's contract is that the same call is repeated once the socket
  is writable, because the bytes it must emit first (a TLS 1.3 KeyUpdate
  answer, a renegotiation flight, an alert) live in the SSL object's own write
  buffer, not in the connection's. The loop instead ran the response flush,
  which found nothing pending, dropped write interest and never touched the
  SSL object, so the record was stranded until the connection timed out. The
  flush also no longer drops the write interest that such a retry depends
  on. (#372)
- TLS: decrypted plaintext left inside OpenSSL is no longer stranded. The
  receive loop's early exits (a streaming body parked at the read-ahead
  high-water, a `blocking:` worker that forbids growing the receive buffer)
  assumed the bytes not taken were still in the kernel, waiting as TCP
  backpressure for the next readable event. Under TLS a read with a small
  `wanted` returns that much and keeps the rest of the record decrypted inside
  OpenSSL with the socket already drained, and a level-triggered fd never
  reports readable for those bytes again: an HTTPS upload to an
  `await req.read()` handler could stall until `bodyTimeout`, and a pipelined
  HTTPS request behind a worker was never answered. Such connections are now
  queued and re-driven by the loop (re-checked when the body ack or the worker
  unpin lifts the block), and the selector does not wait while any are
  queued. (#366)
- TLS: a connection that asked for a lingering close now gets one. It was
  exempted on the grounds that "TLS has its own close_notify", but close_notify
  is a TLS-layer record and does nothing to stop the kernel sending RST instead
  of FIN when `close()` runs with unread data still in the receive queue, and
  that RST discards the whole send queue: the error response the client had not
  read yet, and the close_notify with it (the truncated upstream response a
  reverse proxy reports). HTTPS now takes the same sequence as plaintext,
  close_notify then `shutdown(SHUT_WR)` then drain to the peer's FIN or the
  drain deadline, and the session is shut down and freed exactly once. (#373)
- HTTP/2: the remaining ways to push overhead frames past the
  `maxControlFrames` budget are charged. A SETTINGS ACK returned before the
  charge, exactly as a PING ACK once did (we send our SETTINGS once, so every
  ACK past the first is pure overhead); a zero-increment WINDOW_UPDATE naming a
  stream we have seen answered with a RST_STREAM before the charge, and on an
  already-closed id it tore nothing down, so the peer could repeat it forever;
  and a stream-level WINDOW_UPDATE was never charged at all, which left the
  cheapest flood of them all (13 bytes a frame against an open stream the server
  owes no bytes on, so the scheduler pass it forces emits nothing). A
  stream-level update that unblocks nothing now goes through the same
  credit-then-charge path as the connection-level and closed-stream ones, so
  flow control from a client that consumed response DATA still rides the credit
  those bytes earned. Charging only the updates that unblock *nothing* left the
  issue's headline vector free, since an increment of 1 always unblocks exactly
  one byte: after `SETTINGS_INITIAL_WINDOW_SIZE=0`, a flood of
  `WINDOW_UPDATE(sid, 1)` still bought one 1-byte DATA frame and one full
  scheduler pass per 13-byte frame. An update that merely dribbles (an increment
  below 256 bytes that leaves the window it credits below 256 bytes while bytes
  are waiting on that window, at either level) is now charged straight to the
  budget and never to the credit pool, because the 1-byte frames it forces would
  otherwise bank exactly the credit that pays for it. No correct client asks for
  more data in pieces that small while holding the window under 256 bytes; that
  is the CVE-2019-9511 data-dribble shape. Conversely, the credit response DATA
  earns now has a floor of two per DATA frame emitted on top of the one per 256
  bytes: the server chooses the frame size, and one stream-level plus one
  connection-level WINDOW_UPDATE per frame is the finest acknowledgement a
  correct client can send, so a streaming handler writing 1500 16-byte events to
  such a client used to be torn down with GOAWAY(ENHANCE_YOUR_CALM) after about
  1070 of them. DATA on a closed stream no longer answers with a RST_STREAM
  after the GOAWAY its own charge triggered, like the other charged replies. The
  budget's bypasses are covered by a frame-level regression suite (PING ACK,
  SETTINGS ACK, received GOAWAY, unknown frame types, WINDOW_UPDATE,
  self-dependent PRIORITY including the RFC 9113 5.1 rule against resetting an
  idle stream, closed-stream DATA, per-entry SETTINGS charging, and a
  one-request-per-burst interleave against the per-request reset), together with
  the dribble vector at both the stream and the connection level and the two
  correct clients that must survive it: a small-frame producer acked per frame on
  both levels, and a 200 KiB download acked in 4096-byte increments. (#234)
- h2, h3: a streaming (`onBody`) route now reconciles the declared
  `content-length` against the DATA actually received on every path a request
  can end on, and as soon as the running tally passes the declared length
  rather than only at the end. Two gaps remained: `content-length: 10` with
  END_STREAM on the request HEADERS themselves (no DATA frame and no trailer
  section, so neither end-of-message check ran) dispatched the handler and
  flushed it a clean, complete, empty body; and excess DATA was handed to the
  sink chunk by chunk, with the reset only following the terminating frame, so
  a route relaying the body upstream under the declared Content-Length had
  already desynchronized that h1 connection (request smuggling) by the time
  the mismatch was noticed. Both now fail the stream with PROTOCOL_ERROR
  (RFC 9113 8.1.1) before anything reaches the handler, and the h3 backend
  takes the same early check (RFC 9114 4.1.2). On h3 the reset by itself was
  not enough. A streaming route is queued for dispatch while its HEADERS are
  parsed and the handler runs only once the whole engine pump is done, and both
  reconciliation sites deliberately leave the rejected stream in the table so
  its flow-control credit can be returned when it closes, so a request whose
  head, body and FIN were parsed in one read batch (out-of-order delivery
  flushes a buffered DATA frame together with the HEADERS that precede it) was
  still handed to the handler afterwards, with all of its side effects. The
  ready-list consumer now skips a stream the backend rejected or has already
  dropped, which is what h2 gets from reconciling before it enqueues, and a
  rejected stream also stops accumulating body bytes it will never deliver.
  Buffered routes are unchanged: they never see a partial body. (#237)
- h2, h3: a `content-length` field in a request *trailer* section is now
  rejected (stream PROTOCOL_ERROR / H3_MESSAGE_ERROR) instead of being stored
  in `req.trailers`. The rest of the trailer-field validation was already in
  place: the shared rule checks the name and value bytes exactly as for the
  request head and rejects pseudo-headers and the connection-specific fields,
  but it was built on the response-side forbidden-field set, which excludes
  `content-length` on purpose. In a trailer section that is not a
  response-generation concern but the framing field RFC 9110 6.5.1 names
  first, the one the h1 parser already drops, so a handler that logged or
  relayed `req.trailers` could emit a second Content-Length for the same
  message. Regression coverage for the whole trailer rule set (CR/LF/NUL and
  edge-whitespace values, uppercase and non-token names, pseudo-headers,
  `connection` / `proxy-connection` / `keep-alive` / `transfer-encoding` /
  `upgrade` / `te`, one bad field poisoning the whole block, and the
  `maxHeaderSize` bound on the block) now lives in
  `tests/test_http2_request_body.nim`. The outbound direction is closed with
  it: a `res.trailers` entry named `content-length` or `te` is now dropped on
  every protocol instead of going out in the trailer section. The three writers
  had drifted (h1's chunked trailer dropped `content-length` but not `te`, h2's
  trailing HEADERS emitted both, h3 dropped `te` but not `content-length`), so a
  handler relaying an upstream's trailers verbatim could hand a client a second,
  later Content-Length for a message it had already framed, which is the same
  smuggling primitive in the other direction, or a `te` RFC 9113 8.2.2 forbids
  on a response outright. They now share one predicate
  (`fieldrules.forbiddenResponseTrailerField`, also the inbound rule's forbidden
  set), and h2 and h3 drop a non-token or pseudo-header trailer name and a
  CR/LF/NUL value there too, as h3's value check already did. (#238)
- SSE: an `id` can no longer break `Last-Event-ID` resume. NUL joins CR and LF
  in the field sanitizer, so no SSE field value (`id`, `event`, a comment's
  text) can carry a byte the wire format has no escape for; a NUL in an `id`
  used to go out verbatim, and the WHATWG EventSource rules make a client ignore
  such a field entirely, leaving `Last-Event-ID` stuck on the previous event. An
  `id` that the sanitizer empties (`"\r\n"`, `"\0"`) now emits no `id:` field at
  all instead of the empty one that *resets* the client's `Last-Event-ID`, so a
  resume point is never cleared by characters that never reached the wire. An
  `event` name that sanitizes away is likewise dropped rather than sent as an
  empty type, which dispatches as the default "message" anyway. (#265)
- HTTP/2: regression coverage for the per-connection cap on un-dispatched
  buffered request-body bytes (added in #242, never covered by a test). A
  buffered body is retained until END_STREAM dispatch and its flow-control bytes
  are credited on receipt, so `h2ConnWindow` cannot bound it: the new suite
  trickles 32 concurrent POST streams past the cap and asserts the connection
  never pins more than `max(h2ConnWindow, maxBodySize)`, and never less than
  the 64 KiB default receive window (verified at 3 MiB with
  the cap check removed), that the stream which crosses it is reset with
  REFUSED_STREAM so the client may retry, that a cancelled stream gives its
  reservation back for a later upload, and that a single upload up to
  `maxBodySize` still succeeds across a smaller connection window because the
  credit stays eager. The debug-only counter audit now re-derives the aggregate
  from a full stream scan too, so a teardown path that forgets to release a
  reservation fails the test suite instead of permanently shrinking what the
  connection will accept. (#235)
- HTTP/2: a response stalled on the peer's flow-control window is now timed out
  from the timeout sweep as well as from the input path. #242 made "response
  bytes owed but blocked on a peer send window" arm the body deadline, but the
  classification runs only in the deadline tail of an inbound-frame pass, and a
  streamed `sendFile` parks its bytes from the outbox instead: a chunk read holds
  a file-chunk pin, which deliberately does not pause input, and its release
  re-processes input only when bytes are already buffered, which a silent client
  never has. So a download to a client that absorbed its initial window and then
  stopped sending WINDOW_UPDATEs reached the loop with no deadline armed at all
  and pinned the fd, the connection slot and the parked chunks until the process
  exited: zero traffic, no timeout. The sweep now arms the same deadline from the
  same predicate (one O(1) counter read per connection per second), so the stall
  is bounded whichever path parked the bytes, and the close sends
  GOAWAY(NO_ERROR) first so the client can tell it from a network fault (unless
  the deadline lands while a file-chunk read is in flight, when the deferred
  close is a bare FIN). A client
  that keeps returning credit re-arms the deadline on every pass and is never cut
  off. Covered by tests/test_http2_backpressure.nim for a buffered response and
  for a streamed `sendFile`. (#236)
- Static files: a streamed `res.sendFile` no longer ends its body early when a
  file read comes up short. Each 256 KiB hop read through one buffered
  `readBuffer` and the trampoline treated any shortfall as end of file, closing
  the response with a clean terminator at a length contradicting the
  `Content-Length` already on the wire. Both ways there are ordinary: `read(2)`
  may legally return fewer bytes than asked for on a regular file, and
  `readBuffer` raises on a short read whose stream has its error flag set,
  discarding the bytes it had already copied, so a partially-satisfied hop
  reported zero. Hops now `pread` in a loop until the buffer is full, which
  makes a short result mean end of file and nothing else and a failure raise. A
  hop that cannot deliver what the declared length still owes aborts the
  response (RST_STREAM on HTTP/2 and /3, connection close on HTTP/1) instead of
  completing it short, a mangled read continuation aborts rather than silently
  restarting the body at offset 0, and a failed *initial* read answers 500,
  since nothing has been sent and the length is still ours to retract. (#386)
- Timeouts: a loop thread that did not get to run for several seconds no longer
  charges that gap to the deadlines armed on its connections. It used to come
  back and fire every deadline that fell inside the gap at once, at peers that
  had done nothing wrong, and the phase a connection happened to be in decided
  what the peer saw: a connection still in its TLS handshake was reset with no
  alert, an HTTP/2 connection closed with no GOAWAY, an in-flight request or
  response truncated -- an unexplained connect failure or read error from a
  server that was otherwise healthy. Measured on an oversubscribed soak host
  (HTTP/2, 14 loop threads, load ~20), ticks were missed by 2 to 33 seconds
  against a 10 s `headerTimeout`. The armed deadlines are now pushed out by the
  gap less its final second, so `headerTimeout`, `bodyTimeout`, `writeTimeout`,
  `keepAliveTimeout` and the WebSocket keep-alive stamps measure a peer that has
  gone quiet while the server could serve it, rather than the host's scheduler.
  They stay finite and absolute, so a peer that is still silent once the loop
  recovers is reaped one gap later, and a slowloris gains only the time the
  server could not serve anyone at all. (#386)
- chronos adapter: the pump no longer spins on futures that only the loop thread
  can complete. Every awaited handler future counted toward `pendingOps`, and a
  non-zero tally made the pump run eight `poll()` passes per loop iteration and
  cap the selector wait at 5 ms. But a handler parked in `ws.messages` or
  `await req.read()` waits on a core callback that runs on the loop thread:
  chronos has no fd, timer or callback of its own for it and can never complete
  it by polling, so a server holding long-lived WebSocket or streaming
  connections never reached zero and every loop thread spun ~1600 chronos polls
  a second forever without ever sleeping on its selector. Futures parked on a
  core wakeup are now tracked separately and the spin (with the cap) ends once
  every outstanding future is parked that way; anything chronos itself drives
  keeps the old behaviour. On the soak's WebSocket cell (HTTP/1, 96 sockets, 14
  loop threads) this was 150-374% CPU against 25-37% for the sync build at the
  same 33k messages/s, and the missing headroom is what let individual
  SO_REUSEPORT threads stall long enough to miss handshake deadlines. (#386)
- HTTP/3: a live but quiet QUIC connection is no longer reaped as idle. RFC 9000
  10.1 restarts an endpoint's idle timer only on a packet it receives, so a peer
  waiting for a response never refreshes its own and any gap in application data
  leaves the connection silent until one side tears it down and blames an "idle
  timeout" on a server that is healthy and still serving its other connections.
  Two things made that gap reachable: the shim advertised a hardcoded 30 s
  `max_idle_timeout`, half the HTTP/1 and /2 budget and narrower than the h3
  drain grace -- and, because QUIC takes `min(local, peer)`, that also talked
  the *client's* timer down -- and ngtcp2's keep-alive was left at its disabled
  default, so nothing ever filled a gap. The advertised window now comes from
  `keepAliveTimeout`, so both protocols give a peer the same budget, and the
  keep-alive PING is armed at a third of it (ack-eliciting, so it restarts the
  timer at both ends, with room for two lost PINGs). ngtcp2's own idle and
  loss-detection timers are absolute stamps on the clock the shim hands it and
  are deliberately NOT given the loop's stall credit above: ngtcp2 asserts that
  the clock never goes behind a stamp it has already seen, and the loop drives
  h3 before it ticks, so crediting the gap aborted the process. (#386)
- Stress harness: a soak cell that fails for an unhandled reason now records
  that reason. The canary client (`conformance/stress/client/stress_client.py`)
  handled exactly two failure classes, `Fail` and `asyncio.TimeoutError`, and
  printed both to stdout; anything else -- an `AttributeError` in a workload, a
  `RuntimeError` out of aioquic/httpx -- propagated out of `asyncio.run`, which
  puts the traceback on stderr. The canary container was also run without
  `2>&1`, and the harness is driven as `nimble stress | tee stress.log`, which
  tees only stdout, so the archived log showed a bare `FAILED (exit 1)` with no
  cause anywhere and the cell could not be root-caused after the fact. The
  canary's stderr is now merged into the tee'd stream, and `main` has a
  catch-all (plus an `ExceptionGroup` arm, since a library's `TaskGroup` can
  raise one that neither existing handler matches) that prints
  `FAIL <workload>: unexpected <type>: <message>` and the full traceback to
  stdout before exiting non-zero. `KeyboardInterrupt` and `SystemExit` still
  propagate. The fire-and-forget `reporter` and `loop_watchdog` tasks, which
  `main` cancels without awaiting, report their own death on stdout too: an
  exception in either was never retrieved, so a dead reporter and a healthy
  quiet run both looked like zero report lines. The chaos sidecar's catch-all
  prints its traceback for the same reason and now covers `BaseException`, so a
  `CancelledError` escaping its `run()` exits 2 (internal error) instead of 1,
  which is its fd-leak verdict. (#387)
- HTTP/3: the QUIC receive buffer now holds a datagram as large as the
  `max_udp_payload_size` the server advertises. It was 2048 bytes while the
  transport parameters carried ngtcp2's 65527 default, so a conforming client on
  a large-MTU path (a 9000-byte VPC MTU, 65536 on loopback) was entitled to send
  a datagram the kernel then truncated: header protection and AEAD failed,
  ngtcp2 dropped the packet, the client retransmitted the same oversize datagram
  indefinitely, and the connection died on the idle timer with nothing logged at
  either end. Both numbers now come from one constant in the shim
  (`vq_max_recv_udp_payload`), so they cannot drift apart; the advertisement was
  deliberately NOT clamped down to the old buffer, which would have capped every
  datagram the peer sends us and cost throughput on exactly those paths. On
  Linux the receive passes `MSG_TRUNC`, so a datagram that still does not fit is
  dropped and counted instead of being fed to ngtcp2 as line corruption. (#380)
- HTTP/3: QUIC ingress now takes at most 256 datagrams per pass of the event
  loop, so a UDP flood can no longer starve the HTTP/1.1 and HTTP/2 connections
  on the same loop thread. `ngReceive` drained the socket with `while true`, and
  every datagram is decrypted and parsed synchronously before the next
  `recvfrom`, so a source whose datagrams cost the server more than they cost
  the sender kept the thread inside the receive loop: TLS handshakes stalled,
  responses did not flush, deadlines fired. Reproduced with a flood of Initial
  packets naming an unsupported QUIC version (each answered with a Version
  Negotiation packet, so each costs a parse plus a send): a plain HTTP/1.1
  request on the same server went unserved past a 2 s client timeout, and now
  completes in tens of milliseconds. The loop treats a spent budget the way it
  treats its `sslReady` queue, going straight back round without waiting on the
  selector, so the backlog is still drained promptly, just with the TCP fds
  serviced between batches. Address validation (a Retry token) is still not
  issued, so a spoofed-source flood can still make the shim commit
  per-connection state up to `maxConnections`. (#381)
- Accept path: a connection the server accepts and then drops is now counted and
  explained instead of vanishing. Three paths did it in silence -- the
  `maxConnections` cap, `startTls` failing because `newTlsSession` returned nil,
  and `registerHandle` raising (the reason swallowed by `except CatchableError`)
  -- and at the client every one of them is a socket that opens and dies with
  nothing on it, which is indistinguishable from a network fault. A 1-hour soak
  lost a cell to an empty `ConnectError` 90 s in with nothing anywhere to say
  which. New `server.acceptDrops()` / `vortex.acceptDrops()` (and a no-argument
  `acceptDrops()` a `{.gcsafe.}` handler can call) return a process-wide
  `AcceptDrops` whose `total` sums exactly those three (`cap`, `tls`,
  `register`). A fourth counter, `acceptSuspend`, reports the times `accept()`
  itself failed on fd/memory exhaustion and the listener was deregistered for
  ~1s; it is reported beside `total` and deliberately not part of it, because
  nothing was accepted there and the kernel's backlog simply waits for the
  listener to come back, so it counts backoff events rather than connections.
  Each of the four writes one line to stderr saying why -- which cap, the
  OpenSSL reason, the selector's message -- rate-limited to one per cause per
  5 s per loop thread, with the first occurrence of a cause never suppressed.
  Those lines, and the handful of other operator messages the server emits, go
  through a single sink (`opLog`) rather than bare `stderr.writeLine` calls
  scattered through the loop. The stress harness grew a `/drops` endpoint
  (`/stats` keeps its exact three fields), prints the tally on SIGTERM and then
  shuts the server down through the blocking `close` so its loop threads are
  joined before the process exits (it used to fall off the end of `main` with
  them still running), and dumps the server container's log when a cell fails,
  so the server's stderr survives in the run log. (#388)
- TLS: a private-key load failure now names its reason. `loadKeyMem` cleared the
  OpenSSL error queue on the failure path, so by the time `buildTlsCtx` read it
  there was nothing left and every key problem -- a wrong `keyPassword`, a
  truncated PEM block, a key in an encoding the decoder rejects -- was reported
  as `cannot load TLS certificate/key: unknown TLS error`, which reads like a
  library fault rather than the configuration mistake it is. The reason now
  survives to the exception message (`bad decrypt` for a wrong passphrase), on
  key files and in-memory `keyPem` alike, and `lastErrorMsg` drains the queue it
  read from so one failed load cannot lend its reason to the next attempt on the
  same thread. (#377)
- TLS: SNI host matching on the TCP listener is ASCII-case-insensitive. Host
  names are case-insensitive (RFC 6066, and DNS generally), but `cstrEq` and
  `wildMatch` compared bytes, so a client that sent `Example.com` for a
  configured `example.com` matched nothing, fell through to the default
  certificate and failed the handshake on a name mismatch. Both sides of the
  comparison are now folded, so the configured `host` need not be lower-cased
  either, and the fold is ASCII-only rather than locale-aware (a locale tolower
  folds `I` to a dotless `i` under tr_TR, which would make matching depend on
  the server's locale). The HTTP/3 path already folded case. (#358)
- TLS: a per-host SNI certificate that fails to build no longer leaks the
  half-built config. `newTlsConfigWith` let the exception escape, so the default
  context, every per-host context ahead of the failing one and the shared
  `TlsConfig` block were all abandoned. They are freed before the raise, and the
  message now names the host (`SNI host "broken.example": ...`) rather than
  reporting only the material, so an operator with several SNI entries can tell
  which one is broken and an embedder that catches the raise can retry with
  corrected configuration. (#361)
- TLS: SNI keeps working after a certificate reload. `reloadTlsConfig` rebuilds
  the default context and re-registered only the ALPN callback on the
  replacement, so the servername callback went away with the old context: from
  the first `reloadTls()` onwards every configured SNI host was served the
  *default* certificate and failed the handshake on a name mismatch, until the
  process restarted. Because the fault only appears after a reload it would
  surface in production long after deployment rather than in testing. The
  callback registration both paths need is now one helper (`installDefaultCbs`),
  so the initial build and the reload cannot drift apart again. (#355)
- TLS: per-host (SNI) certificates rotate on reload. `reloadTlsConfig` rebuilt
  only the default context, so every SNI host served the certificate it loaded
  at startup for the lifetime of the process and eventually served an expired
  one, with no API to rotate it short of a restart. `TlsConfig` now keeps each
  host's `TlsMaterial` alongside its host name and context, every per-host
  context is rebuilt from it on reload (so a bare `reloadTls()` re-reads the
  per-host files, the certbot pattern), and `reloadTls`/`reloadTlsConfig` take
  an `sni` override that replaces the per-host material wholesale, host set
  included, persisted only on success. The reload is all-or-nothing with the
  default context: one per-host certificate that fails to build rejects it and
  leaves everything as it was, rather than half-rotating or dropping a host back
  to the default certificate. The new contexts are published and the old ones
  released under `ctxLock`, which `servernameCb` now holds across its whole
  lookup, so a handshake can neither index a context array that disagrees with
  the host list it scanned nor have a context freed between the load and
  `SSL_set_SSL_CTX` (which up-refs what it is handed). The `sni` override
  reaches the TCP listener only: the HTTP/3 engine rebuilds its per-host
  contexts from its own configured material on the same reload (#374), so
  renewed per-host *files* rotate on both transports while new in-memory
  per-host material rotates on TCP alone. (#356)
- TLS: a rejected certificate reload says why. `reloadTlsConfig` caught the
  exception carrying the only diagnostic that existed and returned a bare
  false, which `server.reloadTls` passed on with nothing written anywhere and
  no accessor to ask, so an operator whose certbot deploy hook failed could not
  tell an unreadable certificate from a mismatched key, a missing OCSP file or a
  rejected cipher string. Every false return now records the reason on the
  config and writes one `vortex: TLS reload failed: <reason>` line to stderr,
  matching the convention `applyQuicReload` already follows, so a hook that
  ignores the bool still leaves a trace. Read the reason back with
  `server.lastTlsReloadError` / `vortex.lastTlsReloadError` (present and
  constant under `-d:plainHttp`); a successful reload clears it. The reason is
  published and read under the short context lock, not the reload lock, so
  reading it from a health handler on a loop thread cannot stall that loop for
  the length of a rotation. (#378)
- HTTP/3: the ngtcp2 ossl crypto backend is initialized exactly once per
  process instead of once per QUIC engine. `ngtcp2_crypto_ossl_init` allocates
  an OpenSSL `ex_data` index and parks it in a library-level global, and is
  documented as a once-per-process, not-thread-safe initializer -- yet
  `vq_engine_new` ran it on every loop thread as the loops came up, all at the
  same time. Each extra call leaked an index, and while they raced a session
  configured under one index could be read back under another, which yields a
  null crypto context and a failed handshake: non-deterministic, only during
  startup of a `numThreads > 1` server, and indistinguishable from a flaky
  client. The initializer now runs under a `std::call_once` and every engine
  sees the same verdict, so a failure fails them all rather than leaving some
  loops on a half-initialized backend. (#357)
- HTTP/3: the shim's certificate loaders clear the context's existing chain
  before installing a new one, so an in-place certificate reload no longer
  grows what h3 clients receive. `SSL_CTX_use_certificate` does not touch the
  chain (unlike `SSL_CTX_use_certificate_chain_file`, which clears it first),
  and the PEM loader appended the new intermediates on top of the previous
  leaf's, as did the PKCS#12 loader's `SSL_CTX_add1_chain_cert` calls. After a
  CA rotated its intermediate, the next reload handed clients the new leaf
  together with the old, no-longer-valid intermediates -- rejected outright by
  strict clients, a larger handshake for the rest -- and the chain grew again
  with every subsequent reload. (#354)
- HTTP/3: a certificate hot reload now builds a complete replacement `SSL_CTX`
  and installs it only once every piece of material loaded and the key matches
  the certificate, so a refused reload leaves the engine serving exactly what
  it was serving before. It used to write into the live context, certificate
  first then key, with no validation and no rollback: OpenSSL's `ssl_set_cert`
  silently frees the existing private key when the new leaf does not match it,
  and `ssl_set_pkey` silently frees the existing certificate when the new key
  does not match, so an unreadable, missing or mismatched key left the loop's
  context holding one half of a pair and every later HTTP/3 handshake on it
  failed until the process restarted -- while the operator was told the old
  certificate was still serving. A cert-only reload was even reported as a
  success. The per-host (SNI) rebuild is part of the same transaction, so a
  failure anywhere leaves every context untouched, and the reload's failure
  reason now reaches the log line instead of generic text: the shim's context
  builder records which step failed plus whatever OpenSSL queued about it
  (`vq_engine_last_error`), and the same reason is appended to the "HTTP/3
  engine setup failed" line at startup. (#352)
- HTTP/3: a bare `reloadTls()` now rotates the HTTP/3 certificate too. The
  no-argument form means "re-read the configured material", which the TCP
  listener has always honoured, but nothing resolved it on the QUIC side: the
  loop handed the shim `readFile("")`, which raised, so the reload failed and
  was logged. That is the certbot pattern the project documents (renew in
  place, then `srv.reloadTls()`), so after a renewal HTTP/1.1 and HTTP/2 served
  the new certificate while HTTP/3 kept serving the one loaded at startup until
  it expired, at which point every h3 connection failed while the other
  protocols stayed healthy. The QUIC engine now keeps the material it was
  configured from -- cert/key paths, in-memory PEM, PKCS#12 bundle and the key
  passphrase -- and a reload with no paths rebuilds from it, re-reading any
  files, exactly as `reloadTlsConfig` does; what loads successfully becomes
  what the next bare reload re-reads. Explicit paths replace the configured
  source under the same rules as the TCP path, including refusing a key-only
  reload against a PKCS#12-sourced certificate. For material configured as PEM
  bytes or a bundle there is nothing to re-read, so the rebuild is a correct
  no-op for the default certificate and still refreshes the per-host files.
  (#353)
- TLS, HTTP/3: certificate validity (`notBefore` / `notAfter`) is now checked
  wherever material is installed -- at startup and on reload, on the TCP path
  (`buildTlsCtx`) and the QUIC path alike, default and per-host certificates
  both. Nothing checked it before: an expired certificate loaded cleanly and
  `reloadTls()` returned true, so a renewal hook racing a certbot symlink swap,
  or one pointed at `archive/` instead of `live/`, reported success while every
  new connection from that moment failed at the client with
  `certificate_expired`, masked until the in-flight ones turned over. The
  policy is a hard failure with no clock-skew allowance and no warning-only
  mode: startup raises `certificate expired at <notAfter>` or `certificate not
  valid until <notBefore>`, and a reload is rejected with the running
  certificate left serving. A time that cannot be read at all is refused too:
  `X509_cmp_current_time` returns 0 only on failure (it reports an exact
  equality as -1), and that 0 used to count as "inside the window", so a
  certificate whose `notAfter` OpenSSL's own `x509` command prints as `Bad time
  value` was installed on the strength of a comparison that never happened; it
  now fails with `certificate validity time could not be parsed`.
  **Behaviour change**: a server that previously started while serving an
  expired certificate now refuses to start. (#379)
- HTTP/3: TLS 1.3 session resumption now works across loop threads. Each loop
  builds its own QUIC `SSL_CTX` and OpenSSL mints a random ticket key per
  context, so a ticket was only decryptable by the loop that issued it -- while
  which loop receives a returning client's first datagram is decided by the
  kernel's SO_REUSEPORT hash over its new 4-tuple, which has nothing to do with
  the issuing loop. On an N-loop server roughly (N-1)/N of resumption attempts
  therefore fell back to a full handshake, invisibly: the connection succeeded,
  just a round trip slower, every time. The contexts stay per-loop (the
  per-loop certificate reload is built on that) and a process-wide ticket key
  is installed on every one of them, default and per-host, initial and rebuilt,
  alongside an explicit session-id context like the TCP path's. The key rotates
  hourly: the current key encrypts, the previous one still decrypts for one
  more lifetime with the ticket reissued under the new key, and any older name
  is refused and costs that client one full handshake -- so a disclosed key
  exposes at most two hours of resumed sessions instead of every session since
  startup, which is what nginx and envoy rotate for. The TCP listener is
  unchanged and keeps OpenSSL's per-context key: nothing rotates it on a
  schedule, but it (and the TLS 1.2 session cache) is regenerated by every
  certificate reload, which invalidates every ticket issued before it -- so h3
  resumption now survives a rotation where TCP's does not. 0-RTT early data is
  not offered on any protocol and is unaffected. (#382)
- TLS: an OpenSSL failure reason is now formatted into a buffer of its own, and
  the thread's error queue is cleared before each session is created, so the
  reason an operator reads belongs to the failure in front of them.
  `lastErrorMsg` formatted with `ERR_error_string(e, nil)`, which writes into
  OpenSSL's single process-wide `static char buf[256]` and is documented as not
  thread-safe. That was harmless while only the configuration path used it, but
  #388 exported it as `tlsLastErrorMsg()` and the accept path calls it from
  every loop thread, so two threads reporting a failure at the same moment could
  each be handed the other's message: a two-thread probe read 128 to 2,760 wrong
  messages per 400,000 samples, and none at all through
  `ERR_error_string_n` into a local buffer. `newTlsSession` also never cleared
  the queue, and `tlsHandshake` / `tlsRead` / `tlsWrite` leave their reason on
  it when a connection fails, so the accept path's `TLS session setup failed`
  line could name the failure of an *earlier* connection accepted on the same
  loop thread. `loadPkcs12` and `buildTlsCtx` now clear the queue on entry as
  the PEM loaders already did, so a rejected bundle, cipher string or protocol
  version is not reported with a leftover from unrelated OpenSSL work either.
  (#377, #388)
- TLS: a certificate-only `reloadTls(certFile = ...)` against material that came
  from a PKCS#12 bundle is rejected with a reason, the way the key-only case
  already was. The bundle carries both halves, so clearing the bundle fields for
  a lone certificate left no private key at all: the reload did fail, but its
  reason was `cannot read private key : cannot open:` -- the path and the OS
  reason both blank, naming neither the key nor the bundle. It is now refused
  before anything is built, with `a certificate-only reload cannot replace a
  PKCS#12 bundle: rotate certFile and keyFile together, or reconfigure with a
  new bundle`, and an empty key or bundle path reaching the loader anywhere else
  reports `no private key configured` rather than asking the OS to open `""`.
  (#377, #378)
- TLS: an SNI handshake no longer serialises every loop's accept path. The
  servername callback held the config's context lock across `SSL_set_SSL_CTX`,
  which in OpenSSL 3 is not a pointer store: it duplicates the entire CERT of
  the context it is handed (an allocation plus an up-ref per chain entry and per
  key slot) and frees the connection's old one. `acquireCtx` takes that same
  lock on every accept, so every accepted connection on every loop thread
  queued behind each SNI handshake's certificate duplication. The lock now
  covers only the host scan and an up-ref of the chosen context -- which is what
  keeps a concurrent reload from releasing it -- while the switch itself runs
  outside the lock and the callback's own reference is dropped straight
  afterwards. (#356)

### Changed

- WebSocket: frames sent from an `onMessage` handler, or by a worker's burst
  through the outbox, are written to the socket once per batch instead of once
  per message (`Connection.flushHold`), and HTTP/1 frames are serialized
  straight into the connection buffer. Inbound frames reuse one payload buffer
  per loop thread, are unmasked 8 bytes at a time, and reach the handler with no
  extra copy. The outbox wakes the loop only on the empty-to-nonempty
  transition. Echo throughput with several messages in flight is roughly 9x in
  a local micro-benchmark. (#333, #336, #337, #338)
- HTTP/2: after the socket drains, the write loop refills from the scheduler and
  keeps writing (up to 16 refills per pass) instead of returning to the selector
  after every 64 KiB. `res.write` on a stream with an empty backlog emits DATA
  straight from the caller's buffer and parks only what flow control refuses;
  writes in one frame batch or outbox batch are flushed once. The deadline
  policy reads maintained counters instead of scanning the stream table on every
  input event. (#332, #334, #339)
- `sendFile` over HTTP/2 dispatches the next disk read before writing the chunk
  that arrived, so the read overlaps the write instead of idling the socket;
  the read-ahead budget is one chunk (256 KiB) measured before the write, which
  keeps the same per-stream ceiling. (#340)
- `writeTimeout` now defaults to 30 s (was 0, off), matching `bodyTimeout`, so a
  slow-reading client that stops draining a response is reaped out of the box.
  It is idle-style (re-armed on every partial write), so a response that keeps
  moving is never cut off; set it to 0 to restore the old behaviour. The
  `maxHeaderCount` limit is documented as answering 431, not 400, and as
  HTTP/1 only. (#249)

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
