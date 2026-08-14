# Security

vortex is a from-scratch HTTP/1.1, HTTP/2, and HTTP/3 server, so it sits on
the untrusted-input boundary: it parses attacker-controlled bytes on every
connection. This document describes what it defends against, how to tune the
defenses, and how the defenses are verified.

The guiding principle is **bounded by default**: every place where a client
can make the server allocate memory, spawn work, or hold a resource has a
limit with a safe default, and the limits are configurable in `initVortexConfig`.

## Threat coverage

| Threat | Defense | Verified by |
|--------|---------|-------------|
| HTTP/2 Rapid Reset (CVE-2023-44487) | Per-connection reset budget, GOAWAY when exceeded; reset streams are never dispatched to a handler | `test_security_dos` |
| HTTP/2 framing floods (PING / SETTINGS / PRIORITY) | Per-connection control-frame budget that resets on real request progress, GOAWAY when exceeded | `test_security_dos` |
| HPACK decompression bomb | Decode aborts once the decoded field list exceeds `maxHeaderSize`, checked during decode | `test_security_parsing` |
| Request smuggling (CL/TE) | Reject Content-Length with Transfer-Encoding, duplicate Content-Length, space in field name, non-chunked TE, and bare-LF line endings | `test_security_parsing`, `test_http1_parser` |
| Slowloris / slow body | Coarse header / body / idle timeout wheel | `test_security_dos` |
| Oversized header / body | 431 / 413 with reliable delivery via lingering close | `test_http1_parser`, `test_http1_server`, `test_security_dos` |
| Integer overflow | Overflow guards on Content-Length and chunk-size parsing; fixed-width and bounded varint elsewhere | `test_security_parsing` |
| Memory exhaustion (connections / streams) | Connection cap (accept-and-drop), concurrent-stream cap, compacted HTTP/2 receive buffer | `test_security_dos` |

## Configuration

All limits are fields on `VortexConfig` (see `initVortexConfig`). A value of `0`
disables the corresponding check where noted.

| Setting | Default | Purpose |
|---------|---------|---------|
| `maxConnections` | 65536 | Live connections per loop thread; excess is accepted then dropped |
| `maxConcurrentStreams` | 256 | Open HTTP/2 and HTTP/3 streams per connection |
| `maxResetStreams` | 512 | HTTP/2 peer resets before GOAWAY (rapid reset) |
| `maxControlFrames` | 1000 | HTTP/2 PING/SETTINGS/PRIORITY between stream progress |
| `maxRequestsPerSocket` | 0 (off) | HTTP/1 keep-alive requests before the connection is closed |
| `maxHeaderSize` | 16 KiB | Request line + headers (431); also caps HPACK decoded size |
| `maxHeaderCount` | 100 | Header fields per request |
| `maxBodySize` | 8 MiB | Request body (413); per-stream for HTTP/2 and HTTP/3 |
| `headerTimeout` | 10 s | First byte to end of headers |
| `bodyTimeout` | 30 s | End of headers to end of body |
| `keepAliveTimeout` | 60 s | Idle time between requests |
| `minTlsVersion` | `tlsV12` | Lowest accepted TLS version (`tlsV12` or `tlsV13`); QUIC is always 1.3 |
| `tlsCipherList` | "" | OpenSSL cipher list for TLS 1.2 ("" keeps OpenSSL's default) |
| `tlsCipherSuites` | "" | OpenSSL cipher suites for TLS 1.3 ("" keeps OpenSSL's default) |

## Defenses in detail

### HTTP/2 abuse

- **Rapid Reset (CVE-2023-44487).** A peer that opens a stream and immediately
  resets it costs handler work while never holding concurrency, so the
  concurrent-stream cap alone does not stop it. vortex counts peer
  `RST_STREAM` frames per connection and sends `GOAWAY(ENHANCE_YOUR_CALM)`
  past `maxResetStreams`. Crucially, the event loop also skips dispatching any
  stream that was reset in the same read batch, so the handler (and any
  `blocking:` worker task it would enqueue) never runs for a cancelled
  request.
- **Framing floods.** Each PING and SETTINGS frame otherwise queues an
  acknowledgement, and PRIORITY frames are pure overhead. A per-connection
  control-frame counter, reset whenever a real request arrives, triggers
  GOAWAY past `maxControlFrames`. WINDOW_UPDATE floods need no separate budget:
  they self-limit through the flow-control window overflow check.
- **Concurrent streams.** `maxConcurrentStreams` is advertised in SETTINGS and
  enforced; excess streams are refused with `RST_STREAM`.

### Header compression

- **HPACK decompression bomb.** A small compressed block can reference large
  dynamic-table entries repeatedly, expanding to many times its size. The
  decoder tracks the accumulated decoded field-list size and raises during
  decode once it exceeds the cap (wired to `maxHeaderSize`), rather than
  checking only after fully expanding.
- **QPACK.** vortex advertises a bounded dynamic-table capacity (4096 bytes)
  as its decoder limit, so the peer's request-header dynamic table can never
  grow past that ceiling, and a field section is further bounded by its HEADERS
  frame length (itself capped by `maxBody`). The response encoder is
  deliberately conservative: it never evicts, and only references entries the
  peer's decoder has acknowledged, so it never emits a reference that would
  block the decoder (`BLOCKED_STREAMS` stays 0, and there is no eviction or
  reference-counting state for an attacker to churn).

### HTTP/1.1 parsing

The incremental, zero-copy parser rejects the classic request-smuggling and
overflow vectors before dispatch:

- Content-Length together with Transfer-Encoding: rejected.
- Duplicate Content-Length: rejected.
- Space in a field name: rejected.
- Transfer-Encoding other than `chunked`: 501.
- Bare-LF line endings (CRLF is required): rejected.
- Content-Length and chunk-size values are parsed with explicit overflow
  guards, returning 413 rather than wrapping.
- Chunk extensions are tolerated and ignored.
- An HTTP/1.1 request without a `Host` field, or with more than one, is
  rejected with 400 (RFC 9112 3.2), closing a host-confusion vector.

Keep-alive connections can additionally be capped with `maxRequestsPerSocket`
(off by default): the last allowed request is answered with `Connection:
close`, bounding how long one connection is amortized across requests.

### Resource exhaustion

- **Connections.** Beyond `maxConnections`, new connections are accepted then
  immediately closed, which keeps the accept queue clear rather than letting
  it back up.
- **Receive buffer.** The HTTP/2 receive buffer is processed and compacted as
  frames are consumed, so it stays small regardless of upload size and is not
  clipped by a tight HTTP/1 body limit. A 1 MiB ceiling bounds backpressure
  while a `blocking:` worker holds a connection pinned.
- **Bodies and headers** are bounded by `maxBodySize`, `maxHeaderSize`, and
  `maxHeaderCount`; HTTP/2 and HTTP/3 bodies are capped per stream.

### Transport security (TLS)

TLS and ALPN are handled by OpenSSL (>= 3.5), and QUIC by ngtcp2 (with OpenSSL
as its crypto backend), so the transport cryptography is OpenSSL's. vortex adds a small policy surface on top:

- **Minimum version.** `minTlsVersion` defaults to `tlsV12`, which is set
  explicitly on the context so the insecure TLS 1.0 and 1.1 are refused
  regardless of the system OpenSSL default. `tlsV13` restricts the server to
  TLS 1.3. QUIC (HTTP/3) always uses TLS 1.3 by protocol.
- **Cipher selection.** `tlsCipherList` (TLS 1.2) and `tlsCipherSuites`
  (TLS 1.3) override OpenSSL's defaults when set; an invalid value fails fast
  at startup rather than silently falling back.
- Build with `-d:plainHttp` to exclude TLS and the OpenSSL dependency
  entirely (cleartext HTTP/1.1 and h2c only).

### Connection lifecycle

- **Lingering close.** When the server rejects a request mid-stream (for
  example an oversized header) and closes while request bytes are still
  unread, a naive `close()` sends a TCP RST that can truncate the error before
  the client reads it. vortex instead half-closes (sends FIN after the
  response) and drains the peer until its FIN, then closes cleanly, so the
  4xx is delivered. The drain is bounded by a deadline and the connection cap.
- **Fault isolation.** A handler exception becomes a 500 and the loop
  survives; an unexpected exception in a connection's processing closes only
  that connection, never the loop thread. HTTP/2 and HTTP/3 protocol errors
  send GOAWAY / stream resets rather than crashing.

## Testing

Security behavior is covered at three levels.

- **Unit (pure, fast).** `test_security_parsing.nim` drives the HTTP/1 parser
  and the HPACK decoder directly: smuggling and integer-overflow vectors, and
  a hand-built HPACK bomb that must raise rather than expand. `test_http1_parser.nim`
  and `test_hpack.nim` add the parser edge cases and the RFC 7541 test vectors.
- **Integration (live server).** `test_security_dos.nim` drives a running
  server at the socket and frame level through `h2client.nim`, a minimal
  frame-level HTTP/2 client: rapid-reset / PING / SETTINGS floods must GOAWAY
  while a well-behaved request still succeeds; oversized requests are rejected;
  stalled requests time out; connections past the cap are dropped; and a large
  HTTP/2 request burst is processed rather than clipped. `test_http1_server.nim`
  confirms the lingering close delivers a 431 before closing.
- **Conformance.** The HTTP/2 implementation passes `h2spec` (145 passed, 1
  skipped, 0 failed against a TLS server); the one skipped case is
  HTTP/2-over-TLS-only and does not apply to the cleartext run. The HTTP/3
  implementation passes `h3spec`'s HTTP/3-servers group (15 examples, 0
  failures), which covers the HTTP/3 and QPACK error cases. Both run as Docker
  conformance jobs in CI (`nimble h2spec` / `nimble h3spec`).

Run everything with `nimble test`.

## Fuzzing

The three decoders that consume untrusted bytes have coverage-guided
libFuzzer harnesses in `fuzz/`:

- `fuzz_http1` fuzzes `parser.parse`, both whole-buffer and split feed (to
  exercise resumability).
- `fuzz_hpack` fuzzes the HPACK decoder across multiple blocks so dynamic-table
  state carries between inputs.
- `fuzz_qpack` fuzzes the QPACK decoder.

They build with clang and `-fsanitize=fuzzer,address`, with Nim's bound and
overflow checks left on and `-d:useMalloc` so AddressSanitizer sees Nim
allocations. A small seed corpus under `fuzz/seeds/` bootstraps coverage. All
three run clean over millions of inputs with no crashes or leaks.

Run with `nimble fuzz`, which builds `fuzz/Dockerfile` (bundling clang and
the libFuzzer runtime, which Apple clang lacks) and fuzzes each target for
30s, exiting non-zero on a crash:

```
nimble fuzz
# override duration or narrow to one target:
docker run --rm -e DUR=120 vortex-fuzz
docker run --rm vortex-fuzz hpack
```

On a host that already has clang and `compiler-rt`, `fuzz/run.sh` runs the
same harnesses without Docker.

## Reporting a vulnerability

vortex is pre-1.0. Please report suspected vulnerabilities privately to the
maintainer (Craig Younker, cryo2010@gmail.com) or via a private security
advisory on the repository, rather than opening a public issue. A short
description and a reproducing input are enough to start.

## Deployment boundary

vortex defends against the abuse classes that a reverse proxy or CDN cannot
handle for it, because they are inherent to terminating the protocol:
HTTP/2 frame abuse, request smuggling, header-compression bombs, malformed
input, and per-connection resource exhaustion. Those must be handled by
whatever parses the bytes, so they live here.

Per-source-IP connection and request rate limiting is deliberately **not** in
the server core. It belongs at the fronting layer (reverse proxy, load
balancer, or CDN), for two reasons:

- Behind a proxy every connection arrives from the proxy's address, so a
  socket-peer limiter would throttle all clients as one. Doing it correctly
  requires trusted-proxy configuration and `X-Forwarded-For` / PROXY-protocol
  real-IP resolution, which is a routing concern, not a parsing one.
- It is the consensus of the mainstream server ecosystem. Node's `http` core
  offers a global `maxConnections` but no per-IP; Go's `net/http` offers only
  timeouts and a global `netutil.LimitListener`; Python's Falcon delegates
  connection handling entirely to the WSGI/ASGI server, none of which limit
  per IP. All treat per-IP as infrastructure's job.

If vortex is deployed directly on the internet with no fronting layer, put a
proxy in front for per-IP limiting. A minimal mitigation for the proxyless
edge case (a default-off, opt-in, per-thread per-source-IP connection counter)
could be added without the full trusted-proxy and real-IP machinery, but it is
not core work.

## Known limitations and roadmap

These are future work, not open holes:

- **Persisted fuzz corpus.** The libFuzzer harnesses run in CI (the `fuzz`
  job fuzzes each decoder for 30s per push), but without a persisted, growing
  corpus (OSS-Fuzz style) each run starts cold from the seed corpus.
- **TLS transport crypto** is OpenSSL's (see the Transport security section
  for the policy vortex layers on top). Certificate rotation, OCSP stapling,
  and session-ticket key management are not exposed yet.
