# Security

vortex is a from-scratch HTTP/1.1, HTTP/2, and HTTP/3 server, so it sits on
the untrusted-input boundary: it parses attacker-controlled bytes on every
connection. This document describes what it defends against, how to tune the
defenses, and how the defenses are verified.

The guiding principle is **bounded by default**: every place where a client
can make the server allocate memory, spawn work, or hold a resource has a
limit with a safe default, and the limits are configurable in `initSettings`.

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

All limits are fields on `Settings` (see `initSettings`). A value of `0`
disables the corresponding check where noted.

| Setting | Default | Purpose |
|---------|---------|---------|
| `maxConnections` | 65536 | Live connections per loop thread; excess is accepted then dropped |
| `maxConcurrentStreams` | 256 | Open HTTP/2 and HTTP/3 streams per connection |
| `maxResetStreams` | 512 | HTTP/2 peer resets before GOAWAY (rapid reset) |
| `maxControlFrames` | 1000 | HTTP/2 PING/SETTINGS/PRIORITY between stream progress |
| `maxHeaderSize` | 16 KiB | Request line + headers (431); also caps HPACK decoded size |
| `maxHeaderCount` | 100 | Header fields per request |
| `maxBodySize` | 8 MiB | Request body (413); per-stream for HTTP/2 and HTTP/3 |
| `headerTimeout` | 10 s | First byte to end of headers |
| `bodyTimeout` | 30 s | End of headers to end of body |
| `keepAliveTimeout` | 60 s | Idle time between requests |

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
- **QPACK** runs in capacity-0 mode: the dynamic table is forbidden, so there
  is no amplification vector to bound.

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
  HTTP/2-over-TLS-only and does not apply to the cleartext run.

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

Run with `nimble fuzz` or `fuzz/run.sh` (needs clang with the libFuzzer
runtime; Apple clang lacks it, so use the Arch container in `bench/Dockerfile`,
which installs `clang` and `compiler-rt`):

```
docker build -f bench/Dockerfile -t vortex-bench .
docker run --rm vortex-bench sh fuzz/run.sh
```

## Reporting a vulnerability

vortex is pre-1.0. Please report suspected vulnerabilities privately to the
maintainer (Craig Younker, cryo2010@gmail.com) or via a private security
advisory on the repository, rather than opening a public issue. A short
description and a reproducing input are enough to start.

## Known limitations and roadmap

These are tracked in `security.txt` and are future work, not open holes:

- **Per-IP connection limits** are not yet implemented (the connection cap is
  per loop thread, not per source address); this needs peer-address plumbing.
- **HTTP/3 conformance** is smoke-tested against real clients but not yet run
  against an h3spec-style suite.
- **CI fuzzing** with a persisted, growing corpus (OSS-Fuzz style) is not yet
  wired up; the harnesses currently run on demand.
- **TLS** relies on OpenSSL (>= 3.5) for the transport, ALPN, and QUIC; its
  security posture is inherited from OpenSSL. Build with `-d:plainHttp` to
  exclude TLS and its dependency entirely.
