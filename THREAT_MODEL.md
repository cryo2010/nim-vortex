# Threat model

vortex is a from-scratch HTTP/1.1, HTTP/2, and HTTP/3 server, so it sits on the
untrusted-input boundary: it parses attacker-controlled bytes on every
connection. This document describes what it defends against, organized with the
STRIDE framework (Spoofing, Tampering, Repudiation, Information disclosure,
Denial of service, Elevation of privilege), and how each defense is verified.

To report a vulnerability, see [SECURITY.md](SECURITY.md). For how to turn these
defenses on and tune them, see [HARDENING.md](HARDENING.md).

The guiding principle is **bounded by default**: every place where a client can
make the server allocate memory, spawn work, or hold a resource has a limit with
a safe default, configurable in `initVortexConfig`.

## System and trust boundaries

- **Client to server (untrusted).** Every byte from a connection is
  attacker-controlled until parsed and validated. This is the primary boundary
  and where most defenses live.
- **Fronting proxy or CDN (optional, semi-trusted).** When present, vortex can
  recover the real client IP from a HAProxy PROXY header, gated on a
  `trustedProxies` allowlist. `X-Forwarded-For` is available but not trusted by
  default.
- **Loop thread and worker pool (internal).** Blocking work runs on a worker
  pool. A `req.blocking:` worker reads a value-only snapshot of the request
  captured on the loop thread, never live loop-owned memory, so a handler on a
  worker cannot race or dangle loop state.
- **Transport crypto (trusted upstream).** TLS and ALPN are OpenSSL's (>= 3.5);
  QUIC is ngtcp2's, with OpenSSL as its crypto backend. vortex layers policy on
  top (versions, ciphers, verification) but does not implement the primitives.

## STRIDE analysis

Each row: the threat, vortex's defense, and how it is verified. "Verified by"
names the test/fuzz/conformance coverage (see the Verification section).

### Spoofing (identity)

| Threat | Defense | Verified by |
|--------|---------|-------------|
| Forged client IP behind a proxy | Real client IP recovered from a PROXY header only from a `trustedProxies` peer (`proxyProtocol`); `X-Forwarded-For` parsed but untrusted by default | `test_proxy_protocol` |
| Cross-site WebSocket hijacking (CSWSH) | `req.originAllowed(allowed)` gates the upgrade on an Origin allowlist; a cross-site page sends its own Origin, which is not in the list | `test_ws_origin` |
| Host-header confusion (HTTP/1.1) | A request with no `Host`, or more than one, is rejected with 400 (RFC 9112 3.2) | `test_http1_parser` |
| Unauthenticated client (when auth is required) | Optional mutual TLS: `verifyClient = Optional/Require` makes OpenSSL validate the client cert during the handshake; `req.clientCertSubject()` exposes the verified subject | `test_tls_advanced`, `test_tls_key_options` |

### Tampering (integrity)

| Threat | Defense | Verified by |
|--------|---------|-------------|
| Request smuggling (CL/TE) | Reject Content-Length together with Transfer-Encoding, duplicate Content-Length, non-chunked TE (501), space in a field name, and bare-LF line endings (CRLF required), before dispatch | `test_security_parsing`, `test_http1_parser` |
| Response splitting / header injection | Header names and values are rejected if they contain CR or LF, in both the buffered and streaming serializers | `test_security_headers`, `test_http1_server` |
| On-path modification | TLS integrity (OpenSSL / ngtcp2); see Information disclosure for the policy vortex sets | conformance (`testssl`) |

### Repudiation (attribution)

vortex exposes the data needed to attribute a request: `req.remoteAddress` (the
direct peer, or the real client IP when a trusted PROXY header is honored) and
`req.forwardedFor()` (the parsed `X-Forwarded-For` hops, untrusted by default).
Access logging and audit trails are the application's responsibility; structured
request/lifecycle logging hooks are a known gap (see Residual risk).

### Information disclosure

| Threat | Defense | Verified by |
|--------|---------|-------------|
| Downgrade to weak TLS | `minTlsVersion` defaults to TLS 1.2, set explicitly so TLS 1.0/1.1 are refused regardless of the system OpenSSL default; `tlsV13` restricts to 1.3; QUIC is always 1.3 | `test_tls`, `testssl` |
| Weak ciphers | `tlsCipherList` (1.2) and `tlsCipherSuites` (1.3) override OpenSSL's defaults; an invalid value fails fast at startup | `test_tls_key_options` |
| MIME sniffing / clickjacking / referrer leak | `securityHeaders` (opt-in) injects `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, plus HSTS on TLS; the `securityHeaders()` helper builds a per-response set (incl. CSP) | `test_security_headers`, `test_security_headers_toggle`, CI `zap` |
| Cookie theft (XSS / cross-site) | `setCookie()` defaults to `Secure`, `HttpOnly`, `SameSite=Lax` | `test_tls_helpers` |
| CRIME (compression oracle) | Response compression is off by default; enable `compress` only when the body is not attacker-influenced | (design default) |
| Server fingerprinting | `serverHeader` is configurable and can be blanked | (config) |
| Verbose errors | Error responses are generic and do not leak internals | `test_security_dos` |

### Denial of service

The largest category. Every client-driven allocation, work item, or held
resource is bounded.

| Threat | Defense | Verified by |
|--------|---------|-------------|
| HTTP/2 Rapid Reset (CVE-2023-44487) | Per-connection reset budget (`maxResetStreams`), GOAWAY(ENHANCE_YOUR_CALM) when exceeded; a stream reset in the same read batch is never dispatched, so no handler or `blocking:` worker runs for a cancelled request | `test_security_dos` |
| HTTP/2 framing floods (PING/SETTINGS/PRIORITY) | Per-connection control-frame budget (`maxControlFrames`) that resets on real request progress, GOAWAY when exceeded; WINDOW_UPDATE floods self-limit via the flow-control overflow check | `test_security_dos` |
| HPACK decompression bomb | The decoder tracks accumulated decoded size and raises during decode once it exceeds `maxHeaderSize`, not after fully expanding | `test_security_parsing`, `test_hpack` |
| QPACK abuse (HTTP/3) | QPACK is handled by nghttp3; vortex advertises a bounded dynamic-table capacity (4096 bytes) as its decoder limit, and a field section is further bounded by its HEADERS frame length (capped by `maxBodySize`), so the peer's request-header table cannot grow unbounded | conformance (`h3spec`) |
| Slowloris / slow body | Coarse header/body/idle timeout wheel (`headerTimeout`, `bodyTimeout`, `keepAliveTimeout`); optional `responseTimeout` | `test_security_dos` |
| Oversized header / body | 431 / 413 with reliable delivery via lingering close (see Elevation of privilege) | `test_http1_parser`, `test_http1_server`, `test_security_dos` |
| Integer overflow | Overflow guards on Content-Length and chunk-size parsing (413 rather than wrapping); fixed-width and bounded varints elsewhere | `test_security_parsing` |
| Connection / stream exhaustion | `maxConnections` (accept-and-drop past the cap, keeping the accept queue clear); `maxConcurrentStreams` advertised and enforced (excess refused with RST_STREAM); the HTTP/2 receive buffer is compacted as frames are consumed and bounded while a `blocking:` worker holds a connection | `test_security_dos` |
| Decompression bomb (request body) | `decompressRequest` (opt-in) decodes gzip/br/zstd bounded by `maxBodySize`; a bomb hits 413, a corrupt body 400, before the handler runs | `test_request_decompression` |
| Per-client request flooding | Token-bucket rate limiting, `rateLimit(key, ratePerSec, burst)`, keyed on the client IP; returns 429 over budget (per-loop-thread, see Residual risk / [HARDENING.md](HARDENING.md)) | `test_ratelimit` |
| Keep-alive amortization abuse | `maxRequestsPerSocket` (opt-in) answers the last allowed request with `Connection: close` | `test_http1_server` |

### Elevation of privilege

| Threat | Defense | Verified by |
|--------|---------|-------------|
| Handler bug taking down the server | A handler exception becomes a 500 and the loop survives; an unexpected exception in a connection's processing closes only that connection, never the loop thread; HTTP/2 and HTTP/3 protocol errors send GOAWAY / stream resets rather than crashing | `test_graceful_shutdown`, `test_security_dos` |
| Cross-thread memory corruption | A `req.blocking:` worker reads a value-only request snapshot, never live loop memory; regressed under ThreadSanitizer | `test_blocking_race`, `test_thread_race` (CI `testrace`) |
| Path traversal (static files) | `res.sendFile` resolves within the configured root and rejects traversal | `test_static_files` |
| Truncated error delivery | Lingering close: on a mid-stream rejection (for example an oversized header) vortex half-closes and drains the peer to its FIN before closing, so the 4xx is delivered instead of being lost to a TCP RST; bounded by a deadline and the connection cap | `test_http1_server` |

## Out of scope

- **Strict per-IP or global rate limiting.** vortex ships a per-client token
  bucket (`rateLimit`), but its state is per loop thread: with `numThreads > 1`
  and SO_REUSEPORT a client can receive up to `rate x numThreads`. For a strict
  global limit, run a single loop thread or enforce it at a fronting proxy / load
  balancer / CDN, which is also where you resolve the real client IP. This is the
  consensus of the mainstream server ecosystem (Node's `http` core, Go's
  `net/http`, Python's ASGI/WSGI servers all treat per-IP as infrastructure's
  job).
- **Transport cryptography.** The primitives are OpenSSL's (TLS) and ngtcp2's
  (QUIC). vortex sets policy (versions, ciphers, verification) but trusts the
  libraries for the crypto itself.
- **Application-level authn/authz, CSRF tokens, input validation** beyond the
  protocol layer. Those belong in the handler.

## Residual risk / known limitations

These are future work, not open holes:

- **Rate limiting is per loop thread** (see Out of scope): not a strict global
  cap under `numThreads > 1`.
- **OCSP stapling is static:** a configured response is stapled but not refreshed
  automatically; rotate it yourself.
- **No persisted fuzz corpus:** the libFuzzer harnesses run in CI, but each run
  starts from the small seed corpus rather than a growing OSS-Fuzz-style corpus.
- **Observability hooks pending:** no built-in request/lifecycle logging or
  metrics callbacks yet (relevant to Repudiation).

## Verification

Security behavior is covered at several levels.

- **Unit (pure, fast).** `test_security_parsing` drives the HTTP/1 parser and the
  HPACK decoder directly (smuggling, integer-overflow, and a hand-built HPACK
  bomb that must raise rather than expand); `test_http1_parser` and `test_hpack`
  add parser edge cases and the RFC 7541 vectors.
- **Integration (live server).** `test_security_dos` drives a running server at
  the frame level via `h2client` (rapid-reset / PING / SETTINGS floods must
  GOAWAY while a well-behaved request still succeeds; oversized requests
  rejected; stalled requests time out; connections past the cap dropped);
  `test_security_headers*`, `test_ratelimit`, `test_ws_origin`,
  `test_proxy_protocol`, and `test_tls_*` cover the SEC1-SEC5 hardening features;
  `test_http1_server` confirms the lingering close delivers a 431 before closing.
- **Conformance.** HTTP/2 passes `h2spec` (145 passed, 1 skipped, 0 failed
  against a TLS server; the skip is TLS-only and does not apply to the cleartext
  run). HTTP/3 passes `h3spec`'s HTTP/3-servers group (15 examples, 0 failures),
  covering the HTTP/3 and QPACK error cases. CI also runs an OWASP ZAP baseline
  scan (fails if a security header regresses) and a `testssl.sh` TLS scan (fails
  on HIGH/CRITICAL).
- **Sanitizers.** AddressSanitizer + UBSan over the test suite, and
  ThreadSanitizer over the handler-race and blocking-request stress
  (`testrace`).
- **Fuzzing.** Coverage-guided libFuzzer harnesses in `fuzz/` for the decoders
  that consume untrusted bytes: `fuzz_http1` (whole-buffer and split feed, to
  exercise resumability), `fuzz_hpack` (across multiple blocks so dynamic-table
  state carries between inputs), and `fuzz_wsdeflate`. They build with clang and
  `-fsanitize=fuzzer,address`, with Nim's bound/overflow checks on and
  `-d:useMalloc` so ASan sees Nim allocations. (QPACK is no longer fuzzed here:
  it moved to nghttp3 with the ngtcp2 migration.) Run with `nimble fuzz`.

Run the suite with `bash tests/run.sh` (or `nimble test`).
