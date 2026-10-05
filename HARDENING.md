# Hardening guide

How to configure vortex defensively. This is the operational companion to the
[THREAT_MODEL.md](THREAT_MODEL.md) (which explains *why* each defense exists) and
[SECURITY.md](SECURITY.md) (how to report a vulnerability).

All settings below are fields on `VortexConfig`, passed to `initVortexConfig`.
The guiding principle is **bounded by default**: the resource limits ship with
safe defaults, so an out-of-the-box server already resists the main abuse
classes. The feature toggles are opt-in.

## Defaults and philosophy

Safe by omission. These are **off by default** so you turn on only what you need:

| Feature | Field | Default | Turn on when |
|---------|-------|---------|--------------|
| OWASP response headers | `securityHeaders` | `false` | serving a browser-facing app (see per-response `securityHeaders()` for finer control) |
| Response compression | `compress` | `false` | the response body is not attacker-influenced (avoids CRIME) |
| Request-body decompression | `decompressRequest` | `false` | you accept gzip/br/zstd request bodies (needs `-d:httpGzip`/`-d:httpBrotli`/`-d:httpZstd`) |
| PROXY protocol | `proxyProtocol` | `Disabled` | behind a PROXY-aware load balancer |
| Mutual TLS | `verifyClient` | `None` | you require client certificates |

The resource limits, by contrast, are **on by default** with the values in the
reference below.

## Configuration reference

### Resource limits (denial of service)

| Setting | Default | Purpose |
|---------|---------|---------|
| `maxConnections` | 65536 | Live connections per loop thread; excess is accepted then dropped. The fd-indexed connection table behind it grows in 1024-slot blocks (~712 KiB each) up to the highest fd a loop thread sees, so its worst case is loop threads x ceil(fd rlimit / 1024) x 712 KiB, bounded by the fd rlimit rather than by this cap |
| `maxConcurrentStreams` | 256 | Open HTTP/2 and HTTP/3 streams per connection |
| `maxResetStreams` | 512 | HTTP/2 and HTTP/3 peer resets before the connection is torn down (rapid reset); 0 disables |
| `maxControlFrames` | 1000 | HTTP/2 overhead frames (PING and SETTINGS including their ACKs, PRIORITY, received GOAWAY, CONTINUATION, unknown types) between stream progress, each charged before the reply it forces, so an RST_STREAM sent in answer is paid for by the frame that caused it; SETTINGS is charged per entry; decays on accepted requests and on response body bytes sent, and WINDOW_UPDATEs that unblock nothing (connection-level, closed-stream, or an open stream the server owes no bytes on) spend credit earned by response DATA before they count: one credit per 256 bytes plus a floor of two per DATA frame emitted, so a small-frame producer acked on both levels per frame is never charged. A WINDOW_UPDATE that only dribbles (increment under 256 bytes, window still under 256 bytes after it, bytes waiting on that window) is charged straight to this budget instead, because the 1-byte DATA frames it forces would otherwise earn the credit for it; 0 disables |
| `maxRequestsPerSocket` | 0 (off) | HTTP/1 keep-alive requests before the connection is closed |
| `maxBlockingQueue` | 0 (unbounded) | `blocking:` tasks that may queue for a free worker; past it new dispatches fail fast (503 / `PoolSaturatedError`) instead of queuing behind slow or stuck work |
| `maxHeaderSize` | 16 KiB | Request line + headers (431); also caps HPACK decoded size |
| `maxHeaderCount` | 100 | Header fields per request (431); HTTP/1 only (HTTP/2 and HTTP/3 bound the decoded header list by size instead, see `maxHeaderSize`) |
| `maxBodySize` | 8 MiB | Request body (413); per stream on HTTP/2 and HTTP/3; also caps a decompressed body |
| `maxWsMessageSize` | 1 MiB | Largest inbound WebSocket message (close 1009) |
| `h2StreamWindow` | 1 MiB | HTTP/2 per-stream receive window (upload flow control) |
| `h2ConnWindow` | 1 MiB | HTTP/2 per-connection cap on total un-consumed upload buffer across streams (bounds memory regardless of stream count, like Go's `MaxUploadBufferPerConnection`). It bounds *streaming* routes directly, through flow control; a buffered route is bounded by the aggregate below |
| (buffered bodies) | `max(h2ConnWindow, maxBodySize)` | HTTP/2 cap on total *un-dispatched buffered* request-body bytes across a connection's streams, independent of the receive window: a buffered body is retained until END_STREAM and its flow-control bytes are credited on receipt (a body larger than the window must be, or it could never arrive), so the window cannot bound it. Never below `maxBodySize`, so any single upload still fits, and never below the 64 KiB protocol default receive window; the stream that crosses it is reset with REFUSED_STREAM (retryable) |
| `h3StreamWindow` | 1 MiB | HTTP/3 per-stream receive window (upload flow control) |
| `h3ConnWindow` | 4 MiB | HTTP/3 per-connection receive window (aggregate cap on buffered uploads) |

HTTP/1 has no configurable upload window, but it is bounded too: a streaming
route whose consumer acks on consume (the async `await req.read()` API, which
registers its `onBody` sink with `manualAck`) may hold at most 1 MiB
delivered-but-unacked before the loop stops reading the socket, so the rest of
the upload waits in the kernel as TCP backpressure instead of piling up in the
consumer's queue. `req.ackBody` repays that debt and resumes the read. It is the
coarse HTTP/1 analog of `h2StreamWindow` / `h3StreamWindow`.

#### Seeing the limits fire

A connection the server refuses after accepting it looks, at the client, exactly
like a network fault: the socket opens and then dies with nothing on it, which
httpx and friends report as an empty `ConnectError`. Four paths do that, and each
one keeps a counter plus one rate-limited `vortex:` line on stderr saying why:

| `acceptDrops()` field | Cause |
|-----------------------|-------|
| `cap` | `maxConnections` reached on that loop thread |
| `tls` | the TLS session could not be created (the line carries the OpenSSL reason) |
| `register` | the selector refused the accepted fd |
| `acceptSuspend` | `accept()` hit fd/memory exhaustion (EMFILE/ENFILE/ENOBUFS/ENOMEM) and the listener backed off for ~1s |

```nim
let d = srv.acceptDrops()     # also acceptDrops() with no argument
echo "refused: cap=", d.cap, " tls=", d.tls, " register=", d.register
```

The tally is process-wide and monotonic, so sample it and watch the rate. A
rising `cap` means raise `maxConnections` or add loop threads (the cap is per
thread); a rising `acceptSuspend` means raise the fd rlimit. Both are the server
shedding load on purpose, not a broken network.

### Timeouts

| Setting | Default | Purpose |
|---------|---------|---------|
| `headerTimeout` | 10 s | First byte to end of headers (slowloris); 0 disables |
| `bodyTimeout` | 30 s | Idle time during the body (re-armed on every read that carries body bytes), so an actively-transferring upload on a slow link is never cut off; only a genuine stall fires. `maxBodySize` still bounds the total. On HTTP/2 it also bounds the reverse stall: a connection whose requests have all finished while the server still owes response bytes parked on an exhausted peer send window, which no read-side or write-side timeout would otherwise cover (the zero-window slow read). 0 disables |
| `keepAliveTimeout` | 60 s | Idle time between requests; 0 disables |
| `responseTimeout` | 0 (off) | End of request to first response byte (stuck handler) |
| `writeTimeout` | 30 s | Idle time the socket may stay unwritable with output pending (slow-read client that never drains its response); re-armed on every partial write, so a response that keeps moving is never cut off; 0 disables |
| `shutdownGrace` | 10 s | Drain window on graceful shutdown |
| `shutdownHardTimeout` | `shutdownGrace` + 5 s | Upper bound on `close`/`waitFor`; a thread still inside a never-returning `blocking:` body is detached (leaked) so shutdown cannot hang |

### TLS

| Setting | Default | Purpose |
|---------|---------|---------|
| `certFile` / `keyFile` | "" | PEM cert and key (presence of any cert enables TLS) |
| `certPem` / `keyPem` | "" | In-memory PEM alternative |
| `pkcs12File` / `pkcs12` / `keyPassword` | "" | PKCS#12 bundle and passphrase |
| `minTlsVersion` | `V12` | Lowest accepted TLS version (`V12` or `V13`); 1.0/1.1 always refused; QUIC is always 1.3 |
| `maxTlsVersion` | `None` (no cap) | Highest accepted TLS version; `V12` requires `http3 = false` (QUIC cannot negotiate below 1.3) |
| `tlsCipherList` | "" | OpenSSL cipher list for TLS 1.2 ("" keeps OpenSSL's default); TCP only, no TLS 1.2 on QUIC |
| `tlsCipherSuites` | "" | OpenSSL cipher suites for TLS 1.3 ("" keeps OpenSSL's default); applies to HTTP/1.1, HTTP/2 and HTTP/3 |
| `verifyClient` | `None` | mTLS: `None` / `Optional` / `Require` client-cert policy; enforced on HTTP/1.1, HTTP/2 and HTTP/3 |
| `clientCaFile` / `clientCaPem` | "" | CA to verify client certs against (**required** when `verifyClient != None`: a config with neither is rejected at startup, since it would verify against an empty trust store) |
| `sni` | `@[]` | Per-hostname certificates (`SniCertEntry`, wildcard `*.example.com` supported); served on HTTP/1.1, HTTP/2 and HTTP/3 |
| `ocspFile` / `ocspResponse` | "" | DER OCSP response to staple (rotate at runtime via `reloadTls(ocspFile = ...)`) |
| `http3` | `true` | Serve HTTP/3 over QUIC (requires a cert; ignored without TLS) |

### Policy and identity

| Setting | Default | Purpose |
|---------|---------|---------|
| `securityHeaders` | `false` | Auto-inject the OWASP baseline (nosniff, DENY, no-referrer, + HSTS on TLS) on every response |
| `serverHeader` | "vortex" | `Server` header value; set "" to omit |
| `proxyProtocol` | `Disabled` | HAProxy PROXY header: `Disabled` / `Optional` / `Require` |
| `trustedProxies` | `@[]` | IPs/CIDRs allowed to supply a PROXY header, and whose `X-Forwarded-*` / RFC 7239 `Forwarded` headers `req.scheme` / `req.host` / `req.clientIp` will believe. Empty = a PROXY header is trusted from any direct peer (safe only if the listener isn't public), but forwarded **headers** are ignored entirely (fail-safe), so `req.clientIp` can't be spoofed without a configured proxy |
| `decompressRequest` | `false` | Decode gzip/br/zstd request bodies, bounded by `maxBodySize` |
| `compress` | `false` | gzip/brotli-compress eligible responses |

TLS renegotiation is refused on every context (`SSL_OP_NO_RENEGOTIATION`), and
there is no setting to allow it. A renegotiation is a full ECDHE key agreement
plus a server signature, run inline on the event-loop thread, for a few hundred
bytes of client effort, and OpenSSL neither counts nor rate-limits it: the
CVE-2011-1473 shape. A client that asks gets a warning-level
`no_renegotiation` alert and keeps its connection. This is a TLS 1.2 and below
mechanism; TLS 1.3 has no renegotiation (its KeyUpdate is a separate and much
cheaper thing) and QUIC is TLS 1.3 only.

The TLS listener offers ALPN `h2` and `http/1.1`. A client that advertises an
ALPN list overlapping neither is refused with a fatal `no_application_protocol`
alert (RFC 7301 3.2) rather than being handed a no-ALPN connection that it would
misframe; a client that advertises no ALPN at all still gets HTTP/1.1.

Certificates can be rotated at runtime with `server.reloadTls(certFile, keyFile)`
(TCP and h3), which validates the new material and swaps it in without dropping
connections. The same call rotates the stapled OCSP response:
`reloadTls(ocspFile = "staple.der")` (or `ocspResponse = bytes`) swaps in a
refreshed staple, `clearOcsp = true` drops it, and a bare `reloadTls()` re-reads
a configured `ocspFile` so a certbot renewal picks up a refreshed staple too.
Staple rotation applies to the default certificate (SNI and HTTP/3 do not
staple), and OpenSSL only sends a staple whose serial matches the served
certificate, so rotate the cert and its staple together. Reload from any
ordinary thread, and from two at once if that is how your renewal plumbing is
built (concurrent reloads serialise internally); not from inside a raw signal
handler, since the call takes a lock and reads files.

A rejected reload says why. `server.lastTlsReloadError` (and
`vortex.lastTlsReloadError`) returns the reason the most recent `reloadTls`
returned false, "" after one that succeeded, and the same reason goes to stderr
as a single `vortex: TLS reload failed: <reason>` line, so a deploy hook that
ignores the bool still leaves a trace in the log. Every rejection is covered:
unreadable or mismatched material, a key-only rotation against a PKCS#12
bundle, contradictory OCSP arguments, an unreadable explicit `ocspFile`, and a
per-host certificate that fails to build (which names the host).

Per-host (SNI) certificates rotate on the same call: each per-host context is
rebuilt from the material it was configured with, so per-host certificate
*files* replaced by the same renewal are picked up even though `reloadTls` names
only the default pair. The reload is all-or-nothing --
one per-host certificate that fails to build rejects it and leaves the default
certificate and every host exactly as they were, rather than half-rotating or
silently dropping a host back to the default certificate, which the client
would reject as a name mismatch. `reloadTls(sni = @[SniCertEntry(...)])`
replaces the per-host material outright, so the host set may change; it is
persisted only on success, and an empty `sni` means "keep what is configured".
One asymmetry to know about: that override reaches the TCP listener only, while
the HTTP/3 engine rebuilds its per-host contexts from *its* configured material
(a file re-read) on the same reload. Renewed per-host files therefore reach both
transports, but new in-memory per-host material supplied through `sni` reaches
TCP alone.

## Deployment recipes

### Behind a trusted proxy or load balancer

Let the proxy resolve the real client IP, then rate-limit on it. Timeouts can be
tighter since the proxy absorbs slow clients.

```nim
var cfg = initVortexConfig(
  certFile = "cert.pem", keyFile = "key.pem",
  proxyProtocol = ProxyProtocol.Require,   # demand a PROXY header from the LB
  trustedProxies = @["10.0.0.0/24"],       # your load balancer(s)
  keepAliveTimeout = 30,
  securityHeaders = true)

proc handler(req: Request, res: Response) =
  # req.remoteAddress is now the real client IP (from the PROXY header).
  if not rateLimit(req.remoteAddress, 100.0, 20):   # 100 req/s, burst 20
    res.send(Http429, "too many requests"); return
  res.send(Http200, "ok")
```

### Public edge (no proxy in front)

Rate-limit on the direct peer and enable the baseline headers. Note the
per-thread limiter caveat: for a strict global cap run one loop thread or front
the server (see [THREAT_MODEL.md](THREAT_MODEL.md) "Out of scope").

```nim
var cfg = initVortexConfig(
  certFile = "cert.pem", keyFile = "key.pem",
  headerTimeout = 5, bodyTimeout = 15, keepAliveTimeout = 15,
  maxRequestsPerSocket = 10000,
  securityHeaders = true)

proc handler(req: Request, res: Response) =
  if not rateLimit(req.remoteAddress, 50.0, 10):
    res.send(Http429, "too many requests"); return
  ...
```

### TLS best practice

```nim
var cfg = initVortexConfig(
  certFile = "cert.pem", keyFile = "key.pem",
  minTlsVersion = TlsVersion.V13,          # 1.3 only, if your clients allow it
  ocspFile = "staple.der",                 # pre-fetched; rotate via reloadTls
  sni = @[SniCertEntry(host: "api.example.com",
                       certFile: "api.pem", keyFile: "api.key")])
```

Mutual TLS (zero-trust): require and inspect a client certificate.

```nim
var cfg = initVortexConfig(
  certFile = "cert.pem", keyFile = "key.pem",
  verifyClient = ClientVerify.Require,
  clientCaFile = "client-ca.pem")

proc handler(req: Request, res: Response) =
  let subject = req.clientCertSubject()    # non-empty means a verified cert
  if subject.len == 0:
    res.send(Http403, "client certificate required"); return
  ...
```

### Browser-facing web app

Use per-response `securityHeaders()` (it includes CSP, which the auto-inject
omits), gate HSTS on `req.isSecure`, set secure cookies, check WebSocket Origin,
and redirect plaintext to HTTPS.

```nim
proc handler(req: Request, res: Response) =
  if not req.isSecure:                      # run a plaintext listener on :80
    res.redirect("https://" & req.host & req.path, permanent = true); return
  if req.isWebSocketUpgrade and
      not req.originAllowed(@["https://app.example.com"]):
    res.send(Http403, "forbidden origin"); return
  res.send(Http200, page, securityHeaders(hsts = req.isSecure) &
           @[setCookie("sid", token, maxAge = 3600)])  # Secure/HttpOnly/SameSite=Lax
```

`securityHeaders()` knobs (all with safe defaults): `hsts`, `hstsMaxAge`
(default 2 years), `hstsIncludeSubdomains`, `hstsPreload`, `frameOptions`
(`DENY`), `contentSecurityPolicy` (`default-src 'none'; frame-ancestors 'none'`),
`referrerPolicy`, `permissionsPolicy`, `noSniff`.

### JSON / API server

Keep it lean: skip the browser headers, leave response compression off (CRIME),
and only decode compressed uploads if you need to, always with a body cap.

```nim
var cfg = initVortexConfig(
  certFile = "cert.pem", keyFile = "key.pem",
  decompressRequest = true,     # needs -d:httpGzip / -d:httpBrotli / -d:httpZstd
  maxBodySize = 4 * 1024 * 1024)  # caps the DECODED size too (bomb defense)
```

## Rate limiting

`rateLimit(key, ratePerSec, burst): bool` is a per-client token bucket. Call it
at the top of the handler, on the loop thread, **before any `req.blocking:`**
(the bucket state is thread-local and not visible from a worker). Key it on the
real client IP: `req.remoteAddress` when you use PROXY protocol from a trusted
proxy, otherwise validate `req.forwardedFor()` yourself, or the direct peer if
there is no proxy. It returns `false` (deny, reply 429) when over budget; passing
`ratePerSec <= 0` or `burst <= 0` disables it. Buckets are pruned when idle, so
memory stays bounded. Remember the per-loop-thread caveat above for strict global
limits.

## Verify your deployment

Mirror what CI does against your running server: an OWASP ZAP baseline scan (it
flags missing security headers) and a `testssl.sh` scan (protocols, ciphers,
known TLS vulnerabilities). See `conformance/zap` and `conformance/testssl` for
the exact invocations.
