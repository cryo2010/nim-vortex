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
| `maxConnections` | 65536 | Live connections per loop thread; excess is accepted then dropped |
| `maxConcurrentStreams` | 256 | Open HTTP/2 and HTTP/3 streams per connection |
| `maxResetStreams` | 512 | HTTP/2 peer resets before GOAWAY (rapid reset); 0 disables |
| `maxControlFrames` | 1000 | HTTP/2 PING/SETTINGS/PRIORITY between stream progress; 0 disables |
| `maxRequestsPerSocket` | 0 (off) | HTTP/1 keep-alive requests before the connection is closed |
| `maxHeaderSize` | 16 KiB | Request line + headers (431); also caps HPACK decoded size |
| `maxHeaderCount` | 100 | Header fields per request (400) |
| `maxBodySize` | 8 MiB | Request body (413); per stream on HTTP/2 and HTTP/3; also caps a decompressed body |
| `maxWsMessageSize` | 1 MiB | Largest inbound WebSocket message (close 1009) |
| `h2StreamWindow` | 1 MiB | HTTP/2 per-stream receive window (upload flow control) |
| `h2ConnWindow` | 1 MiB | HTTP/2 per-connection cap on total un-consumed upload buffer across streams (bounds memory regardless of stream count, like Go's `MaxUploadBufferPerConnection`) |
| `h3StreamWindow` | 1 MiB | HTTP/3 per-stream receive window (upload flow control) |
| `h3ConnWindow` | 4 MiB | HTTP/3 per-connection receive window (aggregate cap on buffered uploads) |

### Timeouts

| Setting | Default | Purpose |
|---------|---------|---------|
| `headerTimeout` | 10 s | First byte to end of headers (slowloris); 0 disables |
| `bodyTimeout` | 30 s | Idle time during the body (re-armed on every read that carries body bytes), so an actively-transferring upload on a slow link is never cut off; only a genuine stall fires. `maxBodySize` still bounds the total. 0 disables |
| `keepAliveTimeout` | 60 s | Idle time between requests; 0 disables |
| `responseTimeout` | 0 (off) | End of request to first response byte (stuck handler) |
| `shutdownGrace` | 10 s | Drain window on graceful shutdown |

### TLS

| Setting | Default | Purpose |
|---------|---------|---------|
| `certFile` / `keyFile` | "" | PEM cert and key (presence of any cert enables TLS) |
| `certPem` / `keyPem` | "" | In-memory PEM alternative |
| `pkcs12File` / `pkcs12` / `keyPassword` | "" | PKCS#12 bundle and passphrase |
| `minTlsVersion` | `V12` | Lowest accepted TLS version (`V12` or `V13`); 1.0/1.1 always refused; QUIC is always 1.3 |
| `maxTlsVersion` | `None` (no cap) | Highest accepted TLS version |
| `tlsCipherList` | "" | OpenSSL cipher list for TLS 1.2 ("" keeps OpenSSL's default) |
| `tlsCipherSuites` | "" | OpenSSL cipher suites for TLS 1.3 ("" keeps OpenSSL's default) |
| `verifyClient` | `None` | mTLS: `None` / `Optional` / `Require` client-cert policy |
| `clientCaFile` / `clientCaPem` | "" | CA to verify client certs against (needed when `verifyClient != None`) |
| `sni` | `@[]` | Per-hostname certificates (`SniCertEntry`, wildcard `*.example.com` supported) |
| `ocspFile` / `ocspResponse` | "" | DER OCSP response to staple (static; rotate yourself) |
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

Certificates can be rotated at runtime with `server.reloadTls(certFile, keyFile)`
(TCP and h3), which validates the new material and swaps it in without dropping
connections.

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
  ocspFile = "staple.der",                 # pre-fetched; refresh on a schedule
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
