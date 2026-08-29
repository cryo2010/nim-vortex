## The protocol-independent request handle. A `Request` is four words:
## a pointer to the owning loop's core state, the connection's fd, a
## generation counter, and (for HTTP/2) a stream id. Responding through a
## stale handle (connection closed/recycled meanwhile) is a safe no-op.
##
## Handlers may respond inside the handler call (fast path) or later;
## HTTP/1 pauses request parsing until a response is produced; HTTP/2
## streams are independent.

import std/[httpcore, strutils, uri, tables, json, options, typetraits, macros, times]
import ./connection
import ./proxyprotocol   # isTrustedProxy for forwarded-header resolution
import ./multipart
export multipart          # MultipartForm/MultipartFile + field/file accessors
import ./blockingguard
import ./conditional
export blockingguard
import ./signing
export signing        # CookieMac + sign/verify for signed cookies (and app use)   # prepArg/assertBlockingType for the blocking macros, and
                       # the re-exported std/isolation (isolate/extract/Isolated)

export PathParams, ResponseHeaders
import ./workerpool
import ./http1/parser as h1parser
import ./http1/codec as h1codec
import ./http2/codec as h2codec
import ./websocket/codec as wscodec
export wscodec
when not defined(plainHttp):
  import ./http3/ngtcp2/backend as h3codec   # HTTP/3 over ngtcp2 + nghttp3
  import ./transport/tls as tlscodec
when defined(httpGzip):
  import ./gzip
when defined(httpBrotli):
  import ./brotli
when defined(httpZstd):
  import ./zstd

type
  Request* = object
    core*: ptr LoopCore
    fd*: int32
    gen*: uint32
    stream*: uint32           ## HTTP/2 stream id, 0 for HTTP/1
    snap*: ptr ReqSnapshot    ## non-nil on a blocking: worker: read this
                              ## value snapshot instead of live loop memory
                              ## (IMP2 / C3). nil on the loop thread.

  Response* = object
    ## The write half of a request/response pair: the same four handle
    ## words as Request, carrying only the capability to send. Copying
    ## it anywhere (workers, async callbacks) is free; sending through a
    ## dead connection is a safe no-op.
    core*: ptr LoopCore
    fd*: int32
    gen*: uint32
    stream*: uint32

  RequestHandler* = proc (req: Request, res: Response) {.gcsafe.}

  RequestHeaders* = object
    ## A read-only, case-insensitive view of a request's headers, mirroring the
    ## `res.headers[name]` shape. Just a handle: `[]` looks up on demand over the
    ## zero-copy parser slices, so it allocates nothing.
    req: Request

  Cookies* = object
    ## A read-only view of a request's cookies, mirroring the `req.headers[name]`
    ## shape: `req.cookies["sid"]`. Just a handle; parses the Cookie header(s) on
    ## demand.
    req: Request

proc response*(req: Request): Response =
  ## The Response paired with a Request. Dispatch hands handlers both;
  ## this exists for code that stored only the read half.
  Response(core: req.core, fd: req.fd, gen: req.gen, stream: req.stream)

proc isAlive*(req: Request): bool =
  if req.snap != nil: return true    # pinned for the blocking body's duration
  if req.fd < 0:
    when not defined(plainHttp):
      let h3c = h3ConnOf(req.core, req.fd, req.gen)
      return h3c != nil and h3StreamAlive(h3c, uint64(req.stream))
    else:
      return false
  let c = conn(req.core, req.fd, req.gen)
  if c == nil: return false
  if req.stream == 0: true
  else: h2StreamAlive(c, req.stream)

proc responded*(res: Response): bool =
  ## True once a response has been sent (or a streamed response started) for this
  ## request, on any protocol. Used by the async `req.stream` sugar to auto-ack
  ## with 200 only when the handler hasn't answered itself. A dead connection
  ## reads as `true` (nothing left to answer).
  if res.fd < 0:
    when not defined(plainHttp):
      let h3c = h3ConnOf(res.core, res.fd, res.gen)
      if h3c != nil:
        let st = h3StreamPtr(h3c, uint64(res.stream))
        if st != nil: return st.responded
    return true
  let c = conn(res.core, res.fd, res.gen)
  if c == nil: return true
  if res.stream != 0:
    let st = h2Stream(c, res.stream)
    return st == nil or st.responded
  c.responded

when not defined(plainHttp):
  template withH3(req: Request, st, body: untyped) =
    let h3c = h3ConnOf(req.core, req.fd, req.gen)
    if h3c != nil:
      let st = h3StreamPtr(h3c, uint64(req.stream))
      if st != nil:
        body

  proc h3FieldOf(req: Request, name: string): string =
    withH3(req, st):
      for (n, v) in st.headers:
        if n == name: return v

template withConn(req: Request, c, body: untyped) =
  let c = conn(req.core, req.fd, req.gen)
  if c != nil:
    body

proc lowerA(c: char): char {.inline.} =
  if c in 'A'..'Z': char(uint8(c) or 0x20'u8) else: c

var cachedThreadId {.threadvar.}: int

proc currentThreadId(): int {.inline.} =
  ## getThreadId() is a syscall on Linux; caching it matters on the
  ## per-request fast path.
  if cachedThreadId == 0:
    cachedThreadId = getThreadId()
  cachedThreadId

proc headers*(res: Response): var ResponseHeaders =
  ## Response headers to send with the eventual `res.send`. Set them from
  ## middleware or a handler, e.g. `res.headers["X-Request-Id"] = id` or
  ## `res.headers.add("Set-Cookie", c)`; the `send` call's own `headers`
  ## argument overrides these per name. Buffered `send` only (not `sendHead`
  ## streaming). Loop-thread only: do not touch from inside `req.blocking`
  ## (pass headers to `send` there instead).
  assert currentThreadId() == res.core.threadId,
    "res.headers is loop-thread only; set headers before req.blocking, or " &
    "pass them to send() from the worker"
  res.core.respHeaders.mgetOrPut((res.fd, res.gen, res.stream), ResponseHeaders())

# --- accessors --------------------------------------------------------------

proc parseMethodStr(s: string): HttpMethod =
  case s
  of "GET": HttpGet
  of "POST": HttpPost
  of "PUT": HttpPut
  of "HEAD": HttpHead
  of "DELETE": HttpDelete
  of "PATCH": HttpPatch
  of "OPTIONS": HttpOptions
  of "TRACE": HttpTrace
  of "CONNECT": HttpConnect
  else: HttpGet

proc h2Field(c: ptr Connection, sid: uint32, name: string): string =
  let st = h2Stream(c, sid)
  if st == nil: return ""
  for (n, v) in st.headers:
    if n == name: return v

proc `method`*(req: Request): HttpMethod =
  ## The request method. `method` is a Nim keyword, but keywords are
  ## valid after a dot, so plain `req.method` works at call sites; only
  ## this declaration (and UFCS/standalone uses) needs backticks.
  result = HttpGet
  if req.snap != nil: return req.snap.httpMethod
  if req.fd < 0:
    when not defined(plainHttp):
      result = parseMethodStr(h3FieldOf(req, ":method"))
    return
  withConn(req, c):
    if req.stream != 0:
      result = parseMethodStr(h2Field(c, req.stream, ":method"))
    else:
      result = c.parser.httpMethod

proc path*(req: Request): string =
  if req.snap != nil: return req.snap.target
  if req.fd < 0:
    when not defined(plainHttp):
      result = h3FieldOf(req, ":path")
    return
  withConn(req, c):
    if req.stream != 0:
      result = h2Field(c, req.stream, ":path")
    else:
      result = c.rbuf.substr(int(c.parser.pathStart),
                             int(c.parser.pathStart + c.parser.pathLen) - 1)

iterator items*(h: RequestHeaders): (string, string) =
  ## Yields (name, value) pairs (`for (n, v) in req.headers`). HTTP/2 and /3
  ## names are lowercase on the wire; pseudo-headers are skipped.
  let req = h.req
  if req.snap != nil:
    for (n, v) in req.snap.headers:
      if n.len > 0 and n[0] != ':': yield (n, v)
  else:
    if req.fd < 0:
      when not defined(plainHttp):
        let h3c = h3ConnOf(req.core, req.fd, req.gen)
        if h3c != nil:
          let st = h3StreamPtr(h3c, uint64(req.stream))
          if st != nil:
            for (n, v) in st.headers:
              if n.len > 0 and n[0] != ':':
                yield (n, v)
    let c = if req.fd < 0: nil else: conn(req.core, req.fd, req.gen)
    if c != nil:
      if req.stream != 0:
        let st = h2Stream(c, req.stream)
        if st != nil:
          for (n, v) in st.headers:
            if n.len > 0 and n[0] != ':':
              yield (n, v)
      else:
        for hs in c.parser.headers:
          yield (c.rbuf.substr(int(hs.nameStart),
                               int(hs.nameStart + hs.nameLen) - 1),
                 c.rbuf.substr(int(hs.valStart),
                               int(hs.valStart + hs.valLen) - 1))

proc header*(req: Request, name: string): string =
  ## Case-insensitive single-header lookup; "" when absent.
  if req.snap != nil:
    let want = name.toLowerAscii
    for (n, v) in req.snap.headers:
      if n.toLowerAscii == want: return v
    return ""
  if req.fd < 0:
    when not defined(plainHttp):
      result = h3FieldOf(req, name.toLowerAscii)
    return
  withConn(req, c):
    if req.stream != 0:
      return h2Field(c, req.stream, name.toLowerAscii)
    for h in c.parser.headers:
      if int(h.nameLen) == name.len:
        var match = true
        for i in 0 ..< name.len:
          if lowerA(c.rbuf[int(h.nameStart) + i]) != lowerA(name[i]):
            match = false
            break
        if match:
          return c.rbuf.substr(int(h.valStart),
                               int(h.valStart + h.valLen) - 1)

proc headers*(req: Request): RequestHeaders {.inline.} =
  ## A read-only, case-insensitive view of the request headers, matching the
  ## `res.headers[name]` shape: `req.headers["Content-Type"]`,
  ## `"authorization" in req.headers`, `for (n, v) in req.headers`.
  RequestHeaders(req: req)

proc `[]`*(h: RequestHeaders, name: string): string =
  ## Case-insensitive lookup; "" when absent (same zero-copy path as `header`).
  h.req.header(name)

proc contains*(h: RequestHeaders, name: string): bool =
  ## True if the header is present (case-insensitive), even with an empty value.
  ## Scans in place (byte-compare on HTTP/1, name compare on h2/h3): no
  ## per-header allocation, unlike iterating the pairs.
  let req = h.req
  template scanSeq(hs: untyped): bool =
    var found = false
    for pair in hs:
      if pair[0].len > 0 and pair[0][0] != ':' and cmpIgnoreCase(pair[0], name) == 0:
        found = true; break
    found
  if req.snap != nil:
    return scanSeq(req.snap.headers)
  if req.fd < 0:
    when not defined(plainHttp):
      let h3c = h3ConnOf(req.core, req.fd, req.gen)
      if h3c != nil:
        let st = h3StreamPtr(h3c, uint64(req.stream))
        if st != nil: return scanSeq(st.headers)
    return false
  let c = conn(req.core, req.fd, req.gen)
  if c == nil: return false
  if req.stream != 0:
    let st = h2Stream(c, req.stream)
    return st != nil and scanSeq(st.headers)
  for hs in c.parser.headers:                 # HTTP/1: compare against the read buffer
    if int(hs.nameLen) == name.len:
      var match = true
      for i in 0 ..< name.len:
        if lowerA(c.rbuf[int(hs.nameStart) + i]) != lowerA(name[i]):
          match = false; break
      if match: return true
  false

proc body*(req: Request): string =
  if req.snap != nil: return req.snap.body
  if req.fd < 0:
    when not defined(plainHttp):
      withH3(req, st):
        result = st.body
    return
  withConn(req, c):
    if req.stream != 0:
      let st = h2Stream(c, req.stream)
      if st != nil: result = st.body
    elif c.bodyDecodedSet:
      result = c.bodyDecoded          # decompressed request body (see decodeRequestBody)
    elif c.parser.chunked:
      result = c.chunkBody
    elif c.parser.bodyLen > 0:
      result = c.rbuf.substr(c.parser.bodyStart,
                             c.parser.bodyStart + c.parser.bodyLen - 1)

proc remoteAddress*(req: Request): string =
  ## The peer IP of the connection, captured at accept (access logging, rate
  ## limiting, audit). This is the *direct* peer: behind a reverse proxy it is
  ## the proxy's IP, so recover the origin client from a trusted X-Forwarded-For
  ## policy (see forwardedFor), never from an untrusted header alone. When the
  ## listener has `settings.proxyProtocol` enabled and the connection came from a
  ## trusted proxy, this is already the real client IP from the PROXY header.
  ## Empty for a stale handle.
  if req.snap != nil: return req.snap.remoteAddr
  if req.fd < 0:
    when not defined(plainHttp):
      let h3c = h3ConnOf(req.core, req.fd, req.gen)
      if h3c != nil: return h3c.remoteAddr
    return ""
  let c = conn(req.core, req.fd, req.gen)
  if c != nil: c.remoteAddr else: ""

proc clientCertSubject*(req: Request): string =
  ## The client certificate's subject DN for an mTLS connection, or "" if none
  ## was presented. Needs `settings.verifyClient = ClientVerify.Optional`/`ClientVerify.Require`; in
  ## those modes OpenSSL has already validated a presented cert during the
  ## handshake, so a non-empty result is a trusted client cert. Always "" over
  ## plaintext (or a -d:plainHttp build).
  if req.snap != nil: return req.snap.clientSubject
  when not defined(plainHttp):
    if req.fd < 0:
      let h3c = h3ConnOf(req.core, req.fd, req.gen)
      if h3c != nil: return tlscodec.peerCertSubject(h3c.ssl)
    else:
      let c = conn(req.core, req.fd, req.gen)
      if c != nil and c.ssl != nil: return tlscodec.peerCertSubject(c.ssl)

proc forwardedFor*(req: Request): seq[string] =
  ## The X-Forwarded-For chain parsed left (origin client) to right (nearest
  ## proxy), trimmed; empty if the header is absent. A client can forge this
  ## header, so trust an entry only for the hops you actually control: combine
  ## it with remoteAddress and a known-proxy policy before treating the leftmost
  ## value as the client IP.
  let xff = req.header("x-forwarded-for")
  if xff.len == 0: return @[]
  for part in xff.split(','):
    let p = part.strip
    if p.len > 0: result.add p

proc fromTrustedProxy*(req: Request): bool =
  ## True when the direct peer is in `settings.trustedProxies` (which must be
  ## non-empty). Forwarding headers (X-Forwarded-*, RFC 7239 Forwarded) are
  ## believed only from such a peer -- a request straight from a client can forge
  ## them, so with no trustedProxies configured this is always false (fail safe).
  req.core != nil and req.core.trustedProxies.len > 0 and
    isTrustedProxy(req.remoteAddress, req.core.trustedProxies)

type ForwardedElem = tuple[forr, proto, host: string]

proc parseForwarded(hdr: string): seq[ForwardedElem] =
  ## RFC 7239 Forwarded -> its elements (client-most first), each with the for /
  ## proto / host params (surrounding quotes stripped, keys lowercased).
  for elem in hdr.split(','):
    var e: ForwardedElem
    for param in elem.split(';'):
      let eq = param.find('=')
      if eq < 0: continue
      let k = param[0 ..< eq].strip.toLowerAscii
      var v = param[eq+1 .. ^1].strip
      if v.len >= 2 and v[0] == '"' and v[^1] == '"': v = v[1 ..< v.len-1]
      case k
      of "for": e.forr = v
      of "proto": e.proto = v
      of "host": e.host = v
      else: discard
    if e.forr.len > 0 or e.proto.len > 0 or e.host.len > 0: result.add e

proc fwdIp(s: string): string =
  ## Extract the bare IP from an RFC 7239 for= node (`ip`, `ip:port`,
  ## `"[v6]:port"`, `_obfuscated`); returns the token unchanged if it isn't one.
  var v = s.strip(chars = {'"'})
  if v.startsWith("["):
    let rb = v.find(']')
    return (if rb > 1: v[1 ..< rb] else: v)
  if v.count(':') == 1: return v[0 ..< v.find(':')]   # ipv4:port
  v

proc forwardedProto*(req: Request): string =
  ## The client-facing scheme ("https"/"http") the outermost trusted proxy saw,
  ## from RFC 7239 Forwarded (proto=) or X-Forwarded-Proto; "" when not behind a
  ## trusted proxy or unset. Prefer `req.scheme` / `req.isSecure`, which fold it
  ## in.
  if not req.fromTrustedProxy: return ""
  let fwd = parseForwarded(req.header("forwarded"))
  if fwd.len > 0 and fwd[0].proto.len > 0: return fwd[0].proto.toLowerAscii
  let xfp = req.header("x-forwarded-proto")
  if xfp.len > 0: return xfp.split(',')[0].strip.toLowerAscii

proc forwardedHost*(req: Request): string =
  ## The Host the client sent to a trusted proxy, from RFC 7239 Forwarded
  ## (host=) or X-Forwarded-Host; "" when not behind a trusted proxy or unset.
  ## Folded into `req.host`.
  if not req.fromTrustedProxy: return ""
  let fwd = parseForwarded(req.header("forwarded"))
  if fwd.len > 0 and fwd[0].host.len > 0: return fwd[0].host
  let xfh = req.header("x-forwarded-host")
  if xfh.len > 0: return xfh.split(',')[0].strip

proc clientIp*(req: Request): string =
  ## The origin client's IP behind a trusted proxy chain. Walks the forwarded
  ## chain (RFC 7239 for= elements, else X-Forwarded-For) from the nearest proxy
  ## outward and returns the first address that is NOT itself a trusted proxy --
  ## what the outermost trusted proxy actually saw. Only trusted hops are peeled,
  ## so a client-forged prefix can't move the result. Falls back to
  ## `remoteAddress` when not behind a trusted proxy.
  if not req.fromTrustedProxy: return req.remoteAddress
  var chain: seq[string]
  let fwd = parseForwarded(req.header("forwarded"))
  if fwd.len > 0:
    for e in fwd:
      if e.forr.len > 0: chain.add fwdIp(e.forr)   # left = client-most
  else:
    chain = req.forwardedFor
  for i in countdown(chain.high, 0):
    if not isTrustedProxy(chain[i], req.core.trustedProxies): return chain[i]
  if chain.len > 0: return chain[0]
  req.remoteAddress

proc isSecure*(req: Request): bool =
  ## True if the request arrived over TLS (HTTPS, or HTTP/2 over TLS) or QUIC
  ## (HTTP/3 is always encrypted). Use it to gate Secure cookies, HSTS, and a
  ## plaintext->HTTPS redirect. Behind a trusted proxy it reflects the forwarded
  ## proto (X-Forwarded-Proto / Forwarded), so termination at the proxy is seen
  ## as secure.
  let fp = req.forwardedProto
  if fp.len > 0: return fp == "https"
  if req.snap != nil: return req.snap.secure
  if req.fd < 0: return true            # HTTP/3 over QUIC is always TLS
  let c = conn(req.core, req.fd, req.gen)
  c != nil and c.ssl != nil

proc scheme*(req: Request): string =
  ## "https" or "http" for the original client request -- the trusted proxy's
  ## forwarded proto if present, else the connection's own scheme. Use it to
  ## build absolute URLs / redirects correctly behind a TLS terminator.
  if req.isSecure: "https" else: "http"

proc securityHeaders*(hsts = false, hstsMaxAge = 63072000,
                      hstsIncludeSubdomains = true, hstsPreload = false,
                      frameOptions = "DENY",
                      contentSecurityPolicy =
                        "default-src 'none'; frame-ancestors 'none'",
                      referrerPolicy = "no-referrer",
                      permissionsPolicy = "",
                      noSniff = true): seq[(string, string)] =
  ## OWASP Secure Headers baseline as a header list to pass to `res.send`
  ## (e.g. `res.send(Http200, body, securityHeaders(hsts = req.isSecure))`).
  ## Defaults suit an API/JSON endpoint (a locked-down CSP);
  ## for an HTML page pass an appropriate `contentSecurityPolicy` and
  ## `frameOptions`. Enable `hsts` only over TLS -- Strict-Transport-Security on
  ## plain HTTP is ignored and misleading, so gate it on `req.isSecure`.
  if noSniff: result.add ("X-Content-Type-Options", "nosniff")
  if frameOptions.len > 0: result.add ("X-Frame-Options", frameOptions)
  if contentSecurityPolicy.len > 0:
    result.add ("Content-Security-Policy", contentSecurityPolicy)
  if referrerPolicy.len > 0: result.add ("Referrer-Policy", referrerPolicy)
  if permissionsPolicy.len > 0:
    result.add ("Permissions-Policy", permissionsPolicy)
  if hsts:
    var v = "max-age=" & $hstsMaxAge
    if hstsIncludeSubdomains: v.add "; includeSubDomains"
    if hstsPreload: v.add "; preload"
    result.add ("Strict-Transport-Security", v)

proc origin*(req: Request): string =
  ## The request's Origin header ("" if absent). For a WebSocket upgrade this is
  ## the site that initiated the connection; check it to defend cross-site
  ## WebSocket hijacking (see originAllowed).
  req.header("origin")

proc originAllowed*(req: Request, allowed: openArray[string],
                    allowMissing = false): bool =
  ## True if the request's Origin exactly matches an entry in `allowed`. Gate a
  ## WebSocket upgrade on this (OWASP WebSocket Security): a cross-site page
  ## sends the attacker's Origin, which won't be in your allowlist. `allowMissing`
  ## (default false = strict) decides requests with no Origin -- browsers always
  ## send it for WebSockets, so a missing Origin is a non-browser client; set it
  ## true to permit native/non-browser clients.
  ##
  ##   if req.isWebSocketUpgrade:
  ##     if not req.originAllowed(@["https://app.example.com"]):
  ##       res.send(Http403, "forbidden origin"); return
  ##     let ws = req.acceptWebSocket()
  let o = req.header("origin")
  if o.len == 0: return allowMissing
  for a in allowed:
    if a == o: return true
  false

proc host*(req: Request): string =
  ## The request's host: behind a trusted proxy the forwarded host
  ## (X-Forwarded-Host / RFC 7239 Forwarded host=); otherwise the :authority
  ## pseudo-header for HTTP/2 and HTTP/3, or the Host header for HTTP/1.1 ("" if
  ## absent). Use it to build an absolute URL, e.g. a plaintext -> HTTPS redirect.
  let fwd = req.forwardedHost
  if fwd.len > 0: return fwd
  result = req.header(":authority")
  if result.len == 0: result = req.header("host")

proc contentLength*(req: Request): int =
  if req.snap != nil: return req.snap.body.len
  if req.fd < 0:
    when not defined(plainHttp):
      withH3(req, st):
        result = st.body.len
    return
  withConn(req, c):
    if req.stream != 0:
      let st = h2Stream(c, req.stream)
      if st != nil: result = st.body.len
    else:
      result = if c.parser.chunked: c.chunkBody.len else: c.parser.bodyLen

template lazyUrl(store: untyped, target: string): Uri =
  if not store.urlCached:
    store.cachedUrl = parseUri(target)
    store.urlCached = true
  store.cachedUrl

template lazyQuery(store: untyped, rawQuery: string):
    Table[string, string] =
  if not store.queryCached:
    store.cachedQuery.clear()          # storage is reused across requests
    for (key, value) in decodeQuery(rawQuery):
      store.cachedQuery[key] = value   # duplicate keys: last one wins
    store.queryCached = true
  store.cachedQuery

proc url*(req: Request): Uri =
  ## The request target parsed as a Uri (so `req.url.path` excludes the
  ## query string). Parsed lazily on first access, cached per request.
  if req.snap != nil: return parseUri(req.snap.target)  # no live cache to reuse
  if req.fd < 0:
    when not defined(plainHttp):
      withH3(req, st):
        result = lazyUrl(st, h3FieldOf(req, ":path"))
    return
  withConn(req, c):
    if req.stream != 0:
      let st = h2Stream(c, req.stream)
      if st != nil:
        result = lazyUrl(st, h2Field(c, req.stream, ":path"))
    else:
      result = lazyUrl(c, c.rbuf.substr(int(c.parser.pathStart),
                       int(c.parser.pathStart + c.parser.pathLen) - 1))

proc query*(req: Request): Table[string, string] =
  ## Decoded query parameters, built lazily on first access and cached
  ## per request. Duplicate keys keep the last value; use
  ## `decodeQuery(req.url.query)` directly if you need every occurrence.
  if req.snap != nil:
    for (k, v) in decodeQuery(parseUri(req.snap.target).query): result[k] = v
    return
  if req.fd < 0:
    when not defined(plainHttp):
      withH3(req, st):
        result = lazyQuery(st, lazyUrl(st, h3FieldOf(req, ":path")).query)
    return
  withConn(req, c):
    if req.stream != 0:
      let st = h2Stream(c, req.stream)
      if st != nil:
        result = lazyQuery(st,
          lazyUrl(st, h2Field(c, req.stream, ":path")).query)
    else:
      result = lazyQuery(c, lazyUrl(c,
        c.rbuf.substr(int(c.parser.pathStart),
                      int(c.parser.pathStart + c.parser.pathLen) - 1)).query)

template lazyJson(store: untyped, raw: string): JsonNode =
  if not store.jsonCached:
    store.cachedJson = if raw.len == 0: newJObject() else: parseJson(raw)
    store.jsonCached = true
  store.cachedJson

proc json*(req: Request): JsonNode =
  ## The request body parsed as JSON, cached per request so repeated field
  ## access (`req.json["a"]`, `req.json["b"]`) parses once. An empty body is
  ## treated as `{}`. Raises `JsonParsingError` on a malformed body (catch it
  ## to answer 400; a future middleware can do this globally). Call it on the
  ## loop thread, not inside `blocking:`.
  if req.snap != nil:
    return (if req.snap.body.len == 0: newJObject() else: parseJson(req.snap.body))
  let raw = req.body
  if req.fd < 0:
    when not defined(plainHttp):
      withH3(req, st):
        result = lazyJson(st, raw)
    return
  withConn(req, c):
    if req.stream != 0:
      let st = h2Stream(c, req.stream)
      if st != nil: result = lazyJson(st, raw)
    else:
      result = lazyJson(c, raw)

proc mediaType*(req: Request): string =
  ## The request's Content-Type media type, lowercased and without parameters
  ## (`"application/json"` from `"application/json; charset=utf-8"`); "" when the
  ## header is absent.
  let ct = req.header("content-type")
  let semi = ct.find(';')
  result = (if semi >= 0: ct[0 ..< semi] else: ct).strip.toLowerAscii

proc form*(req: Request): FormFields =
  ## The submitted form fields, from an `application/x-www-form-urlencoded` body
  ## OR the text parts of a `multipart/form-data` body (percent-decoded, `+` is a
  ## space for urlencoded). Indexed like `req.headers`: `req.form["email"]` is
  ## the first value ("" if absent), `"email" in req.form` tests presence,
  ## `for (k, v) in req.form` iterates all (a repeated field keeps every value;
  ## `[]` returns the first). Empty for any other content type. Uploaded files
  ## are on `req.files`. Reads `req.body` (bounded by `maxBodySize`) and parses on
  ## each call, so bind it once (`let f = req.form`) rather than indexing
  ## repeatedly; loop thread only (not inside `blocking:`).
  case req.mediaType
  of "application/x-www-form-urlencoded":
    for (k, v) in decodeQuery(req.body): result.s.add (k, v)
  of "multipart/form-data":
    let boundary = multipartBoundary(req.header("content-type"))
    if boundary.len > 0: result.s = parseMultipart(req.body, boundary).fields
  else: discard

proc files*(req: Request): UploadedFiles =
  ## The uploaded files of a `multipart/form-data` body, keyed by the form field
  ## name (the `<input name>`). Indexed like `req.headers`, except a missing key
  ## raises (there is no empty file): `req.files["avatar"]` is the first file for
  ## that field, `"avatar" in req.files` tests presence, `for f in req.files`
  ## iterates all. Each is an `UploadedFile` (`.filename`, `.contentType`,
  ## `.content`). Empty for any other content type. Buffered -- reads `req.body`
  ## (bounded by `maxBodySize`); for large uploads stream via `req.onBody` /
  ## `req.read` and parse incrementally instead. Loop thread only.
  if req.mediaType == "multipart/form-data":
    let boundary = multipartBoundary(req.header("content-type"))
    if boundary.len > 0: result.s = parseMultipart(req.body, boundary).files

# --- content negotiation (Accept / Accept-Language / Accept-Charset) ---------

proc parseAcceptHeader(h: string): seq[tuple[tok: string, q: float]] =
  ## Split an Accept-style header into (token, q) pairs, lowercased. A missing
  ## q defaults to 1.0; an unparseable q means 0.0 (the entry is not acceptable).
  for part in h.split(','):
    let s = part.strip
    if s.len == 0: continue
    var tok = s
    var q = 1.0
    let semi = s.find(';')
    if semi >= 0:
      tok = s[0 ..< semi].strip
      for p in s[semi + 1 .. ^1].split(';'):     # parameters after the token
        let eq = p.find('=')
        if eq > 0 and p[0 ..< eq].strip.toLowerAscii == "q":
          try: q = parseFloat(p[eq + 1 .. ^1].strip)
          except ValueError: q = 0.0
    result.add (tok.toLowerAscii, q)

proc negotiate(header: string, offered: openArray[string],
               match: proc(entry, offered: string): int {.nimcall, gcsafe.}): string =
  ## Pick the value from `offered` (in server-preference order) that the client
  ## most prefers. The most specific matching range determines an offer's q; the
  ## highest q wins, ties broken by offer order. No header -> the first offer.
  if header.strip.len == 0:
    return (if offered.len > 0: offered[0] else: "")
  let entries = parseAcceptHeader(header)
  var bestQ = 0.0
  for off in offered:
    let o = off.toLowerAscii
    var q = 0.0
    var spec = -1
    for e in entries:
      let s = match(e.tok, o)
      if s > spec:                               # most specific match sets q
        spec = s
        q = e.q
    if spec >= 0 and q > bestQ:
      bestQ = q
      result = off

proc matchMedia(entry, offered: string): int {.nimcall, gcsafe.} =
  ## exact "type/subtype" = 2, "type/*" = 1, "*/*" = 0, no match = -1.
  if entry == offered: return 2
  if entry == "*/*": return 0
  let slash = entry.find('/')
  if slash > 0 and entry[slash + 1 .. ^1] == "*":
    let oslash = offered.find('/')
    if oslash > 0 and offered[0 ..< oslash] == entry[0 ..< slash]: return 1
  -1

proc matchLang(entry, offered: string): int {.nimcall, gcsafe.} =
  ## exact = 2, prefix range ("en" matches "en-US") = 1, "*" = 0, none = -1.
  if entry == "*": return 0
  if entry == offered: return 2
  if offered.startsWith(entry & "-"): return 1
  -1

proc matchCharset(entry, offered: string): int {.nimcall, gcsafe.} =
  ## exact = 1, "*" = 0, none = -1.
  if entry == "*": return 0
  if entry == offered: return 1
  -1

proc accepts*(req: Request, offered: varargs[string]): string =
  ## The media type from `offered` (server-preference order) the client accepts
  ## best per the Accept header, honoring q-values and `type/*` / `*/*` wildcards
  ## (`req.accepts("application/json", "text/html")`). "" if none is acceptable;
  ## the first offer if there is no Accept header.
  negotiate(req.header("accept"), offered, matchMedia)

proc acceptsLanguage*(req: Request, offered: varargs[string]): string =
  ## The language tag from `offered` the client prefers per Accept-Language; a
  ## range like `en` matches an offered `en-US`. "" if none; first offer if no
  ## header.
  negotiate(req.header("accept-language"), offered, matchLang)

proc acceptsCharset*(req: Request, offered: varargs[string]): string =
  ## The charset from `offered` the client prefers per Accept-Charset. "" if
  ## none; first offer if no header.
  negotiate(req.header("accept-charset"), offered, matchCharset)

proc param*(params: PathParams, name: string): string =
  ## Value of a path parameter; "" when absent.
  for (n, v) in params:
    if n == name: return v

proc setParams*(req: Request, params: sink PathParams) =
  ## Store route parameters for req.params. Called by the router on the
  ## loop thread at match time; params are computed by matching anyway,
  ## so they are stored eagerly (a move) rather than lazily.
  if req.fd < 0:
    when not defined(plainHttp):
      withH3(req, st):
        st.pathParams = params
    return
  withConn(req, c):
    if req.stream != 0:
      let st = h2Stream(c, req.stream)
      if st != nil: st.pathParams = params
    else:
      c.pathParams = params

proc params*(req: Request): PathParams =
  ## Route parameters captured by the router ("/users/:id" etc.); empty
  ## when no router matched. Valid from any thread holding the handle,
  ## same as req.body.
  if req.snap != nil: return req.snap.params
  if req.fd < 0:
    when not defined(plainHttp):
      withH3(req, st):
        result = st.pathParams
    return
  withConn(req, c):
    if req.stream != 0:
      let st = h2Stream(c, req.stream)
      if st != nil: result = st.pathParams
    else:
      result = c.pathParams

proc param*(req: Request, name: string): string =
  ## Single path-parameter lookup; "" when absent.
  if req.snap != nil: return req.snap.params.param(name)
  if req.fd < 0:
    when not defined(plainHttp):
      withH3(req, st):
        return st.pathParams.param(name)
    return
  withConn(req, c):
    if req.stream != 0:
      let st = h2Stream(c, req.stream)
      if st != nil: return st.pathParams.param(name)
    else:
      return c.pathParams.param(name)

proc httpVersion*(req: Request): int =
  ## 1 for HTTP/1.x, 2 for HTTP/2, 3 for HTTP/3.
  if req.fd < 0: 3
  elif req.stream != 0: 2
  else: 1

# --- responding -------------------------------------------------------------

proc withSecHeaders*(core: ptr LoopCore,
                     headers: openArray[(string, string)]): seq[(string, string)] =
  ## Merge the loop's configured OWASP security-headers baseline into `headers`,
  ## skipping any name the handler already set (case-insensitive, so the app
  ## always wins). Only called when core.secHeaders is non-empty, so the default
  ## (toggle-off) response path allocates nothing extra.
  result = @headers
  for (bn, bv) in core.secHeaders:
    var present = false
    for (an, _) in headers:
      if cmpIgnoreCase(an, bn) == 0:
        present = true
        break
    if not present: result.add (bn, bv)

proc `[]=`*(h: var ResponseHeaders, name, value: string) =
  ## Set `name` to `value`, replacing any existing value(s) for that name.
  for i in 0 ..< h.s.len:
    if cmpIgnoreCase(h.s[i][0], name) == 0:
      h.s[i] = (name, value)
      var j = i + 1                       # drop any further duplicates
      while j < h.s.len:
        if cmpIgnoreCase(h.s[j][0], name) == 0: h.s.delete(j)
        else: inc j
      return
  h.s.add (name, value)

proc `[]`*(h: ResponseHeaders, name: string): string =
  ## The first value for `name`, or "" if unset.
  for (n, v) in h.s:
    if cmpIgnoreCase(n, name) == 0: return v

proc contains*(h: ResponseHeaders, name: string): bool =
  for (n, _) in h.s:
    if cmpIgnoreCase(n, name) == 0: return true

proc add*(h: var ResponseHeaders, name, value: string) =
  ## Append `name: value` without replacing an existing one (allows duplicates,
  ## e.g. multiple Set-Cookie).
  h.s.add (name, value)

proc del*(h: var ResponseHeaders, name: string) =
  ## Remove every header named `name`.
  var i = 0
  while i < h.s.len:
    if cmpIgnoreCase(h.s[i][0], name) == 0: h.s.delete(i)
    else: inc i

proc len*(h: ResponseHeaders): int = h.s.len
proc clear*(h: var ResponseHeaders) = h.s.setLen(0)

iterator pairs*(h: ResponseHeaders): (string, string) =
  for x in h.s: yield x

proc mergedWith*(h: ResponseHeaders,
                 sendArg: openArray[(string, string)]): seq[(string, string)] =
  ## Combine pending `res.headers` with a `send` call's `headers`: the send
  ## argument wins per name (its own duplicates preserved), while pending
  ## headers whose name the send argument does not set are kept.
  for (pn, pv) in h.s:
    var overridden = false
    for (sn, _) in sendArg:
      if cmpIgnoreCase(pn, sn) == 0: overridden = true; break
    if not overridden: result.add (pn, pv)
  for pair in sendArg: result.add pair

proc headersHaveCt(h: openArray[(string, string)]): bool =
  for (n, _) in h:
    if cmpIgnoreCase(n, "content-type") == 0: return true

proc applyResponse*(core: ptr LoopCore, c: ptr Connection, stream: uint32,
                    code: int, contentType: string,
                    headers: openArray[(string, string)],
                    body: openArray[char]) =
  ## Serialize a response into the connection's write buffer using the
  ## connection's protocol. Loop thread only.
  template emit(ct: string, h: openArray[(string, string)]) =
    if stream != 0:
      h2Respond(c, code, stream, core.dateStr, core.serverHeader,
                ct, h, body, core.altSvc)
    else:
      if c.responded: return
      c.responded = true
      appendResponse(c.wbuf, HttpCode(code), core.dateStr, core.serverHeader,
                     ct, body, h,
                     keepAlive = c.parser.keepAlive,
                     skipBody = c.parser.httpMethod == HttpHead,
                     announceKeepAlive = c.parser.keepAlive and
                                         c.parser.minor == 0,
                     altSvc = core.altSvc)
      if not c.parser.keepAlive:
        c.closeAfterFlush = true
  let key = (c.fd, c.gen, stream)
  if core.respHeaders.hasKey(key):
    let merged = core.respHeaders[key].mergedWith(headers)
    core.respHeaders.del key
    # a Content-Type among the merged headers wins over the (auto) contentType
    let ct = if contentType.len > 0 and headersHaveCt(merged): "" else: contentType
    if core.secHeaders.len == 0: emit(ct, merged)
    else: emit(ct, withSecHeaders(core, merged))
  elif core.secHeaders.len == 0: emit(contentType, headers)
  else: emit(contentType, withSecHeaders(core, headers))

proc h3Apply*(core: ptr LoopCore, fd: int32, gen: uint32, stream: uint32,
              code: int, contentType: string,
              headers: openArray[(string, string)],
              body: openArray[char]) =
  ## HTTP/3 counterpart of applyResponse. Loop thread only.
  when not defined(plainHttp):
    let h3c = h3ConnOf(core, fd, gen)
    if h3c != nil:
      let key = (fd, gen, stream)
      if core.respHeaders.hasKey(key):
        let merged = core.respHeaders[key].mergedWith(headers)
        core.respHeaders.del key
        let ct = if contentType.len > 0 and headersHaveCt(merged): "" else: contentType
        if core.secHeaders.len == 0:
          h3Respond(core, h3c, uint64(stream), code, ct, merged, body)
        else:
          h3Respond(core, h3c, uint64(stream), code, ct,
                    withSecHeaders(core, merged), body)
      elif core.secHeaders.len == 0:
        h3Respond(core, h3c, uint64(stream), code, contentType, headers, body)
      else:
        h3Respond(core, h3c, uint64(stream), code, contentType,
                  withSecHeaders(core, headers), body)

var workerResponded* {.threadvar.}: bool
  ## On a worker thread, set by the worker-path `send` so blockingTrampoline can
  ## tell whether the `blocking:` body produced a response. A body that finishes
  ## without one (a bug, or a misuse of the loop-thread-only streaming API from a
  ## worker) must still get a default response emitted, otherwise the outbox push
  ## that releases the connection's pin never happens and it hangs forever.

proc sendRaw(res: Response, code: HttpCode, body: openArray[char],
             contentType: string, headers: openArray[(string, string)]) =
  if currentThreadId() != res.core.threadId:
    # Worker thread: pack protocol-neutrally; the loop serializes.
    # Idempotent (R3): a blocking: body that calls send twice must not push a
    # second response. Each push is one OutMsg, and the loop decrements the
    # connection pin once per OutMsg (eventloop.processOutbox), so a duplicate
    # would both corrupt the pipeline (a spurious extra response) and
    # over-release the pin. First send wins; later ones are dropped.
    if workerResponded: return
    push(res.core.outbox, OutMsg(
      fd: res.fd, gen: res.gen, stream: res.stream, code: int32(code),
      data: packResponse(contentType, headers, body)))
    workerResponded = true
    return
  if res.fd < 0:
    h3Apply(res.core, res.fd, res.gen, res.stream, int(code), contentType,
            headers, body)
    return
  let c = conn(res.core, res.fd, res.gen)
  if c != nil:
    applyResponse(res.core, c, res.stream, int(code), contentType,
                  headers, body)

when defined(httpGzip) or defined(httpBrotli) or defined(httpZstd):
  const compressMinSize = 1400   # not worth compressing below ~one MTU

  proc compressibleType(ct: string): bool =
    if ct.len == 0: return false
    let t = ct.toLowerAscii
    t.startsWith("text/") or t.startsWith("application/json") or
      t.startsWith("application/javascript") or t.startsWith("application/xml") or
      t.startsWith("image/svg+xml") or t.startsWith("application/wasm") or
      ("+json" in t) or ("+xml" in t)

  proc hasContentEncoding(headers: openArray[(string, string)]): bool =
    for (n, _) in headers:
      if cmpIgnoreCase(n, "content-encoding") == 0: return true
    false

  proc chooseEncoding(req: Request): string =
    ## Pick the best Content-Encoding we can produce from the client's
    ## Accept-Encoding, honoring q-values (q=0 disables an encoding). On a q tie
    ## the server prefers br, then zstd, then gzip (widest support / best text
    ## ratio first). Returns "br", "zstd", "gzip", or "" (send identity).
    var brQ, zsQ, gzQ = -1.0
    for part in req.header("accept-encoding").split(','):
      let tok = part.strip
      if tok.len == 0: continue
      var name = tok
      var q = 1.0
      let semi = tok.find(';')
      if semi >= 0:
        name = tok[0 ..< semi].strip
        let low = tok.toLowerAscii
        let qpos = low.find("q=")
        if qpos >= 0:
          try: q = parseFloat(low[qpos + 2 .. ^1].strip)
          except ValueError: q = 0.0
      case name.toLowerAscii
      of "br": brQ = q
      of "zstd": zsQ = q
      of "gzip": gzQ = q
      of "*":
        if brQ < 0: brQ = q
        if zsQ < 0: zsQ = q
        if gzQ < 0: gzQ = q
      else: discard
    when not defined(httpBrotli): brQ = -1.0     # can't produce it
    when not defined(httpZstd): zsQ = -1.0
    when not defined(httpGzip): gzQ = -1.0
    if brQ > 0 and brQ >= zsQ and brQ >= gzQ: "br"
    elif zsQ > 0 and zsQ >= gzQ: "zstd"
    elif gzQ > 0: "gzip"
    else: ""

  # --- streaming compression (res.sendHead/write/finish, SSE, file streaming) --
  proc negotiateStreamEnc(res: Response, contentType: string,
                          headers: openArray[(string, string)]): string =
    ## The encoding to stream a sendHead body with, or "" for identity. Same
    ## eligibility as send() minus the size threshold (the length is unknown).
    if not res.core.compress or not compressibleType(contentType) or
        hasContentEncoding(headers):
      return ""
    chooseEncoding(Request(core: res.core, fd: res.fd, gen: res.gen,
                           stream: res.stream))

  proc makeStreamComp(enc: string): RootRef =
    ## A streaming compressor for `enc` (upcast to RootRef), or nil.
    when defined(httpBrotli):
      if enc == "br": return newBrotliStream()
    when defined(httpZstd):
      if enc == "zstd": return newZstdStream()
    when defined(httpGzip):
      if enc == "gzip": return newGzipStream()
    nil

  proc compChunk(comp: RootRef, enc: string, data: openArray[char],
                 last: bool): string =
    ## Feed a chunk to `comp` and return the bytes to emit (may be "").
    when defined(httpBrotli):
      if enc == "br": return BrotliStream(comp).compress(data, last)
    when defined(httpZstd):
      if enc == "zstd": return ZstdStream(comp).compress(data, last)
    when defined(httpGzip):
      if enc == "gzip": return GzipStream(comp).compress(data, last)
    ""

proc contentTypeOf(headers: openArray[(string, string)]): string =
  ## The Content-Type already present in `headers` ("" if none, case-insensitive).
  for (n, v) in headers:
    if cmpIgnoreCase(n, "content-type") == 0: return v

proc toHeaderPairs(j: JsonNode): seq[(string, string)] =
  ## Header pairs from a JSON object: string values pass through, others are
  ## stringified (`{"X-Count": 5}` -> `("X-Count", "5")`).
  if j == nil or j.kind != JObject: return
  for k, v in j.pairs:
    result.add (k, (if v.kind == JString: v.getStr else: $v))

proc sendBody(res: Response, code: HttpCode, body: openArray[char],
              defaultCt: string, headers: openArray[(string, string)]) =
  ## Shared send path. Content-Type is `defaultCt` unless `headers` already
  ## carries one, which then wins (never a duplicate). Compresses when eligible.
  let ctHdr = contentTypeOf(headers)
  let effCt = if ctHdr.len > 0: ctHdr else: defaultCt   # for compressibility
  let writeCt = if ctHdr.len > 0: "" else: defaultCt    # skip if headers have it
  when defined(httpGzip) or defined(httpBrotli) or defined(httpZstd):
    if res.core.compress and body.len >= compressMinSize and
        compressibleType(effCt) and not hasContentEncoding(headers):
      let enc = chooseEncoding(Request(core: res.core, fd: res.fd,
                                       gen: res.gen, stream: res.stream))
      var packed = ""
      when defined(httpBrotli):
        if enc == "br": packed = brotli(body)
      when defined(httpZstd):
        if enc == "zstd": packed = zstd(body)
      when defined(httpGzip):
        if enc == "gzip": packed = gzip(body)
      if packed.len > 0 and packed.len < body.len:
        var hh = newSeqOfCap[(string, string)](headers.len + 2)
        for h in headers: hh.add h
        hh.add ("content-encoding", enc)
        hh.add ("vary", "accept-encoding")
        sendRaw(res, code, packed, writeCt, hh)
        return
  sendRaw(res, code, body, writeCt, headers)

proc send*(res: Response, code: HttpCode, body: openArray[char],
           headers: openArray[(string, string)] = []) =
  ## Queue the response. `Content-Type` defaults to `text/plain` unless a
  ## `Content-Type` is present in `headers` (which then wins). Safe to call once
  ## per request -- from the handler, later (deferred), or from a worker inside
  ## `blocking:` -- and a no-op if the connection is gone. With
  ## `settings.compress` and a compression build, an eligible body is compressed.
  sendBody(res, code, body, "text/plain", headers)

proc send*(res: Response, code: HttpCode, json: JsonNode,
           headers: openArray[(string, string)] = []) =
  ## Send `json` stringified; `Content-Type` defaults to `application/json`
  ## (a `Content-Type` in `headers` overrides it). Convert a Table/object with
  ## `%`/`%*`: `res.send(Http200, %*{"ok": true})`, `res.send(Http200, %myTable)`.
  sendBody(res, code, $json, "application/json", headers)

proc send*(res: Response, code: HttpCode, body: openArray[char], headers: JsonNode) =
  ## As `send` above, with headers as a JSON object:
  ## `res.send(Http200, "hi", %*{"X-Trace": "abc"})`.
  send(res, code, body, toHeaderPairs(headers))

proc send*(res: Response, code: HttpCode, json: JsonNode, headers: JsonNode) =
  send(res, code, json, toHeaderPairs(headers))

proc send*(res: Response, code: HttpCode) =
  ## An empty-body response (no Content-Type).
  sendRaw(res, code, "", "", [])

proc send*(res: Response, code: int, body: openArray[char],
           headers: openArray[(string, string)] = []) =
  send(res, HttpCode(code), body, headers)

proc send*(res: Response, code: int, json: JsonNode,
           headers: openArray[(string, string)] = []) =
  send(res, HttpCode(code), json, headers)

proc send*(res: Response, code: int, body: openArray[char], headers: JsonNode) =
  send(res, HttpCode(code), body, headers)

proc send*(res: Response, code: int, json: JsonNode, headers: JsonNode) =
  send(res, HttpCode(code), json, headers)

# --- Structured bodies: send any `%`-able value or a named tuple as JSON ------
# These forward to the JsonNode overload, so `Content-Type` defaults to
# application/json (a `Content-Type` in `headers` still wins) and compression
# applies. `string` keeps its own text/plain overload and `JsonNode` its own;
# both are concrete matches, so they win over these generics.

type JsonBody* = (object | ref object | Table | OrderedTable | seq | enum | Option)
  ## Value families std/json's `%` serializes, minus `string` (which has its own
  ## text/plain overload). Anything you can `%` this way, `res.send` accepts.

proc tupleToJson[T: tuple](t: T): JsonNode   # forward decl (recursion)

proc toJsonField[V](v: V): JsonNode =
  ## Serialize a tuple field: recurse for nested tuples (std/json's `%` has no
  ## tuple case), otherwise defer to `%`.
  when V is tuple: tupleToJson(v) else: %v

proc tupleToJson[T: tuple](t: T): JsonNode =
  ## Named tuple -> JSON object. A nested anonymous tuple becomes a JSON array; a
  ## top-level anonymous tuple is rejected at the `send` overload below.
  when isNamedTuple(T):
    result = newJObject()
    for k, v in t.fieldPairs: result[k] = toJsonField(v)
  else:
    result = newJArray()
    for v in t.fields: result.add toJsonField(v)

proc send*[T: JsonBody](res: Response, code: HttpCode, body: T,
                        headers: openArray[(string, string)] = []) =
  ## Send any `%`-able value as JSON (`Content-Type` defaults to
  ## `application/json`): `res.send(Http200, user)`, `res.send(Http200, myTable)`,
  ## `res.send(Http200, @[1, 2, 3])`. Tables must be string-keyed.
  send(res, code, %body, headers)

proc send*[T: JsonBody](res: Response, code: HttpCode, body: T, headers: JsonNode) =
  send(res, code, %body, headers)

proc send*[T: JsonBody](res: Response, code: int, body: T,
                        headers: openArray[(string, string)] = []) =
  send(res, HttpCode(code), body, headers)

proc send*[T: JsonBody](res: Response, code: int, body: T, headers: JsonNode) =
  send(res, HttpCode(code), body, headers)

proc send*[T: tuple](res: Response, code: HttpCode, body: T,
                     headers: openArray[(string, string)] = []) =
  ## Send a named tuple as a JSON object: `res.send(Http200, (ok: true, n: 3))`.
  ## Anonymous tuples are rejected (their array mapping is a footgun) -- use a
  ## named tuple, an object, or `%*{...}`. Note: a tuple nested inside an object
  ## or seq you send won't compile (std/json's `%` has no tuple case); wrap it in
  ## an object or convert with `%*{...}`.
  when not isNamedTuple(T):
    {.error: "res.send accepts named tuples only (got an anonymous tuple); " &
             "use a named tuple, an object, or %*{...}.".}
  send(res, code, tupleToJson(body), headers)

proc send*[T: tuple](res: Response, code: HttpCode, body: T, headers: JsonNode) =
  send(res, code, body, toHeaderPairs(headers))

proc send*[T: tuple](res: Response, code: int, body: T,
                     headers: openArray[(string, string)] = []) =
  send(res, HttpCode(code), body, headers)

proc send*[T: tuple](res: Response, code: int, body: T, headers: JsonNode) =
  send(res, HttpCode(code), body, headers)

when defined(httpGzip) or defined(httpBrotli) or defined(httpZstd):
  proc decodeRequestBody*(req: Request, res: Response): bool =
    ## Transparently decode a gzip/br/zstd request body into `req.body` when
    ## settings.decompressRequest is set. Bounded by maxBodySize so a
    ## decompression bomb can't exhaust memory. Returns false (having sent 413
    ## for an over-cap body or 400 for a corrupt one) to skip the handler; true
    ## otherwise (including the no-op cases: feature off, no/other encoding,
    ## empty body). Called once at dispatch (loop thread) before the handler.
    if not req.core.decompressRequest: return true
    let enc = req.header("content-encoding").strip.toLowerAscii
    var isGzip, isBr, isZstd = false
    when defined(httpGzip):
      if enc == "gzip": isGzip = true
    when defined(httpBrotli):
      if enc == "br": isBr = true
    when defined(httpZstd):
      if enc == "zstd": isZstd = true
    if not (isGzip or isBr or isZstd): return true
    let raw = req.body
    if raw.len == 0: return true
    let cap = if req.core.maxDecompressedBody > 0: req.core.maxDecompressedBody
              else: 512 * 1024 * 1024      # hard ceiling when maxBodySize=0
    var r: tuple[ok: bool, tooLarge: bool, data: string]
    when defined(httpGzip):
      if isGzip: r = gunzip(raw, cap)
    when defined(httpBrotli):
      if isBr: r = brotliDecode(raw, cap)
    when defined(httpZstd):
      if isZstd: r = zstdDecode(raw, cap)
    if not r.ok:
      if r.tooLarge:
        res.send(HttpCode(413), "413 Payload Too Large")
      else:
        res.send(HttpCode(400), "400 Bad Request")
      return false
    # Store the decoded body so req.body returns it (h2/h3 overwrite st.body;
    # h1 uses a dedicated field since its body is a slice of the read buffer).
    if req.fd < 0:
      when not defined(plainHttp):
        withH3(req, st): st.body = r.data
    else:
      withConn(req, c):
        if req.stream != 0:
          let st = h2Stream(c, req.stream)
          if st != nil: st.body = r.data
        else:
          c.bodyDecoded = r.data
          c.bodyDecodedSet = true
    true

proc informational*(res: Response, code: HttpCode,
                    headers: openArray[(string, string)] = []) =
  ## Send a 1xx informational response (e.g. 103 Early Hints) NOW, ahead of the
  ## final response; the handler then continues and later calls `send`. May be
  ## called several times. Loop-thread only (a sync or async handler, before any
  ## `blocking:`); a no-op once the final response is sent. Implemented for
  ## HTTP/1.1 and HTTP/2; over HTTP/3 it is currently a no-op (pending an nghttp3
  ## submit_info binding), so treat early hints as best-effort.
  let ci = int(code)
  if ci < 100 or ci > 199: return
  if currentThreadId() != res.core.threadId: return   # loop-thread only
  if res.fd < 0: return                                # h3: not yet supported
  let c = conn(res.core, res.fd, res.gen)
  if c == nil: return
  if res.stream != 0:
    h2SendInformational(c, ci, res.stream, headers)
  else:
    if c.responded: return
    var s = "HTTP/1.1 " & $code & "\r\n"
    for (n, v) in headers: s.add n & ": " & v & "\r\n"
    s.add "\r\n"
    c.wbuf.add s
  # Flush now so the hint is on the wire before the handler does its work.
  try: res.core.flushHook(res.core.loopPtr, res.fd, res.gen)
  except Exception: discard

proc earlyHints*(res: Response, links: openArray[string],
                 headers: openArray[(string, string)] = []) =
  ## Send a 103 Early Hints response carrying `Link` headers, so the client can
  ## preload / preconnect the listed resources while your handler prepares the
  ## final response (RFC 8297). Best-effort (see `informational`):
  ##   res.earlyHints(["</app.css>; rel=preload; as=style",
  ##                   "<https://cdn.example>; rel=preconnect"])
  ##   ... build the page ...
  ##   res.send(Http200, html)
  var h: seq[(string, string)]
  for l in links: h.add ("Link", l)
  for kv in headers: h.add kv
  res.informational(Http103, h)

proc redirect*(res: Response, location: string, permanent = false,
               preserveMethod = false,
               extraHeaders: openArray[(string, string)] = []) =
  ## Send a redirect to `location`. By default 302 (temporary) or 301 (with
  ## `permanent`), which let the client fall back to GET. Set `preserveMethod`
  ## for 307 (temporary) / 308 (permanent), which keep the original method and
  ## body (RFC 9110 15.4) -- use these to redirect a POST/PUT/PATCH so it is not
  ## silently downgraded to GET. For a plaintext-listener -> HTTPS redirect:
  ## `res.redirect("https://" & req.host & req.url.path, permanent = true)`.
  ## Serve HTTPS with HSTS (securityHeaders) so subsequent requests skip the
  ## plaintext hop entirely.
  let code =
    if preserveMethod: (if permanent: Http308 else: Http307)
    else:              (if permanent: Http301 else: Http302)
  var hdrs = @[("Location", location)]
  for h in extraHeaders: hdrs.add h
  send(res, code, "", hdrs)

type CookiePrefix* = enum
  ## RFC 6265bis cookie name prefixes. The browser rejects a cookie carrying the
  ## prefix unless it also carries the attributes the prefix demands, so vortex
  ## forces them (rather than letting a misconfigured cookie be silently dropped).
  cpNone       ## no prefix
  cpSecure     ## `__Secure-`: forces Secure
  cpHost       ## `__Host-`: forces Secure, Path=/ and no Domain (host-locked)

const cookieDateFmt = "ddd, dd MMM yyyy HH:mm:ss 'GMT'"  # RFC 7231 IMF-fixdate

var mpBoundaryCtr {.threadvar.}: uint64

proc serveContent*(req: Request, res: Response, body: openArray[char],
                   contentType = "application/octet-stream", etag = "",
                   lastModified = none(Time), cacheControl = "") =
  ## Serve an in-memory `body` with full conditional-request and byte-range
  ## handling -- the analog of Go's http.ServeContent for a buffered body. Pass
  ## an `etag` and/or `lastModified` to enable validators; it then honors
  ## If-Match / If-Unmodified-Since (-> 412 Precondition Failed), If-None-Match /
  ## If-Modified-Since (-> 304 Not Modified), If-Range, and Range (-> 206 for a
  ## single range, `multipart/byteranges` for several, 416 if none are
  ## satisfiable). Emits `Accept-Ranges: bytes` plus the validators and
  ## Cache-Control you pass. For a large or generated body prefer `res.sendFile`
  ## / `res.stream` (this holds the whole body, and any multipart parts, in
  ## memory).
  let size = body.len.int64
  let isGetHead = req.method in {HttpGet, HttpHead}
  var hdrs: seq[(string, string)] = @[("Accept-Ranges", "bytes")]
  if etag.len > 0: hdrs.add ("ETag", etag)
  if lastModified.isSome: hdrs.add ("Last-Modified", httpDate(lastModified.get))
  if cacheControl.len > 0: hdrs.add ("Cache-Control", cacheControl)

  case evalPreconditions(req.header("if-match"), req.header("if-none-match"),
      req.header("if-modified-since"), req.header("if-unmodified-since"),
      etag, lastModified, isGetHead)
  of pcNotModified: send(res, Http304, "", hdrs); return
  of pcFailed:      send(res, HttpCode(412), "", hdrs); return
  of pcProceed:     discard

  var ranges: seq[ByteRange]
  if isGetHead and req.header("range").len > 0 and
      ifRangeApplies(req.header("if-range"), etag, lastModified):
    let (ok, rs) = parseRanges(req.header("range"), size)
    if not ok:
      hdrs.add ("Content-Range", "bytes */" & $size)
      send(res, HttpCode(416), "", hdrs); return
    ranges = rs

  if ranges.len == 0:                        # whole body -> 200
    hdrs.add ("Content-Type", contentType)
    send(res, Http200, body, hdrs); return

  if ranges.len == 1:                        # one range -> 206
    let (s, e) = ranges[0]
    hdrs.add ("Content-Type", contentType)
    hdrs.add ("Content-Range", "bytes " & $s & "-" & $e & "/" & $size)
    send(res, HttpCode(206), body.toOpenArray(int(s), int(e)), hdrs); return

  # Several ranges -> multipart/byteranges (RFC 9110 14.6). The body is
  # server-supplied (not attacker-controlled), so a counter-based boundary
  # token that won't occur in it is sufficient.
  inc mpBoundaryCtr
  let boundary = "vortex" & toHex(mpBoundaryCtr) & toHex(size)
  var mp = ""
  for (s, e) in ranges:
    mp.add "\r\n--" & boundary & "\r\n"
    mp.add "Content-Type: " & contentType & "\r\n"
    mp.add "Content-Range: bytes " & $s & "-" & $e & "/" & $size & "\r\n\r\n"
    let rlen = int(e - s + 1)
    let old = mp.len
    mp.setLen(old + rlen)
    if rlen > 0: copyMem(addr mp[old], unsafeAddr body[int(s)], rlen)
  mp.add "\r\n--" & boundary & "--\r\n"
  hdrs.add ("Content-Type", "multipart/byteranges; boundary=" & boundary)
  send(res, HttpCode(206), mp, hdrs)

proc setCookie*(name, value: string, maxAge = -1, path = "/", domain = "",
                secure = true, httpOnly = true, sameSite = "Lax",
                expires = none(Time), partitioned = false,
                prefix = cpNone): (string, string) =
  ## Build a Set-Cookie header (as a (name, value) pair for res.send's headers)
  ## with secure defaults: Secure, HttpOnly, SameSite=Lax (OWASP Session
  ## Management). maxAge < 0 omits Max-Age (a session cookie); maxAge = 0 (or an
  ## `expires` in the past) deletes the cookie. `expires` sets an absolute expiry
  ## (Max-Age takes precedence in modern browsers; send both for old ones).
  ## `partitioned` adds Partitioned (CHIPS: a separate cookie jar per top-level
  ## site; requires Secure). `prefix` prepends `__Secure-`/`__Host-` and forces
  ## the attributes those prefixes require. Set secure=false only for local
  ## plaintext development. Emit several by passing several pairs.
  var (nm, p, dom, sec) = (name, path, domain, secure)
  case prefix
  of cpSecure: nm = "__Secure-" & name; sec = true
  of cpHost:   nm = "__Host-" & name; sec = true; p = "/"; dom = ""
  of cpNone:   discard
  var v = nm & "=" & value
  if p.len > 0: v.add "; Path=" & p
  if dom.len > 0: v.add "; Domain=" & dom
  if maxAge >= 0: v.add "; Max-Age=" & $maxAge
  if expires.isSome: v.add "; Expires=" & expires.get.utc.format(cookieDateFmt)
  if sec: v.add "; Secure"
  if httpOnly: v.add "; HttpOnly"
  if sameSite.len > 0: v.add "; SameSite=" & sameSite
  if partitioned: v.add "; Partitioned"
  ("Set-Cookie", v)

proc setSignedCookie*(name, value, secret: string, algo = macSha256,
                      maxAge = -1, path = "/", domain = "", secure = true,
                      httpOnly = true, sameSite = "Lax",
                      expires = none(Time),
                      partitioned = false): (string, string) =
  ## Like `setCookie`, but the value is HMAC signed with `secret` (HMAC-SHA256 by
  ## default; see `CookieMac`) so the client cannot forge or alter it. The stored
  ## value is `value.signature`; read it back and verify with
  ## `req.cookies.signed(name, secret)` using the same `algo`. This is
  ## tamper-proofing, not encryption: the value stays readable, only unforgeable.
  ## Keep `secret` private and stable (rotating it invalidates live cookies), and
  ## pass a cookie-safe `value` (no ';', as with `setCookie`). A name `prefix` is
  ## intentionally not offered here: it changes the cookie name the client sends
  ## back, which must match the name signed -- use `setCookie` for prefixed
  ## signed cookies if you sign the prefixed name yourself.
  let stored = value & "." & sign(secret, name & "=" & value, algo)
  setCookie(name, stored, maxAge, path, domain, secure, httpOnly, sameSite,
            expires = expires, partitioned = partitioned)

proc cookies*(req: Request): Cookies {.inline.} =
  ## A view of the request's cookies, matching the `req.headers` shape:
  ## `req.cookies["sid"]`. Reads the incoming Cookie header(s) sent by the
  ## client (the request side of `setCookie`).
  Cookies(req: req)

proc dequoteCookie(v: string): string =
  ## RFC 6265 4.1.1 allows a cookie value to be wrapped in double quotes; strip a
  ## single matched surrounding pair (only). Interior quotes and unbalanced ones
  ## are left as-is, and no unescaping/percent-decoding is done.
  if v.len >= 2 and v[0] == '"' and v[^1] == '"': v[1 ..< v.high] else: v

iterator all*(c: Cookies, name: string): string =
  ## Yields the value of every cookie named `name`, in the order the client sent
  ## them (RFC 6265 5.4: most-specific path first). Use this to detect a
  ## duplicate/shadowed cookie (e.g. a cookie-tossing attack sets a second,
  ## broader-scoped cookie of the same name); `[]` returns only the first.
  ## Cookie names are case-sensitive; all `cookie` header fields are scanned
  ## (HTTP/2 and /3 may split them). A single matched pair of surrounding double
  ## quotes is stripped (RFC 6265 4.1.1); no other decoding is done.
  for (n, v) in c.req.headers:
    if cmpIgnoreCase(n, "cookie") == 0:
      for part in v.split(';'):
        let kv = part.strip()
        if kv.len == 0: continue
        let eq = kv.find('=')
        let key = if eq < 0: kv else: kv[0 ..< eq].strip()
        if key == name:
          yield (if eq < 0: "" else: dequoteCookie(kv[eq+1 .. ^1].strip()))

proc `[]`*(c: Cookies, name: string): string =
  ## Value of the named cookie ("" when absent). If the same name appears more
  ## than once (distinct cookies sharing a name, e.g. different paths), the FIRST
  ## occurrence wins: per RFC 6265 5.4 the client sends the most-specific-path
  ## cookie first, so it is the safer pick against shadowing. Use `all` to see
  ## every value. Case-sensitive names; a matched pair of surrounding double
  ## quotes is stripped (RFC 6265 4.1.1), no other decoding.
  for v in c.all(name):
    return v

proc signed*(c: Cookies, name, secret: string,
             algo = macSha256): Option[string] =
  ## The verified value of a cookie written with `setSignedCookie`, or `none`
  ## when the cookie is absent, unsigned/malformed, or its HMAC signature does
  ## not match `secret`/`algo` (i.e. tampered). Use the same `algo` the cookie
  ## was signed with. The comparison is constant time. All `cookie` fields with
  ## this name are checked and the first that verifies is returned, so a valid
  ## cookie is not masked by an injected forgery.
  for raw in c.all(name):
    let dot = raw.rfind('.')                    # signature is base64url (no '.')
    if dot <= 0: continue
    let value = raw[0 ..< dot]
    if verify(secret, name & "=" & value, raw[dot + 1 .. ^1], algo):
      return some(value)
  none(string)

# --- streaming request bodies (inbound) -------------------------------------

proc onBody*(req: Request, cb: proc(chunk: openArray[char], last: bool)
             {.gcsafe.}, manualAck = false) =
  ## Register a sink for the request body, called on the loop thread as bytes
  ## arrive (`last` true on the final chunk). Only meaningful in a handler
  ## dispatched for a streaming route (router.stream / a start streamRoute
  ## predicate), which runs at headers-complete before the body; for an
  ## ordinary buffered handler the body is already in `req.body`.
  ##
  ## With `manualAck` the consumer must call `req.ackBody(n)` for each chunk it
  ## has processed; the HTTP/2 stream flow-control window (and HTTP/3 stream
  ## reads) are only replenished on ack, so a slow consumer throttles the peer.
  ## The default auto-acks each chunk once the callback returns (a synchronous
  ## consumer is already throttled by holding the loop thread). The async
  ## adapters use `manualAck` and ack on `read()`.
  if req.fd < 0:
    when not defined(plainHttp):
      let h3c = h3ConnOf(req.core, req.fd, req.gen)
      if h3c != nil:
        h3SetOnBody(h3c, uint64(req.stream), cb, manualAck)
    return
  let c = conn(req.core, req.fd, req.gen)
  if c == nil: return
  if req.stream != 0:
    h2SetOnBody(c, req.stream, cb, manualAck)
    return
  c.onBodyCb = cb
  # HTTP/1 Expect: 100-continue -> send it now that the handler is reading the
  # body (Go's send-on-read model; h2/h3 have no Expect flow). Loop-thread only;
  # a handler that responds before reading never reaches here, so it never
  # prompts the client for the body.
  if c.parser.expectContinue and not c.sent100 and not c.responded and
      currentThreadId() == req.core.threadId:
    c.sent100 = true
    c.wbuf.add continue100
    try: req.core.flushHook(req.core.loopPtr, req.fd, req.gen)
    except Exception: discard

proc ackBody*(req: Request, n: int) =
  ## Grant flow-control credit for `n` consumed request-body bytes on a
  ## `manualAck` streaming handler: HTTP/2 sends a stream WINDOW_UPDATE, HTTP/3
  ## resumes reading the QUIC stream. No-op on HTTP/1 (backpressure there is the
  ## socket) and for the auto-ack default. Loop-thread only.
  if n <= 0 or currentThreadId() != req.core.threadId: return
  if req.fd < 0:
    when not defined(plainHttp):
      let h3c = h3ConnOf(req.core, req.fd, req.gen)
      if h3c != nil:
        h3AckBody(h3c, uint64(req.stream), n)
    return
  let c = conn(req.core, req.fd, req.gen)
  if c == nil or req.stream == 0: return
  h2AckBody(c, req.stream, n)
  try: req.core.flushHook(req.core.loopPtr, req.fd, req.gen)
  except Exception: discard

# --- streaming responses ----------------------------------------------------

proc flushConn(res: Response) {.raises: [].} =
  ## Call the loop's flush hook, containing its untyped effect so the streaming
  ## API stays callable from a strict-effect async body (chronos infers the
  ## hook as raising Exception, which `{.async.}` forbids).
  try: res.core.flushHook(res.core.loopPtr, res.fd, res.gen)
  except Exception: discard

proc kickConn(res: Response) {.raises: [].} =
  try: res.core.kick(res.core.loopPtr, res.fd, res.gen, 0)
  except Exception: discard

proc h2Writable(res: Response, backlog: int): bool =
  ## Backpressure verdict for an HTTP/2 streamed write: writable only when both
  ## the stream send window (empty `backlog`) and the connection write buffer
  ## (`pendingOut`) have room. Unlike HTTP/1 (which is capped by the socket), a
  ## large peer window lets sendData move a whole response into c.wbuf, so
  ## without the pendingOut cap one stream could buffer it all in RAM. When
  ## backed up, mark the stream so flushOut's drain (h2DrainResume) resumes it.
  let c = conn(res.core, res.fd, res.gen)     # flush may have closed the conn
  if c == nil: return false
  if backlog >= respHighWater or pendingOut(c) >= respHighWater:
    h2MarkRespBackedUp(c, res.stream)
    return false
  true

proc sendHead*(res: Response, code: HttpCode, contentType = "",
               headers: openArray[(string, string)] = [],
               contentLength = -1) {.raises: [].} =
  ## Begin a streaming response: send the status line and headers, then emit
  ## the body incrementally with `write` and terminate with `finish`. With the
  ## default `contentLength = -1` no length is sent (HTTP/1.1 uses chunked
  ## framing); pass a known length to send `Content-Length` and a length-
  ## delimited (keep-alive) body instead -- used by file serving. Loop-thread
  ## only (call from the handler or an async/onDrain callback, not a worker).
  ## `{.raises: [].}` (contained) so it composes in strict-effect async bodies.
  try:
    if currentThreadId() != res.core.threadId: return
    # Merge any pending res.headers (set via res.headers[...] before this call)
    # with the send-arg headers, exactly as the buffered path does in
    # applyResponse/h3Apply -- the streaming/file head used to drop them (R14).
    # The send argument wins per name. Consume the entry so the HEAD fallback's
    # applyResponse (which also merges) does not double-apply it.
    let hkey = (res.fd, res.gen, res.stream)
    var userHeaders: seq[(string, string)]
    if res.core.respHeaders.hasKey(hkey):
      userHeaders = res.core.respHeaders[hkey].mergedWith(headers)
      res.core.respHeaders.del hkey
    else:
      userHeaders = @headers
    # Inject the security-headers baseline here too (a streaming response's head;
    # merged once, not per chunk).
    var hdrs = withSecHeaders(res.core, userHeaders)
    # Negotiate streaming compression up front: it drops Content-Length (the
    # compressed size is unknown -> chunked) and adds Content-Encoding + Vary.
    var enc = ""
    when defined(httpGzip) or defined(httpBrotli) or defined(httpZstd):
      enc = negotiateStreamEnc(res, contentType, userHeaders)
      if enc.len > 0:
        hdrs.add ("content-encoding", enc)
        hdrs.add ("vary", "accept-encoding")
    let effLen = if enc.len > 0: -1 else: contentLength
    if effLen >= 0 and (res.fd < 0 or res.stream != 0):
      hdrs.add ("content-length", $effLen)   # h2/h3: informational header
    if res.fd < 0:
      when not defined(plainHttp):
        let h3c = h3ConnOf(res.core, res.fd, res.gen)
        if h3c != nil:
          h3SendHead(res.core, h3c, uint64(res.stream), int(code),
                     contentType, hdrs)
          when defined(httpGzip) or defined(httpBrotli) or defined(httpZstd):
            if enc.len > 0:
              h3SetRespComp(h3c, uint64(res.stream), makeStreamComp(enc), enc)
      return
    let c = conn(res.core, res.fd, res.gen)
    if c == nil: return
    if res.stream != 0:
      h2SendHead(c, int(code), res.stream, res.core.dateStr,
                 res.core.serverHeader, contentType, hdrs, res.core.altSvc)
      when defined(httpGzip) or defined(httpBrotli) or defined(httpZstd):
        if enc.len > 0:
          let st = h2Stream(c, res.stream)
          if st != nil and not st.isHead:
            st.respComp = makeStreamComp(enc)
            st.respEnc = enc
      flushConn(res)
      return
    if c.responded: return
    c.responded = true
    if c.parser.httpMethod == HttpHead:
      # HEAD carries no body. When the caller declared a length (file serving),
      # report it as the Content-Length a GET would return -- length-delimited
      # and keep-alive, but with no body -- rather than forcing Content-Length:
      # 0. finish() completes it (write() is a no-op on HEAD). With no declared
      # length, fall back to a plain empty response.
      if effLen >= 0:
        c.respStreaming = true
        c.respCLDelimited = true
        let ka = c.parser.keepAlive
        appendStreamHead(c.wbuf, code, res.core.dateStr, res.core.serverHeader,
                         contentType, hdrs, chunked = false, keepAlive = ka,
                         announceKeepAlive = ka and c.parser.minor == 0,
                         altSvc = res.core.altSvc, contentLength = effLen)
        flushConn(res)
      else:
        applyResponse(res.core, c, 0, int(code), contentType, userHeaders, "")
      return
    c.respStreaming = true
    let ka = c.parser.keepAlive
    # Known length -> Content-Length + length-delimited keep-alive. Unknown ->
    # chunked (HTTP/1.1) or close-delimited (HTTP/1.0).
    let chunked = effLen < 0 and c.parser.minor >= 1
    c.respChunked = chunked
    c.respCLDelimited = effLen >= 0
    when defined(httpGzip) or defined(httpBrotli) or defined(httpZstd):
      if enc.len > 0:
        c.respComp = makeStreamComp(enc)
        c.respEnc = enc
    appendStreamHead(c.wbuf, code, res.core.dateStr, res.core.serverHeader,
                     contentType, hdrs, chunked, keepAlive = ka,
                     announceKeepAlive = ka and c.parser.minor == 0,
                     altSvc = res.core.altSvc, contentLength = effLen)
    flushConn(res)
  except Exception:
    discard

proc write*(res: Response, data: openArray[char]): bool {.discardable,
            raises: [].} =
  ## Append a body chunk to a streaming response and flush. Returns false once
  ## the unsent backlog reaches `respHighWater`; the producer should then stop
  ## and wait for `onDrain`. Safe no-op (returns false) on a dead connection.
  ## `{.raises: [].}` (the body is contained) so it composes in strict-effect
  ## async bodies -- a producer's `if not res.write(chunk): await res.drained()`.
  try:
    if currentThreadId() != res.core.threadId: return false
    if res.fd < 0:
      when not defined(plainHttp):
        let h3c = h3ConnOf(res.core, res.fd, res.gen)
        if h3c != nil:
          when defined(httpGzip) or defined(httpBrotli) or defined(httpZstd):
            let comp = h3RespComp(h3c, uint64(res.stream))
            if comp != nil:
              let z = compChunk(comp, h3RespEnc(h3c, uint64(res.stream)),
                                data, false)
              if z.len == 0: return true      # buffered; still writable
              return h3StreamWrite(h3c, uint64(res.stream), z) < respHighWater
          return h3StreamWrite(h3c, uint64(res.stream), data) < respHighWater
      return false
    var c = conn(res.core, res.fd, res.gen)
    if c == nil: return false
    if res.stream != 0:
      when defined(httpGzip) or defined(httpBrotli) or defined(httpZstd):
        let st = h2Stream(c, res.stream)
        if st != nil and st.respComp != nil:
          let z = compChunk(st.respComp, st.respEnc, data, false)
          if z.len == 0: return true
          let backlog = h2StreamWrite(c, res.stream, z)
          flushConn(res)
          return h2Writable(res, backlog)
      let backlog = h2StreamWrite(c, res.stream, data)
      flushConn(res)
      return h2Writable(res, backlog)
    if not c.respStreaming: return false
    if c.parser.httpMethod == HttpHead: return true   # no body on HEAD
    when defined(httpGzip) or defined(httpBrotli) or defined(httpZstd):
      if c.respComp != nil:
        let z = compChunk(c.respComp, c.respEnc, data, false)
        if z.len > 0:
          if c.respChunked: appendChunk(c.wbuf, z)
          else:
            let oldLen = c.wbuf.len
            c.wbuf.setLen(oldLen + z.len)
            copyMem(addr c.wbuf[oldLen], unsafeAddr z[0], z.len)
        flushConn(res)
        c = conn(res.core, res.fd, res.gen)
        if c == nil: return false
        if pendingOut(c) >= respHighWater:
          c.respBackedUp = true
          return false
        return true
    if c.respChunked:
      appendChunk(c.wbuf, data)
    elif data.len > 0:
      let oldLen = c.wbuf.len
      c.wbuf.setLen(oldLen + data.len)
      copyMem(addr c.wbuf[oldLen], unsafeAddr data[0], data.len)
    flushConn(res)
    c = conn(res.core, res.fd, res.gen)   # flush may have closed on error
    if c == nil: return false
    if pendingOut(c) >= respHighWater:
      c.respBackedUp = true
      return false
    return true
  except Exception:
    return false

proc finish*(res: Response, trailers: openArray[(string, string)] = [])
             {.raises: [].} =
  ## Terminate a streaming response (the chunked 0-chunk plus optional
  ## trailers, or a connection close for HTTP/1.0), flush, and resume the
  ## connection for the next request. `{.raises: [].}` (contained) for async.
  try:
    if currentThreadId() != res.core.threadId: return
    if res.fd < 0:
      when not defined(plainHttp):
        let h3c = h3ConnOf(res.core, res.fd, res.gen)
        if h3c != nil:
          when defined(httpGzip) or defined(httpBrotli) or defined(httpZstd):
            let comp = h3RespComp(h3c, uint64(res.stream))
            if comp != nil:
              let z = compChunk(comp, h3RespEnc(h3c, uint64(res.stream)), "", true)
              if z.len > 0: discard h3StreamWrite(h3c, uint64(res.stream), z)
              h3SetRespComp(h3c, uint64(res.stream), nil, "")
          h3StreamFinish(h3c, uint64(res.stream))
      return
    let c = conn(res.core, res.fd, res.gen)
    if c == nil: return
    if res.stream != 0:
      when defined(httpGzip) or defined(httpBrotli) or defined(httpZstd):
        let st = h2Stream(c, res.stream)
        if st != nil and st.respComp != nil:
          let z = compChunk(st.respComp, st.respEnc, "", true)
          if z.len > 0: discard h2StreamWrite(c, res.stream, z)
          st.respComp = nil
          st.respEnc = ""
      h2StreamFinish(c, res.stream)
      flushConn(res)
      return
    if not c.respStreaming: return
    c.respStreaming = false
    c.respBackedUp = false
    c.onRespDrain = nil
    let clDelimited = c.respCLDelimited
    c.respCLDelimited = false
    when defined(httpGzip) or defined(httpBrotli) or defined(httpZstd):
      if c.respComp != nil:
        let z = compChunk(c.respComp, c.respEnc, "", true)   # trailer/finish
        if z.len > 0 and c.parser.httpMethod != HttpHead:
          if c.respChunked: appendChunk(c.wbuf, z)
          else:
            let oldLen = c.wbuf.len
            c.wbuf.setLen(oldLen + z.len)
            copyMem(addr c.wbuf[oldLen], unsafeAddr z[0], z.len)
        c.respComp = nil
        c.respEnc = ""
    if c.respChunked and c.parser.httpMethod != HttpHead:
      appendLastChunk(c.wbuf, trailers)
    # Close-delimited (HTTP/1.0, neither chunked nor Content-Length) must close;
    # chunked and Content-Length bodies keep the connection alive.
    if not c.parser.keepAlive or c.peerHalfClosed or
        not (c.respChunked or clDelimited):
      c.closeAfterFlush = true
    # kick resumes the paused pipeline when finish runs after the handler
    # returned (deferred); inline finish is a no-op here and the dispatch
    # return path resets and flushes.
    kickConn(res)
  except Exception:
    discard

proc onDrain*(res: Response, cb: proc(res: Response) {.gcsafe.}) =
  ## Register a callback fired (loop thread) when a backed-up streaming
  ## response's write backlog empties, so the producer can resume writing.
  if currentThreadId() != res.core.threadId: return
  let captured = cb
  if res.fd < 0:
    when not defined(plainHttp):
      # The h3 reflush path cannot pass the handle words, so h3's callback
      # closes over the Response; h1/h2 reconstruct it from the passed words.
      let held = res
      let h3c = h3ConnOf(res.core, res.fd, res.gen)
      if h3c != nil:
        let st = h3StreamPtr(h3c, uint64(res.stream))
        if st != nil:
          st.onRespDrain = proc(core: ptr LoopCore, fd: int32, gen: uint32,
                                stream: uint32) {.gcsafe.} =
            captured(held)
    return
  let c = conn(res.core, res.fd, res.gen)
  if c == nil: return
  let drain = proc(core: ptr LoopCore, fd: int32, gen: uint32,
                   stream: uint32) {.gcsafe.} =
    captured(Response(core: core, fd: fd, gen: gen, stream: stream))
  if res.stream != 0:
    let st = h2Stream(c, res.stream)
    if st != nil: st.onRespDrain = drain
    return
  c.onRespDrain = drain

proc bufferedAmount*(res: Response): int =
  ## Bytes queued for the streaming response but not yet written to the
  ## socket. Zero when idle or on a dead connection.
  if res.fd < 0:
    when not defined(plainHttp):
      let h3c = h3ConnOf(res.core, res.fd, res.gen)
      if h3c != nil:
        return h3StreamBacklog(h3c, uint64(res.stream))
    return 0
  let c = conn(res.core, res.fd, res.gen)
  if c == nil: return 0
  if res.stream != 0:
    let st = h2Stream(c, res.stream)
    if st == nil: return 0
    # Both limits `write` backpressures on: this stream's send-window backlog
    # and the shared connection write buffer. Without pendingOut, a stream
    # parked on the connection cap (backlog 0) would report 0 and `drained()`
    # would resume the producer at once, defeating the connection-level cap.
    return max(st.pendingBody.len - st.pendingPos, pendingOut(c))
  pendingOut(c)

proc abort*(res: Response) {.raises: [].} =
  ## Abort a streamed response mid-body *without* a clean terminator, so the
  ## client can tell the transfer was cut short rather than completed: HTTP/1.1
  ## closes the connection before the final chunk; HTTP/2 and HTTP/3 reset the
  ## stream with an internal error. Use this instead of `finish` when the body
  ## cannot be completed (an error partway through). No-op if not streaming.
  ## `{.raises: [].}` (contained) so it composes in strict-effect async bodies.
  try:
    if currentThreadId() != res.core.threadId: return
    if res.fd < 0:
      when not defined(plainHttp):
        let h3c = h3ConnOf(res.core, res.fd, res.gen)
        if h3c != nil:
          h3StreamAbort(h3c, uint64(res.stream))
      return
    let c = conn(res.core, res.fd, res.gen)
    if c == nil: return
    if res.stream != 0:
      h2StreamAbort(c, res.stream)
      flushConn(res)
      return
    if not c.respStreaming: return
    c.respStreaming = false
    c.respBackedUp = false
    c.onRespDrain = nil
    # No terminating chunk: closing mid-stream is the truncation signal. (For a
    # close-delimited HTTP/1.0 body there is no in-band signal; close is all we
    # have.)
    c.closeAfterFlush = true
    kickConn(res)
  except Exception:
    discard

template stream*(res: Response, code: HttpCode, contentType: string,
                 headers: openArray[(string, string)], body: untyped) =
  ## Block form of a streamed response: send the head, run `body`, then
  ## `finish()` on clean exit -- or `abort()` if `body` raises, so the client
  ## sees an incomplete transfer rather than a well-formed truncation (the
  ## exception propagates). The body emits chunks with `res.write(chunk)`
  ## (sync, returns false under backpressure) or, in an `{.async.}` handler with
  ## an async adapter, `await res.write(chunk)` (write + await the drain):
  ##
  ##     res.stream(Http200, "text/csv", @[("X-K", "v")]):
  ##       for row in rows: await res.write(row)
  ##
  ## Shorthands drop trailing args: `res.stream(code, ct): ...`,
  ## `res.stream(ct): ...`, and `res.stream(): ...` (defaults to 200 +
  ## application/octet-stream -- pass a text/* content-type to enable
  ## compression).
  sendHead(res, code, contentType, headers)
  var streamCompleted = false
  # `streamCompleted = true` is unreachable when the caller's `body` ends in a
  # `return` (a legitimate way to end a stream), so silence that here.
  {.push warning[UnreachableCode]: off.}
  try:
    body
    streamCompleted = true
  finally:
    if streamCompleted: finish(res)
    else: abort(res)
  {.pop.}

template stream*(res: Response, code: HttpCode, contentType: string,
                 body: untyped) =
  res.stream(code, contentType, [], body)

template stream*(res: Response, contentType: string, body: untyped) =
  res.stream(Http200, contentType, [], body)

template stream*(res: Response, body: untyped) =
  res.stream(Http200, "application/octet-stream", [], body)

template stream*(req: Request, chunk, last, body: untyped) =
  ## Consume a streaming request body: `body` runs on the loop thread for each
  ## chunk as it arrives, with `chunk: openArray[char]` and `last: bool` in
  ## scope. The inbound mirror of `res.stream` (which produces a body; this
  ## consumes one). Sugar over `req.onBody`; use in a handler dispatched for a
  ## streaming route. If `body` raises, the response is aborted (mirroring
  ## `res.stream`) so a truncated upload isn't mistaken for a complete one.
  ##
  ##   req.stream(chunk, last):
  ##     sink.write(chunk)
  ##     if last: res.send(Http200, "stored\n")
  block:
    let capturedReq = req
    capturedReq.onBody(proc(chunk: openArray[char], last: bool) {.gcsafe.} =
      try:
        body
      except CatchableError:
        response(capturedReq).abort())

# --- Server-Sent Events (text/event-stream) ---------------------------------

type
  SseStream* = object
    ## A live Server-Sent Events response. Created by `res.sse(...)`, which
    ## sends the SSE headers; push events with `send`, keep idle connections
    ## warm with `comment`, end with `close`. Wraps a streaming `Response`, so
    ## HTTP/1.1 uses chunked framing and HTTP/2/3 a streamed body, with the
    ## same backpressure surface (`bufferedAmount` / `onDrain`).
    res: Response

proc response*(s: SseStream): Response = s.res
  ## The underlying streaming response (e.g. for `await s.response.drained()`).

proc sseSanitize(s: string): string =
  ## SSE field values are single-line; drop CR/LF so a value can't inject a
  ## second field or terminate the event early.
  s.multiReplace(("\r", ""), ("\n", ""))

proc sse*(res: Response, headers: openArray[(string, string)] = [],
          retry = 0): SseStream {.raises: [].} =
  ## Begin a Server-Sent Events stream: sends `200 text/event-stream` with
  ## `Cache-Control: no-cache, no-transform` and `X-Accel-Buffering: no` (so
  ## intermediary proxies don't buffer the stream), then returns a handle to
  ## push events. Loop-thread only. `retry > 0` emits an initial `retry:` field
  ## setting the client's reconnection delay (ms).
  var h = @[("Cache-Control", "no-cache, no-transform"),
            ("X-Accel-Buffering", "no")]
  for kv in headers: h.add kv
  res.sendHead(Http200, "text/event-stream", h)
  result = SseStream(res: res)
  if retry > 0:
    discard res.write("retry: " & $retry & "\n\n")

proc send*(s: SseStream, data: string, event = "", id = "",
           retry = 0): bool {.discardable, raises: [].} =
  ## Push one SSE event and flush. `data` may span multiple lines; each is
  ## emitted as its own `data:` field per the spec. `event` sets the type
  ## (client default "message"), `id` sets the client's `Last-Event-ID` (echoed
  ## as the request header on reconnect), `retry` (ms) overrides the delay.
  ## Returns false when the write backlog is full (see `bufferedAmount` /
  ## `onDrain`); the producer should pause. A dead connection returns false.
  var f = ""
  if id.len > 0:    f.add "id: " & sseSanitize(id) & "\n"
  if event.len > 0: f.add "event: " & sseSanitize(event) & "\n"
  if retry > 0:     f.add "retry: " & $retry & "\n"
  for line in data.splitLines:
    f.add "data: " & line & "\n"
  f.add "\n"                               # blank line terminates the event
  s.res.write(f)

proc comment*(s: SseStream, text = ""): bool {.discardable, raises: [].} =
  ## Emit a comment line (`: text`). Clients ignore it; use it as a heartbeat
  ## to keep idle connections and proxies from timing out. `s.comment()` is a
  ## bare `:` ping.
  s.res.write(": " & sseSanitize(text) & "\n\n")

proc bufferedAmount*(s: SseStream): int = s.res.bufferedAmount
  ## Bytes queued for the SSE stream but not yet written to the socket.

proc onDrain*(s: SseStream, cb: proc(s: SseStream) {.gcsafe.}) =
  ## Fire `cb` (loop thread) when a backed-up SSE stream's write backlog
  ## empties, so the producer can resume.
  let captured = cb
  s.res.onDrain(proc(r: Response) {.gcsafe.} = captured(SseStream(res: r)))

proc alive*(s: SseStream): bool =
  ## False once the client disconnects; the producer loop should stop. Use this
  ## rather than `send` returning false, which is ambiguous (backpressure *or*
  ## a dead connection).
  Request(core: s.res.core, fd: s.res.fd, gen: s.res.gen,
          stream: s.res.stream).isAlive

proc close*(s: SseStream) {.raises: [].} = s.res.finish()
  ## End the SSE stream cleanly and resume the connection.

proc abort*(s: SseStream) {.raises: [].} = s.res.abort()
  ## Cut the SSE stream short (truncation signal), for an error mid-stream.

proc lastEventId*(req: Request): string = req.header("last-event-id")
  ## The `Last-Event-ID` the client echoes when reconnecting an SSE stream (the
  ## `id:` of the last event it saw). Empty on first connect; use it to resume.

template withSse*(res: Response, s, body: untyped) =
  ## Block form for a finite stream: opens an SSE stream bound to `s`, runs
  ## `body`, then closes it (aborting on exception, like `res.stream`). Named
  ## `withSse` (not `sse`) to avoid clashing with the `res.sse(...)` handle
  ## constructor, following the `withLock`/`withFile` scoped-resource idiom.
  ##
  ##   res.withSse(s):
  ##     for row in report: s.send(row.toJson, event = "row", id = $row.id)
  block:
    var s = res.sse()
    var sseCompleted = false
    try:
      body
      sseCompleted = true
    finally:
      if sseCompleted: s.close()
      else: s.abort()

# --- blocking dispatch ------------------------------------------------------

type
  BlockingProc* = proc (req: Request, res: Response) {.nimcall, gcsafe.}
    ## A `blocking:` body. Must be capture-free (nimcall): closures cannot
    ## cross threads under ORC. Request data is read through `req`, which
    ## stays valid (the connection is pinned) until the body sends.

proc snapshotRequest(req: Request): ReqSnapshot =
  ## Capture everything a handler reads, on the loop thread, so a blocking:
  ## worker reads this value copy instead of live loop memory (IMP2 / C3). Uses
  ## the live accessors (safe here -- called on the loop thread, req.snap == nil).
  result.present = true
  result.httpMethod = req.method
  result.target = req.path
  result.body = req.body
  result.params = req.params
  result.remoteAddr = req.remoteAddress
  result.secure = req.isSecure
  result.clientSubject = req.clientCertSubject
  # All headers, pseudo-headers kept (so header(":authority") etc. still work).
  if req.fd < 0:
    when not defined(plainHttp):
      withH3(req, st):
        for (n, v) in st.headers: result.headers.add (n, v)
  else:
    withConn(req, c):
      if req.stream != 0:
        let st = h2Stream(c, req.stream)
        if st != nil:
          for (n, v) in st.headers: result.headers.add (n, v)
      else:
        for (n, v) in req.headers: result.headers.add (n, v)  # h1: no pseudo

proc workerReq(lc: ptr LoopCore, fd: int32, gen: uint32, stream: uint32): Request =
  ## Build the worker's Request, pointing it at the task snapshot when present
  ## (pool path); nil snapshot on the inline loop-thread path (live reads).
  var snap: ptr ReqSnapshot = nil
  if workerSnapshot != nil and workerSnapshot.present: snap = workerSnapshot
  Request(core: lc, fd: fd, gen: gen, stream: stream, snap: snap)

proc blockingTrampoline(user, core: pointer, fd: int32, gen: uint32,
                        stream: uint32, data: string) {.nimcall, gcsafe.} =
  discard data                 # HTTP bodies read the request via `req`
  let fn = cast[BlockingProc](user)
  let lc = cast[ptr LoopCore](core)
  let req = workerReq(lc, fd, gen, stream)
  let res = response(req)
  # On the pool path this runs on a worker thread and holds the connection pin;
  # the inline no-pool path runs on the loop thread with no pin. Only the worker
  # path needs the "always respond" guard (and its send routes via the outbox).
  let onWorker = currentThreadId() != lc.threadId
  if onWorker: workerResponded = false
  try:
    fn(req, res)
  except Exception:
    # Exception (incl. a catchable Defect): answer 500 rather than let the
    # worker thread abort. The trailing guard still releases the pin.
    res.send(Http500, "500 Internal Server Error")
  if onWorker and not workerResponded:
    # The body finished without a response (forgot res.send, or used the
    # loop-thread-only streaming API from a worker, which no-ops here). Emit a
    # default 500 so the client is answered and the outbox push releases the
    # pin this task holds -- otherwise the connection stays pinned forever.
    res.send(Http500, "500 Internal Server Error")

proc dispatchBlocking*(req: Request, fn: BlockingProc) {.raises: [].} =
  ## Pin the connection and hand `fn` to the worker pool. Must be called
  ## from the owning loop thread (i.e. inside a handler). Prefer the
  ## `blocking:` template.
  ##
  ## Declared `{.raises: [].}` so it composes inside strict-effect async
  ## bodies (chronos `{.async.}` tracks raises and only permits
  ## CatchableError). Handler exceptions are already contained: in the
  ## pool this is a pure enqueue, and the no-pool inline path runs the
  ## trampoline, which turns a failing body into a 500.
  try:
    if req.core.pool == nil:
      blockingTrampoline(cast[pointer](fn), cast[pointer](req.core),
                         req.fd, req.gen, req.stream, "")  # no pool: inline
      return
    if req.fd < 0:
      let idx = int(-req.fd) - 2
      if idx >= req.core.h3slots.len or req.core.h3slots[idx].gen != req.gen:
        return
      inc req.core.h3slots[idx].pinned
    else:
      let c = conn(req.core, req.fd, req.gen)
      if c == nil: return
      inc c.pinned
    enqueue(cast[ptr WorkerPool](req.core.pool),
            WorkerTask(fn: blockingTrampoline, user: cast[pointer](fn),
                       core: cast[pointer](req.core), fd: req.fd,
                       gen: req.gen, stream: req.stream,
                       snap: snapshotRequest(req)))
  except Exception:
    discard

type
  BlockingDataProc* = proc (req: Request, res: Response, data: string)
                           {.nimcall, gcsafe.}
    ## Like BlockingProc, but also receives a payload moved into the worker
    ## task (config the capture-free body cannot close over). Used by static
    ## file serving to carry the resolved path + options to the worker.

proc blockingDataTrampoline(user, core: pointer, fd: int32, gen: uint32,
                            stream: uint32, data: string) {.nimcall, gcsafe.} =
  let fn = cast[BlockingDataProc](user)
  let lc = cast[ptr LoopCore](core)
  let req = workerReq(lc, fd, gen, stream)
  let res = response(req)
  let onWorker = currentThreadId() != lc.threadId
  if onWorker: workerResponded = false
  try:
    fn(req, res, data)
  except Exception:
    res.send(Http500, "500 Internal Server Error")
  if onWorker and not workerResponded:
    res.send(Http500, "500 Internal Server Error")

proc dispatchBlockingData*(req: Request, fn: BlockingDataProc,
                           data: sink string) {.raises: [].} =
  ## Like dispatchBlocking, but moves `data` into the worker task so the
  ## capture-free `fn` can read per-request config from it. Call from the
  ## owning loop thread. The pin/enqueue bookkeeping mirrors dispatchBlocking.
  try:
    if req.core.pool == nil:
      blockingDataTrampoline(cast[pointer](fn), cast[pointer](req.core),
                             req.fd, req.gen, req.stream, data)  # no pool: inline
      return
    if req.fd < 0:
      let idx = int(-req.fd) - 2
      if idx >= req.core.h3slots.len or req.core.h3slots[idx].gen != req.gen:
        return
      inc req.core.h3slots[idx].pinned
    else:
      let c = conn(req.core, req.fd, req.gen)
      if c == nil: return
      inc c.pinned
    enqueue(cast[ptr WorkerPool](req.core.pool),
            WorkerTask(fn: blockingDataTrampoline, user: cast[pointer](fn),
                       core: cast[pointer](req.core), fd: req.fd,
                       gen: req.gen, stream: req.stream, data: data,
                       snap: snapshotRequest(req)))
  except Exception:
    discard

type
  BlockingArgsBox[T] = ref object
    ## Carries a capture-free body plus the values moved into the worker. Boxed
    ## so an arbitrary `T` (the `req.blocking(a, b, ...)` argument tuple) can
    ## cross to the worker without a per-type WorkerTask field.
    body: proc (req: Request, res: Response, data: T) {.nimcall, gcsafe.}
    data: T

proc blockingArgsTrampoline[T](user, core: pointer, fd: int32, gen: uint32,
                               stream: uint32, ignored: string) {.nimcall, gcsafe.} =
  let box = cast[BlockingArgsBox[T]](user)
  let lc = cast[ptr LoopCore](core)
  let req = workerReq(lc, fd, gen, stream)
  let res = response(req)
  let onWorker = currentThreadId() != lc.threadId
  if onWorker: workerResponded = false
  try:
    box.body(req, res, box.data)
  except Exception:
    res.send(Http500, "500 Internal Server Error")
  if onWorker and not workerResponded:
    res.send(Http500, "500 Internal Server Error")
  GC_unref(box)

proc dispatchBlockingArgs[T](req: Request,
    body: proc (req: Request, res: Response, data: T) {.nimcall, gcsafe.},
    data: sink T) {.raises: [].} =
  ## Internal: move `data` (the blocking args as a tuple) into the worker and run
  ## the capture-free `body` there. Backs the `req.blocking(a, b, ...)` macro;
  ## not a public API. Pin/enqueue bookkeeping mirrors dispatchBlocking.
  try:
    var box = BlockingArgsBox[T](body: body, data: data)
    if req.core.pool == nil:
      # Inline (no pool): the trampoline runs on THIS thread and unrefs the box;
      # GC_ref so it survives that unref until this scope's own decref. Both are
      # on the loop thread, so there is no cross-thread refcount access.
      GC_ref(box)
      blockingArgsTrampoline[T](cast[pointer](box), cast[pointer](req.core),
                                req.fd, req.gen, req.stream, "")   # inline; unrefs
      return
    # Pool path: hand the box's sole reference to the worker. ORC refcounts are
    # non-atomic, so the box's header must be touched on exactly one thread. The
    # worker's trampoline inc/decs it (bind + GC_unref); `wasMoved` drops this
    # thread's local WITHOUT a decref, so the loop never races the worker on the
    # count (previously the loop's scope-exit decref raced the worker's bind
    # incref -- a genuine data race and the ASan use-after-free in the
    # blocking(args) path). An early return below (dead conn) still decs the
    # local here, but only on the loop thread, which is safe.
    if req.fd < 0:
      let idx = int(-req.fd) - 2
      if idx >= req.core.h3slots.len or req.core.h3slots[idx].gen != req.gen:
        return
      inc req.core.h3slots[idx].pinned
    else:
      let c = conn(req.core, req.fd, req.gen)
      if c == nil: return
      inc c.pinned
    let raw = cast[pointer](box)
    wasMoved(box)                                 # transfer ownership; no loop dec
    enqueue(cast[ptr WorkerPool](req.core.pool),
            WorkerTask(fn: blockingArgsTrampoline[T], user: raw,
                       core: cast[pointer](req.core), fd: req.fd,
                       gen: req.gen, stream: req.stream,
                       snap: snapshotRequest(req)))
  except Exception:
    discard

type
  BlockingResultBase* = ref object of RootObj
    ## Type-erased handle for an awaitable `req.blocking` result. The worker
    ## fills the typed subtype and posts it back; the loop calls `onDone` to
    ## complete it. `onDone` takes the box as a parameter (not a capture) so the
    ## box does not form a reference cycle with its own completion closure --
    ## a cycle would drag ORC's cycle collector into this cross-thread object.
    ## Internal.
    onDone*: proc (self: BlockingResultBase) {.gcsafe.}
  BlockingResultBox*[A, R] = ref object of BlockingResultBase
    ## `body` runs on the worker with the moved-in `args`; its result lands in
    ## `value` (or `err`), read back on the loop. Internal. A `void` body (the
    ## block responds itself) has no `value`.
    body*: proc (req: Request, res: Response, args: A): R {.nimcall, gcsafe.}
    args*: A
    when R isnot void:
      value*: R
    err*: ref CatchableError

proc blockingResultTrampoline[A, R](user, core: pointer, fd: int32, gen: uint32,
                                    stream: uint32, ignored: string) {.nimcall, gcsafe.} =
  # Access the box through a raw `ptr` to its object payload, never a counted
  # ref-bind. `box` outlives the hop via the single GC_ref in
  # dispatchBlockingResult (released by the drain's GC_unref on the loop). ORC
  # refcounts are non-atomic, so touching the box's header here -- on a worker
  # thread, concurrently with the loop thread's own inc/dec -- is a genuine data
  # race that can corrupt the count (caught by helgrind). A `ptr` view reads
  # `body`/`args` and writes `value`/`err` (payload, ordered by the outbox
  # channel) without ever touching the refcount. `ptr <objectType>` (not
  # `ptr <refType>`, which would be a ptr-to-ref double indirection) keeps the
  # RootObj m_type offset correct.
  let box = cast[ptr typeof(BlockingResultBox[A, R]()[])](user)
  let lc = cast[ptr LoopCore](core)
  let req = workerReq(lc, fd, gen, stream)
  let res = response(req)
  try:
    when R is void:
      box.body(req, res, box.args)
    else:
      box.value = box.body(req, res, box.args)
  except CatchableError as e:
    box.err = e
  push(lc.outbox, OutMsg(kind: omBlockingDone, fd: fd, gen: gen,
                         stream: stream, user: user))

proc dispatchBlockingResult*[A, R](req: Request,
                                   box: BlockingResultBox[A, R]) {.raises: [].} =
  ## Internal: run an awaitable blocking `box` on the worker; the result is moved
  ## back and `box.onDone` runs on the loop (see the drain). Backs the async
  ## `req.blocking(...)` overload; not a public API. `box` must outlive the hop,
  ## so it is GC-pinned here and released in the drain.
  try:
    GC_ref(box)
    if req.core.pool == nil:
      blockingResultTrampoline[A, R](cast[pointer](box), cast[pointer](req.core),
                                     req.fd, req.gen, req.stream, "")   # inline
      return
    if req.fd < 0:
      let idx = int(-req.fd) - 2
      if idx >= req.core.h3slots.len or req.core.h3slots[idx].gen != req.gen:
        GC_unref(box); return
      inc req.core.h3slots[idx].pinned
    else:
      let c = conn(req.core, req.fd, req.gen)
      if c == nil: (GC_unref(box); return)
      inc c.pinned
    enqueue(cast[ptr WorkerPool](req.core.pool),
            WorkerTask(fn: blockingResultTrampoline[A, R],
                       user: cast[pointer](box), core: cast[pointer](req.core),
                       fd: req.fd, gen: req.gen, stream: req.stream,
                       snap: snapshotRequest(req)))
  except Exception:
    discard

# --- file streaming (loop-pull; large static files, see staticfiles.nim) ----
# The worker reads one chunk and hands it back via the outbox (emitFile*); the
# loop writes it and pulls the next read (applyFile*), throttled by write
# backpressure. Memory stays bounded to ~one chunk; state travels in the
# messages, so the loop keeps no per-stream table.

proc emitFileStart*(res: Response, status: int, contentType: string,
                    headers: openArray[(string, string)], totalLen: int64,
                    firstChunk: openArray[char], nextRead: string,
                    reader: pointer, last: bool) =
  ## Worker-side: send the head (with Content-Length) plus the first chunk back
  ## to the loop. Marks the task as having responded (no fallback 500).
  push(res.core.outbox, OutMsg(
    kind: omFileStart, fd: res.fd, gen: res.gen, stream: res.stream,
    code: int32(status), data: packResponse(contentType, headers, firstChunk),
    aux: nextRead, user: reader, n64: totalLen, last: last))
  workerResponded = true

proc emitFileChunk*(res: Response, bytes: openArray[char], nextRead: string,
                    reader: pointer, last: bool) =
  ## Worker-side: hand one more chunk back to the loop.
  var d = newString(bytes.len)
  if bytes.len > 0: copyMem(addr d[0], unsafeAddr bytes[0], bytes.len)
  push(res.core.outbox, OutMsg(
    kind: omFileChunk, fd: res.fd, gen: res.gen, stream: res.stream,
    data: d, aux: nextRead, user: reader, last: last))
  workerResponded = true

proc dispatchNextRead(res: Response, nextRead: string, reader: pointer) =
  ## Loop-side: pin + enqueue the next chunk read; the worker calls
  ## emitFileChunk when it lands.
  dispatchBlockingData(
    Request(core: res.core, fd: res.fd, gen: res.gen, stream: res.stream),
    cast[BlockingDataProc](reader), nextRead)

proc applyFileChunk*(res: Response, bytes: openArray[char], nextRead: string,
                     reader: pointer, last: bool) =
  ## Loop-side: write one chunk; finish on the last, else pull the next read now
  ## (or after the write backlog drains).
  let room = res.write(bytes)
  if last:
    res.finish()
    return
  if room:
    dispatchNextRead(res, nextRead, reader)
  else:
    let held = nextRead
    let r = reader
    res.onDrain(proc(res2: Response) {.gcsafe.} =
      dispatchNextRead(res2, held, r))

proc applyFileStart*(res: Response, status: int, contentType: string,
                     headers: openArray[(string, string)], totalLen: int64,
                     firstChunk: openArray[char], nextRead: string,
                     reader: pointer, last: bool) =
  ## Loop-side: send the head (Content-Length = totalLen), then the first chunk.
  res.sendHead(HttpCode(status), contentType, headers,
               contentLength = int(totalLen))
  applyFileChunk(res, firstChunk, nextRead, reader, last)

macro blocking*(request: Request, args: varargs[untyped]): untyped =
  ## Run a block on the worker pool, where blocking calls (sync DB drivers, file
  ## IO, CPU work) are safe. Values named in the call are **moved** into the
  ## worker and are available inside the block by name; `req` and `res` are
  ## injected. The block must call `res.send` (an uncaught exception sends 500).
  ## Only the named values cross the thread boundary -- capturing other
  ## surrounding locals is rejected, which keeps loop-thread state unshared.
  ##
  ## ```nim
  ## proc handler(req: Request, res: Response) =
  ##   let user = req.param("id")
  ##   req.blocking(user):                    # user moved into the worker
  ##     res.send(Http200, render(loadFrom(db, user)))
  ## ```
  ##
  ## Pass several values (they ride in as a tuple, each usable by name):
  ## `req.blocking(user, cfg): ...`. With no values, `req.blocking: ...` just
  ## runs the block on a worker.
  ##
  ## Only **value** data may cross to the worker. A `ref`/`ptr`/`closure`
  ## argument (or a value that has one nested in a field) is rejected at compile
  ## time: it would be shared, not copied, and mutating it on the worker races
  ## the loop thread. To move a uniquely-owned reference in, wrap it with
  ## `isolate(...)` (from the re-exported `std/isolation`), as a `var`; inside
  ## the block it is the plain type: `var u = isolate(load()); req.blocking(u):
  ## use(u)`.
  let body = args[^1]
  var names: seq[NimNode]
  for i in 0 ..< args.len - 1: names.add args[i]
  # bindSym so the expansion reaches these even though `dispatchBlockingArgs`
  # is not exported (kept off the public API).
  let dispatchArgs = bindSym"dispatchBlockingArgs"
  if names.len == 0:
    result = quote do:
      dispatchBlocking(`request`,
        proc (req {.inject.}: Request, res {.inject.}: Response)
            {.nimcall, gcsafe.} =
          `body`)
  else:
    let payload = genSym(nskParam, "payload")
    # Prepare each named value into a local first (prepArg statically rejects
    # ref/ptr/closure types and extracts an isolate(...)), then build the tuple
    # from the locals -- moving a move-only Isolated straight into a tuple
    # constructor defeats the optimizer.
    var prelude = newStmtList()
    var tup = nnkTupleConstr.newTree()
    for n in names:
      let a = genSym(nskLet, "barg")
      prelude.add newLetStmt(a, newCall(bindSym"prepArg", n))
      tup.add a
    var inner = newStmtList()
    for i, n in names:
      inner.add newLetStmt(n, nnkBracketExpr.newTree(payload, newLit(i)))
    inner.add body
    result = quote do:
      block:
        `prelude`
        let moved = `tup`
        `dispatchArgs`(`request`, proc (req {.inject.}: Request,
            res {.inject.}: Response, `payload`: typeof(moved))
            {.nimcall, gcsafe.} =
          `inner`, moved)

# --- WebSockets -------------------------------------------------------------

proc headerHasToken(value, token: string): bool =
  ## Case-insensitive search for `token` in a comma-separated header value.
  for part in value.split(','):
    if part.strip.toLowerAscii == token: return true
  false

proc isWebSocketUpgrade*(req: Request): bool =
  ## True when this request is a WebSocket handshake: an RFC 6455 upgrade over
  ## HTTP/1.1, or an Extended CONNECT over HTTP/2 (RFC 8441) or HTTP/3
  ## (RFC 9220). Call inside a handler, then `acceptWebSocket`.
  if req.fd < 0:
    # HTTP/3: :method CONNECT + :protocol websocket (the h3 codec already
    # validated scheme/path/authority for a ws-connect stream).
    when not defined(plainHttp):
      return req.method == HttpConnect and
        h3FieldOf(req, ":protocol") == "websocket" and
        req.header("sec-websocket-version") == "13"
    else:
      return false
  if req.httpVersion == 2:
    # HTTP/2: :method CONNECT + :protocol websocket (validated by the codec).
    return req.method == HttpConnect and
      h2Field(conn(req.core, req.fd, req.gen), req.stream, ":protocol") ==
        "websocket" and
      req.header("sec-websocket-version") == "13"
  req.httpVersion == 1 and req.method == HttpGet and
  "websocket" in req.header("upgrade").toLowerAscii and
  headerHasToken(req.header("connection"), "upgrade") and
  req.header("sec-websocket-version") == "13" and
  req.header("sec-websocket-key").len > 0

proc acceptWebSocket*(req: Request,
                      protocols: openArray[string] = []): WebSocket =
  ## Complete the handshake and switch to WebSocket mode. Loop thread only;
  ## call from the handler after `isWebSocketUpgrade`. Set `onMessage` /
  ## `onClose` on the returned handle. If the request is not upgradeable or
  ## already answered, the handle is dead (`ws.isAlive == false`) and the
  ## caller should send a normal response.
  ##
  ## `protocols` is the server's supported subprotocols in preference
  ## order; the first that the client also offered is negotiated and echoed
  ## in the handshake. Read it back with `ws.subprotocol` ("" if none).
  result = WebSocket(core: req.core, fd: req.fd, gen: req.gen,
                     stream: req.stream)
  if req.fd < 0:
    # HTTP/3 (RFC 9220): reply 200 on the QUIC stream and attach a WsConn.
    when not defined(plainHttp):
      let h3c = h3ConnOf(req.core, req.fd, req.gen)
      if h3c != nil:
        discard h3WsAccept(req.core, h3c, uint64(req.stream), req.fd, req.gen,
                           req.core.maxWsMessage,
                           req.header("sec-websocket-extensions"),
                           req.header("sec-websocket-protocol"), protocols)
    return
  let c = conn(req.core, req.fd, req.gen)
  if c == nil: return
  if req.stream != 0:
    # HTTP/2 (RFC 8441): reply 200 on the stream and attach a WsConn.
    discard h2WsAccept(c, req.stream, req.core.maxWsMessage,
                       req.header("sec-websocket-extensions"),
                       req.header("sec-websocket-protocol"), protocols,
                       req.core.dateStr, req.core.serverHeader)
    return
  if c.responded or c.ws != nil: return
  discard wsAccept(req.core, c, req.header("sec-websocket-key"),
                   req.core.maxWsMessage,
                   req.header("sec-websocket-extensions"),
                   req.header("sec-websocket-protocol"), protocols)

type
  WsBlockingProc* = proc (ws: WebSocket, msg: string) {.nimcall, gcsafe.}
    ## A `ws.blocking:` body. Capture-free (nimcall) like the HTTP one;
    ## the message is passed in by value rather than read from a handle.

proc wsRunBody(lc: ptr LoopCore, fn: WsBlockingProc, fd: int32, gen: uint32,
               stream: uint32, data: string) {.gcsafe.} =
  let ws = WebSocket(core: lc, fd: fd, gen: gen, stream: stream)
  try:
    fn(ws, data)
  except Exception:
    discard                    # a WebSocket has no "500"; contain a Defect too
                               # so the worker survives and still unpins below

proc wsBlockingTrampoline(user, core: pointer, fd: int32, gen: uint32,
                          stream: uint32, data: string) {.nimcall, gcsafe.} =
  ## Worker-pool entry point: run the body, then signal completion so the
  ## loop unpins the connection and dispatches the next buffered message.
  let lc = cast[ptr LoopCore](core)
  wsRunBody(lc, cast[WsBlockingProc](user), fd, gen, stream, data)
  try:
    push(lc.outbox, OutMsg(kind: omWsDone, fd: fd, gen: gen, stream: stream))
  except Exception:
    discard

proc dispatchWsBlocking*(ws: WebSocket, msg: sink string,
                         fn: WsBlockingProc) {.raises: [].} =
  ## Pin the connection and hand `fn` (plus the message) to the worker pool.
  ## Loop thread only. Pinning gives per-connection backpressure: the loop
  ## stops dispatching further frames until the worker finishes, so one
  ## message is processed at a time and in order (like the HTTP `blocking:`).
  ## `ws.send` from the worker is safe (a stale send after the socket closes
  ## is a no-op via the generation check).
  try:
    if ws.core.pool == nil:
      # No pool: run inline on the loop thread. It is already serialized, so
      # there is nothing to pin and no completion to signal.
      wsRunBody(ws.core, fn, ws.fd, ws.gen, ws.stream, msg)
      return
    if ws.fd < 0:
      # HTTP/3: pin only this QUIC stream (per-stream), like HTTP/2.
      let w = wsConnForH3(ws.core, ws.fd, ws.gen, ws.stream)
      if w == nil: return
      w.blockingPinned = true
    else:
      let c = conn(ws.core, ws.fd, ws.gen)
      if c == nil: return
      if ws.stream == 0:
        inc c.pinned                     # HTTP/1: pin the whole connection
      else:
        # HTTP/2: pin only this stream so the other multiplexed streams stay
        # responsive while the worker runs.
        let w = wsConnForStream(ws.core, c, ws.stream)
        if w == nil: return
        w.blockingPinned = true
    enqueue(cast[ptr WorkerPool](ws.core.pool),
            WorkerTask(fn: wsBlockingTrampoline, user: cast[pointer](fn),
                       core: cast[pointer](ws.core), fd: ws.fd, gen: ws.gen,
                       stream: ws.stream, data: msg))
  except Exception:
    discard

template blocking*(socket: WebSocket, message: string, body: untyped) =
  ## Run `body` on the worker pool in response to a WebSocket message,
  ## where blocking calls (sync DB drivers, file IO, CPU work) are safe.
  ## `ws` and `msg` are injected; `body` cannot capture surrounding locals
  ## (it runs on another thread). Reply with `ws.send`.
  ##
  ## Like the HTTP `blocking:`, the connection is pinned while the body runs:
  ## the loop stops dispatching further frames until it returns, so messages
  ## from one connection are handled one at a time and in order, and a slow
  ## body applies backpressure to that client (frames buffer, bounded by the
  ## receive cap). Different connections still run in parallel.
  ##
  ## ```nim
  ## ws.onMessage = proc(ws: WebSocket, data: string, kind: WsKind) {.gcsafe.} =
  ##   ws.blocking(data):
  ##     let rows = db.getAllRows(sql"...")   # blocking is fine here
  ##     ws.send($rows & ": " & msg)          # `msg` is the message here
  ## ```
  dispatchWsBlocking(socket, message,
    proc (ws {.inject.}: WebSocket, msg {.inject.}: string)
        {.nimcall, gcsafe.} =
      body)
