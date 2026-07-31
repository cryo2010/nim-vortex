## The protocol-independent request handle. A `Request` is four words:
## a pointer to the owning loop's core state, the connection's fd, a
## generation counter, and (for HTTP/2) a stream id. Responding through a
## stale handle (connection closed/recycled meanwhile) is a safe no-op.
##
## Handlers may respond inside the handler call (fast path) or later;
## HTTP/1 pauses request parsing until a response is produced; HTTP/2
## streams are independent.

import std/[httpcore, strutils, uri, tables]
import ./connection

export PathParams
import ./workerpool
import ./http1/parser as h1parser
import ./http1/codec as h1codec
import ./http2/codec as h2codec
import ./websocket/codec as wscodec
export wscodec
when not defined(plainHttp):
  import ./http3/codec as h3codec
  import ./transport/tls as tlscodec
when defined(httpGzip):
  import ./gzip
when defined(httpBrotli):
  import ./brotli

type
  Request* = object
    core*: ptr LoopCore
    fd*: int32
    gen*: uint32
    stream*: uint32           ## HTTP/2 stream id, 0 for HTTP/1

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

proc response*(req: Request): Response =
  ## The Response paired with a Request. Dispatch hands handlers both;
  ## this exists for code that stored only the read half.
  Response(core: req.core, fd: req.fd, gen: req.gen, stream: req.stream)

proc isAlive*(req: Request): bool =
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

iterator headers*(req: Request): (string, string) =
  ## Yields (name, value) pairs. HTTP/2 and /3 names are lowercase on the
  ## wire; pseudo-headers are skipped.
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
      for h in c.parser.headers:
        yield (c.rbuf.substr(int(h.nameStart),
                             int(h.nameStart + h.nameLen) - 1),
               c.rbuf.substr(int(h.valStart),
                             int(h.valStart + h.valLen) - 1))

proc header*(req: Request, name: string): string =
  ## Case-insensitive single-header lookup; "" when absent.
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

proc body*(req: Request): string =
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
  ## Empty for a stale handle (and, over HTTP/3, if OpenSSL can't report the QUIC
  ## peer).
  if req.fd < 0:
    when not defined(plainHttp):
      let h3c = h3ConnOf(req.core, req.fd, req.gen)
      if h3c != nil: return h3c.remoteAddr
    return ""
  let c = conn(req.core, req.fd, req.gen)
  if c != nil: c.remoteAddr else: ""

proc clientCertSubject*(req: Request): string =
  ## The client certificate's subject DN for an mTLS connection, or "" if none
  ## was presented. Needs `settings.verifyClient = cvOptional`/`cvRequire`; in
  ## those modes OpenSSL has already validated a presented cert during the
  ## handshake, so a non-empty result is a trusted client cert. Always "" over
  ## plaintext (or a -d:plainHttp build).
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

proc isSecure*(req: Request): bool =
  ## True if the request arrived over TLS (HTTPS, or HTTP/2 over TLS) or QUIC
  ## (HTTP/3 is always encrypted). Use it to gate Secure cookies, HSTS, and a
  ## plaintext->HTTPS redirect.
  if req.fd < 0: return true            # HTTP/3 over QUIC is always TLS
  let c = conn(req.core, req.fd, req.gen)
  c != nil and c.ssl != nil

proc securityHeaders*(hsts = false, hstsMaxAge = 63072000,
                      hstsIncludeSubdomains = true, hstsPreload = false,
                      frameOptions = "DENY",
                      contentSecurityPolicy =
                        "default-src 'none'; frame-ancestors 'none'",
                      referrerPolicy = "no-referrer",
                      permissionsPolicy = "",
                      noSniff = true): seq[(string, string)] =
  ## OWASP Secure Headers baseline as a header list to pass to `res.send`
  ## (e.g. `res.send(Http200, body, "application/json", securityHeaders(hsts =
  ## req.isSecure))`). Defaults suit an API/JSON endpoint (a locked-down CSP);
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
  ## The request's host: the :authority pseudo-header for HTTP/2 and HTTP/3, the
  ## Host header for HTTP/1.1 ("" if absent). Use it to build an absolute URL,
  ## e.g. a plaintext -> HTTPS redirect.
  result = req.header(":authority")
  if result.len == 0: result = req.header("host")

proc contentLength*(req: Request): int =
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

proc applyResponse*(core: ptr LoopCore, c: ptr Connection, stream: uint32,
                    code: int, contentType: string,
                    headers: openArray[(string, string)],
                    body: openArray[char]) =
  ## Serialize a response into the connection's write buffer using the
  ## connection's protocol. Loop thread only.
  template emit(h: openArray[(string, string)]) =
    if stream != 0:
      h2Respond(c, code, stream, core.dateStr, core.serverHeader,
                contentType, h, body, core.altSvc)
    else:
      if c.responded: return
      c.responded = true
      appendResponse(c.wbuf, HttpCode(code), core.dateStr, core.serverHeader,
                     contentType, body, h,
                     keepAlive = c.parser.keepAlive,
                     skipBody = c.parser.httpMethod == HttpHead,
                     announceKeepAlive = c.parser.keepAlive and
                                         c.parser.minor == 0,
                     altSvc = core.altSvc)
      if not c.parser.keepAlive:
        c.closeAfterFlush = true
  if core.secHeaders.len == 0: emit(headers)
  else: emit(withSecHeaders(core, headers))

proc h3Apply*(core: ptr LoopCore, fd: int32, gen: uint32, stream: uint32,
              code: int, contentType: string,
              headers: openArray[(string, string)],
              body: openArray[char]) =
  ## HTTP/3 counterpart of applyResponse. Loop thread only.
  when not defined(plainHttp):
    let h3c = h3ConnOf(core, fd, gen)
    if h3c != nil:
      if core.secHeaders.len == 0:
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

when defined(httpGzip) or defined(httpBrotli):
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
    ## Accept-Encoding, honoring q-values (q=0 disables an encoding); brotli wins
    ## a tie. Returns "br", "gzip", or "" (send identity).
    var brQ, gzQ = -1.0
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
      of "gzip": gzQ = q
      of "*":
        if brQ < 0: brQ = q
        if gzQ < 0: gzQ = q
      else: discard
    when not defined(httpBrotli): brQ = -1.0     # can't produce it
    when not defined(httpGzip): gzQ = -1.0
    if brQ > 0 and brQ >= gzQ: "br"
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
    when defined(httpGzip):
      if enc == "gzip": return newGzipStream()
    nil

  proc compChunk(comp: RootRef, enc: string, data: openArray[char],
                 last: bool): string =
    ## Feed a chunk to `comp` and return the bytes to emit (may be "").
    when defined(httpBrotli):
      if enc == "br": return BrotliStream(comp).compress(data, last)
    when defined(httpGzip):
      if enc == "gzip": return GzipStream(comp).compress(data, last)
    ""

proc send*(res: Response, code: HttpCode, body: openArray[char],
           contentType = "", headers: openArray[(string, string)] = []) =
  ## Queue the response. Safe to call once per request, from the handler,
  ## later (deferred), or from a worker thread inside `blocking:`; no-op
  ## if the connection is already gone. With `settings.compress` and a
  ## compression build (`-d:httpBrotli` and/or `-d:httpGzip`), an eligible body
  ## is compressed with the best encoding the client accepts (brotli preferred).
  when defined(httpGzip) or defined(httpBrotli):
    if res.core.compress and body.len >= compressMinSize and
        compressibleType(contentType) and not hasContentEncoding(headers):
      let enc = chooseEncoding(Request(core: res.core, fd: res.fd,
                                       gen: res.gen, stream: res.stream))
      var packed = ""
      when defined(httpBrotli):
        if enc == "br": packed = brotli(body)
      when defined(httpGzip):
        if enc == "gzip": packed = gzip(body)
      if packed.len > 0 and packed.len < body.len:
        var hh = newSeqOfCap[(string, string)](headers.len + 2)
        for h in headers: hh.add h
        hh.add ("content-encoding", enc)
        hh.add ("vary", "accept-encoding")
        sendRaw(res, code, packed, contentType, hh)
        return
  sendRaw(res, code, body, contentType, headers)

proc send*(res: Response, code: HttpCode) =
  send(res, code, "", "")

proc send*(res: Response, code: int, body: openArray[char],
           contentType = "", headers: openArray[(string, string)] = []) =
  send(res, HttpCode(code), body, contentType, headers)

when defined(httpGzip) or defined(httpBrotli):
  proc decodeRequestBody*(req: Request, res: Response): bool =
    ## Transparently decode a gzip/br request body into `req.body` when
    ## settings.decompressRequest is set. Bounded by maxBodySize so a
    ## decompression bomb can't exhaust memory. Returns false (having sent 413
    ## for an over-cap body or 400 for a corrupt one) to skip the handler; true
    ## otherwise (including the no-op cases: feature off, no/other encoding,
    ## empty body). Called once at dispatch (loop thread) before the handler.
    if not req.core.decompressRequest: return true
    let enc = req.header("content-encoding").strip.toLowerAscii
    var isGzip, isBr = false
    when defined(httpGzip):
      if enc == "gzip": isGzip = true
    when defined(httpBrotli):
      if enc == "br": isBr = true
    if not (isGzip or isBr): return true
    let raw = req.body
    if raw.len == 0: return true
    let cap = if req.core.maxDecompressedBody > 0: req.core.maxDecompressedBody
              else: 512 * 1024 * 1024      # hard ceiling when maxBodySize=0
    var r: tuple[ok: bool, tooLarge: bool, data: string]
    when defined(httpGzip):
      if isGzip: r = gunzip(raw, cap)
    when defined(httpBrotli):
      if isBr: r = brotliDecode(raw, cap)
    if not r.ok:
      if r.tooLarge:
        res.send(HttpCode(413), "413 Payload Too Large", "text/plain")
      else:
        res.send(HttpCode(400), "400 Bad Request", "text/plain")
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

proc redirect*(res: Response, location: string, permanent = false,
               extraHeaders: openArray[(string, string)] = []) =
  ## Send a redirect to `location` (301 permanent / 302 temporary). For a
  ## plaintext-listener -> HTTPS redirect: `res.redirect("https://" & req.host &
  ## req.url.path, permanent = true)`. Serve HTTPS with HSTS (securityHeaders)
  ## so subsequent requests skip the plaintext hop entirely.
  var hdrs = @[("Location", location)]
  for h in extraHeaders: hdrs.add h
  send(res, (if permanent: Http301 else: Http302), "", "text/plain", hdrs)

proc setCookie*(name, value: string, maxAge = -1, path = "/", domain = "",
                secure = true, httpOnly = true,
                sameSite = "Lax"): (string, string) =
  ## Build a Set-Cookie header (as a (name, value) pair for res.send's headers)
  ## with secure defaults: Secure, HttpOnly, SameSite=Lax (OWASP Session
  ## Management). maxAge < 0 omits Max-Age (a session cookie). Set secure=false
  ## only for local plaintext development. Emit several by passing several pairs.
  var v = name & "=" & value
  if path.len > 0: v.add "; Path=" & path
  if domain.len > 0: v.add "; Domain=" & domain
  if maxAge >= 0: v.add "; Max-Age=" & $maxAge
  if secure: v.add "; Secure"
  if httpOnly: v.add "; HttpOnly"
  if sameSite.len > 0: v.add "; SameSite=" & sameSite
  ("Set-Cookie", v)

proc sendContinue*(req: Request) =
  ## Send a "100 Continue" interim response for a request that carried
  ## `Expect: 100-continue`, telling the client to proceed with the body. Only
  ## needed when `settings.auto100Continue` is false (otherwise the loop sends it
  ## automatically); call it from a streaming-route handler (which runs at
  ## headers-complete, before the body) once you decide to accept the upload --
  ## or answer 4xx instead to reject it before it is sent. Loop-thread only;
  ## HTTP/1 only (HTTP/2 and HTTP/3 have no Expect flow), a no-op otherwise.
  if req.fd < 0 or req.stream != 0: return
  if currentThreadId() != req.core.threadId: return
  let c = conn(req.core, req.fd, req.gen)
  if c == nil or c.sent100 or c.responded or not c.parser.expectContinue: return
  c.sent100 = true
  c.wbuf.add continue100
  try: req.core.flushHook(req.core.loopPtr, req.fd, req.gen)
  except Exception: discard

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

const respHighWater* = 256 * 1024
  ## write() reports backpressure once the unsent backlog reaches this many
  ## bytes; the producer should pause and resume from onDrain.

proc flushConn(res: Response) {.raises: [].} =
  ## Call the loop's flush hook, containing its untyped effect so the streaming
  ## API stays callable from a strict-effect async body (chronos infers the
  ## hook as raising Exception, which `{.async.}` forbids).
  try: res.core.flushHook(res.core.loopPtr, res.fd, res.gen)
  except Exception: discard

proc kickConn(res: Response) {.raises: [].} =
  try: res.core.kick(res.core.loopPtr, res.fd, res.gen, 0)
  except Exception: discard

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
    # Inject the security-headers baseline here too (a streaming response's head;
    # merged once, not per chunk). The HEAD fallback below routes through
    # applyResponse, which does its own merge, so it keeps the original headers.
    var hdrs = withSecHeaders(res.core, headers)
    # Negotiate streaming compression up front: it drops Content-Length (the
    # compressed size is unknown -> chunked) and adds Content-Encoding + Vary.
    var enc = ""
    when defined(httpGzip) or defined(httpBrotli):
      enc = negotiateStreamEnc(res, contentType, headers)
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
          when defined(httpGzip) or defined(httpBrotli):
            if enc.len > 0:
              h3SetRespComp(h3c, uint64(res.stream), makeStreamComp(enc), enc)
      return
    let c = conn(res.core, res.fd, res.gen)
    if c == nil: return
    if res.stream != 0:
      h2SendHead(c, int(code), res.stream, res.core.dateStr,
                 res.core.serverHeader, contentType, hdrs, res.core.altSvc)
      when defined(httpGzip) or defined(httpBrotli):
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
      # HEAD carries no body: emit the head as a normal empty response.
      applyResponse(res.core, c, 0, int(code), contentType, headers, "")
      return
    c.respStreaming = true
    let ka = c.parser.keepAlive
    # Known length -> Content-Length + length-delimited keep-alive. Unknown ->
    # chunked (HTTP/1.1) or close-delimited (HTTP/1.0).
    let chunked = effLen < 0 and c.parser.minor >= 1
    c.respChunked = chunked
    c.respCLDelimited = effLen >= 0
    when defined(httpGzip) or defined(httpBrotli):
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
          when defined(httpGzip) or defined(httpBrotli):
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
      when defined(httpGzip) or defined(httpBrotli):
        let st = h2Stream(c, res.stream)
        if st != nil and st.respComp != nil:
          let z = compChunk(st.respComp, st.respEnc, data, false)
          if z.len == 0: return true
          let backlog = h2StreamWrite(c, res.stream, z)
          flushConn(res)
          return backlog < respHighWater
      let backlog = h2StreamWrite(c, res.stream, data)
      flushConn(res)
      return backlog < respHighWater
    if not c.respStreaming: return false
    if c.parser.httpMethod == HttpHead: return true   # no body on HEAD
    when defined(httpGzip) or defined(httpBrotli):
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
          when defined(httpGzip) or defined(httpBrotli):
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
      when defined(httpGzip) or defined(httpBrotli):
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
    when defined(httpGzip) or defined(httpBrotli):
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
    return st.pendingBody.len - st.pendingPos
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
                 headersOrEmit, body: untyped) =
  ## Block form of a streamed response: sends the head, runs `body`, and
  ## terminates the stream afterwards -- or aborts it if `body` raises, so the
  ## client sees an incomplete transfer rather than a well-formed truncation
  ## (the exception propagates). The 4th argument is one of two things:
  ##
  ## * **response headers** (`openArray[(string, string)]`) -- the body writes
  ##   chunks itself with `res.write(...)`:
  ##
  ##       res.stream(Http200, "text/plain", @[("X-K", "v")]):
  ##         for chunk in chunks: res.write(chunk)
  ##
  ## * **a fresh identifier** -- injected as an auto-draining `emit(chunk)`: it
  ##   writes and `await`s the drain under backpressure for you. This form needs
  ##   an async adapter in scope (for `res.drained`) and an `{.async.}` body:
  ##
  ##       res.stream(Http200, "application/octet-stream", emit):
  ##         for chunk in source: emit(chunk)
  ##
  ## (The no-headers `res.stream(code, ct): body` form delegates to the first.)
  when compiles(sendHead(res, code, contentType, headersOrEmit)):
    sendHead(res, code, contentType, headersOrEmit)
  else:
    sendHead(res, code, contentType)
    template headersOrEmit(chunk: untyped) =   # injected as the caller's ident
      if not res.write(chunk): await res.drained()
  var streamCompleted = false
  try:
    body
    streamCompleted = true
  finally:
    if streamCompleted: finish(res)
    else: abort(res)

template stream*(res: Response, code: HttpCode, contentType: string,
                 body: untyped) =
  res.stream(code, contentType, [], body)

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

proc blockingTrampoline(user, core: pointer, fd: int32, gen: uint32,
                        stream: uint32, data: string) {.nimcall, gcsafe.} =
  discard data                 # HTTP bodies read the request via `req`
  let fn = cast[BlockingProc](user)
  let lc = cast[ptr LoopCore](core)
  let req = Request(core: lc, fd: fd, gen: gen, stream: stream)
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
    res.send(Http500, "500 Internal Server Error", "text/plain")
  if onWorker and not workerResponded:
    # The body finished without a response (forgot res.send, or used the
    # loop-thread-only streaming API from a worker, which no-ops here). Emit a
    # default 500 so the client is answered and the outbox push releases the
    # pin this task holds -- otherwise the connection stays pinned forever.
    res.send(Http500, "500 Internal Server Error", "text/plain")

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
                       gen: req.gen, stream: req.stream))
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
  let req = Request(core: lc, fd: fd, gen: gen, stream: stream)
  let res = response(req)
  let onWorker = currentThreadId() != lc.threadId
  if onWorker: workerResponded = false
  try:
    fn(req, res, data)
  except Exception:
    res.send(Http500, "500 Internal Server Error", "text/plain")
  if onWorker and not workerResponded:
    res.send(Http500, "500 Internal Server Error", "text/plain")

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
                       gen: req.gen, stream: req.stream, data: data))
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

template blocking*(request: Request, body: untyped) =
  ## Run `body` on the worker pool, where blocking calls (sync DB drivers,
  ## file IO, CPU work) are safe. Inside `body` the request and response
  ## are available as `req` and `res`; `body` must eventually call
  ## `res.send` (an uncaught exception sends 500). `body` cannot capture
  ## surrounding locals; read what you need via `req` inside the body.
  ##
  ## ```nim
  ## proc handler(req: Request, res: Response) =
  ##   req.blocking:
  ##     let rows = db.getAllRows(sql"...")   # blocking is fine here
  ##     res.send(Http200, $rows)
  ## ```
  dispatchBlocking(request,
    proc (req {.inject.}: Request, res {.inject.}: Response)
        {.nimcall, gcsafe.} =
      body)

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
