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
    elif c.parser.chunked:
      result = c.chunkBody
    elif c.parser.bodyLen > 0:
      result = c.rbuf.substr(c.parser.bodyStart,
                             c.parser.bodyStart + c.parser.bodyLen - 1)

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

proc applyResponse*(core: ptr LoopCore, c: ptr Connection, stream: uint32,
                    code: int, contentType: string,
                    headers: openArray[(string, string)],
                    body: openArray[char]) =
  ## Serialize a response into the connection's write buffer using the
  ## connection's protocol. Loop thread only.
  if stream != 0:
    h2Respond(c, code, stream, core.dateStr, core.serverHeader,
              contentType, headers, body, core.altSvc)
  else:
    if c.responded: return
    c.responded = true
    appendResponse(c.wbuf, HttpCode(code), core.dateStr, core.serverHeader,
                   contentType, body, headers,
                   keepAlive = c.parser.keepAlive,
                   skipBody = c.parser.httpMethod == HttpHead,
                   announceKeepAlive = c.parser.keepAlive and
                                       c.parser.minor == 0,
                   altSvc = core.altSvc)
    if not c.parser.keepAlive:
      c.closeAfterFlush = true

proc h3Apply*(core: ptr LoopCore, fd: int32, gen: uint32, stream: uint32,
              code: int, contentType: string,
              headers: openArray[(string, string)],
              body: openArray[char]) =
  ## HTTP/3 counterpart of applyResponse. Loop thread only.
  when not defined(plainHttp):
    let h3c = h3ConnOf(core, fd, gen)
    if h3c != nil:
      h3Respond(core, h3c, uint64(stream), code, contentType, headers, body)

proc send*(res: Response, code: HttpCode, body: openArray[char],
           contentType = "", headers: openArray[(string, string)] = []) =
  ## Queue the response. Safe to call once per request, from the handler,
  ## later (deferred), or from a worker thread inside `blocking:`; no-op
  ## if the connection is already gone.
  if currentThreadId() != res.core.threadId:
    # Worker thread: pack protocol-neutrally; the loop serializes.
    push(res.core.outbox, OutMsg(
      fd: res.fd, gen: res.gen, stream: res.stream, code: int32(code),
      data: packResponse(contentType, headers, body)))
    return
  if res.fd < 0:
    h3Apply(res.core, res.fd, res.gen, res.stream, int(code), contentType,
            headers, body)
    return
  let c = conn(res.core, res.fd, res.gen)
  if c != nil:
    applyResponse(res.core, c, res.stream, int(code), contentType,
                  headers, body)

proc send*(res: Response, code: HttpCode) =
  send(res, code, "", "")

proc send*(res: Response, code: int, body: openArray[char],
           contentType = "", headers: openArray[(string, string)] = []) =
  send(res, HttpCode(code), body, contentType, headers)

# --- streaming responses ----------------------------------------------------

const respHighWater* = 256 * 1024
  ## write() reports backpressure once the unsent backlog reaches this many
  ## bytes; the producer should pause and resume from onDrain.

proc sendHead*(res: Response, code: HttpCode, contentType = "",
               headers: openArray[(string, string)] = []) =
  ## Begin a streaming response: send the status line and headers, then emit
  ## the body incrementally with `write` and terminate with `finish`. No
  ## Content-Length is sent (HTTP/1.1 uses chunked framing). Loop-thread only
  ## (call from the handler or an async/onDrain callback, not a worker).
  if currentThreadId() != res.core.threadId: return
  if res.fd < 0:
    when not defined(plainHttp):
      let h3c = h3ConnOf(res.core, res.fd, res.gen)
      if h3c != nil:
        h3SendHead(res.core, h3c, uint64(res.stream), int(code),
                   contentType, headers)
    return
  let c = conn(res.core, res.fd, res.gen)
  if c == nil: return
  if res.stream != 0:
    h2SendHead(c, int(code), res.stream, res.core.dateStr,
               res.core.serverHeader, contentType, headers, res.core.altSvc)
    res.core.flushHook(res.core.loopPtr, res.fd, res.gen)
    return
  if c.responded: return
  c.responded = true
  if c.parser.httpMethod == HttpHead:
    # HEAD carries no body: emit the head as a normal empty response.
    applyResponse(res.core, c, 0, int(code), contentType, headers, "")
    return
  c.respStreaming = true
  let ka = c.parser.keepAlive
  let chunked = c.parser.minor >= 1     # HTTP/1.0 clients: close-delimited
  c.respChunked = chunked
  appendStreamHead(c.wbuf, code, res.core.dateStr, res.core.serverHeader,
                   contentType, headers, chunked, keepAlive = ka,
                   announceKeepAlive = ka and c.parser.minor == 0,
                   altSvc = res.core.altSvc)
  res.core.flushHook(res.core.loopPtr, res.fd, res.gen)

proc write*(res: Response, data: openArray[char]): bool {.discardable.} =
  ## Append a body chunk to a streaming response and flush. Returns false once
  ## the unsent backlog reaches `respHighWater`; the producer should then stop
  ## and wait for `onDrain`. Safe no-op (returns false) on a dead connection.
  if currentThreadId() != res.core.threadId: return false
  if res.fd < 0:
    when not defined(plainHttp):
      let h3c = h3ConnOf(res.core, res.fd, res.gen)
      if h3c != nil:
        return h3StreamWrite(h3c, uint64(res.stream), data) < respHighWater
    return false
  var c = conn(res.core, res.fd, res.gen)
  if c == nil: return false
  if res.stream != 0:
    let backlog = h2StreamWrite(c, res.stream, data)
    res.core.flushHook(res.core.loopPtr, res.fd, res.gen)
    return backlog < respHighWater
  if not c.respStreaming: return false
  if c.parser.httpMethod == HttpHead: return true   # no body on HEAD
  if c.respChunked:
    appendChunk(c.wbuf, data)
  elif data.len > 0:
    let oldLen = c.wbuf.len
    c.wbuf.setLen(oldLen + data.len)
    copyMem(addr c.wbuf[oldLen], unsafeAddr data[0], data.len)
  res.core.flushHook(res.core.loopPtr, res.fd, res.gen)
  c = conn(res.core, res.fd, res.gen)   # flush may have closed on error
  if c == nil: return false
  if pendingOut(c) >= respHighWater:
    c.respBackedUp = true
    return false
  true

proc finish*(res: Response, trailers: openArray[(string, string)] = []) =
  ## Terminate a streaming response (the chunked 0-chunk plus optional
  ## trailers, or a connection close for HTTP/1.0), flush, and resume the
  ## connection for the next request.
  if currentThreadId() != res.core.threadId: return
  if res.fd < 0:
    when not defined(plainHttp):
      let h3c = h3ConnOf(res.core, res.fd, res.gen)
      if h3c != nil:
        h3StreamFinish(h3c, uint64(res.stream))
    return
  let c = conn(res.core, res.fd, res.gen)
  if c == nil: return
  if res.stream != 0:
    h2StreamFinish(c, res.stream)
    res.core.flushHook(res.core.loopPtr, res.fd, res.gen)
    return
  if not c.respStreaming: return
  c.respStreaming = false
  c.respBackedUp = false
  c.onRespDrain = nil
  if c.respChunked and c.parser.httpMethod != HttpHead:
    appendLastChunk(c.wbuf, trailers)
  if not c.parser.keepAlive or not c.respChunked or c.peerHalfClosed:
    c.closeAfterFlush = true
  # kick resumes the paused pipeline when finish runs after the handler
  # returned (deferred); inline finish is a no-op here and the dispatch
  # return path resets and flushes.
  res.core.kick(res.core.loopPtr, res.fd, res.gen, 0)

proc onDrain*(res: Response, cb: proc(res: Response) {.gcsafe.}) =
  ## Register a callback fired (loop thread) when a backed-up streaming
  ## response's write backlog empties, so the producer can resume writing.
  if currentThreadId() != res.core.threadId: return
  let captured = cb
  # The h3 reflush path cannot pass the handle words, so h3's callback closes
  # over the Response; h1/h2 reconstruct it from the passed words.
  let held = res
  if res.fd < 0:
    when not defined(plainHttp):
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
  let req = Request(core: cast[ptr LoopCore](core), fd: fd, gen: gen,
                    stream: stream)
  let res = response(req)
  try:
    fn(req, res)
  except CatchableError:
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
  except CatchableError:
    discard                    # a WebSocket has no "500"; the app decides

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
