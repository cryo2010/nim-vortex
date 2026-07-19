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

proc remoteAddress*(req: Request): string =
  ## The peer IP of the connection, captured at accept (access logging, rate
  ## limiting, audit). This is the *direct* peer: behind a reverse proxy it is
  ## the proxy's IP, so recover the origin client from a trusted X-Forwarded-For
  ## policy (see forwardedFor), never from an untrusted header alone. Empty for
  ## HTTP/3 (the QUIC peer address is not captured yet) and for a stale handle.
  if req.fd < 0: return ""
  let c = conn(req.core, req.fd, req.gen)
  if c != nil: c.remoteAddr else: ""

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

var workerResponded* {.threadvar.}: bool
  ## On a worker thread, set by the worker-path `send` so blockingTrampoline can
  ## tell whether the `blocking:` body produced a response. A body that finishes
  ## without one (a bug, or a misuse of the loop-thread-only streaming API from a
  ## worker) must still get a default response emitted, otherwise the outbox push
  ## that releases the connection's pin never happens and it hangs forever.

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

proc send*(res: Response, code: HttpCode) =
  send(res, code, "", "")

proc send*(res: Response, code: int, body: openArray[char],
           contentType = "", headers: openArray[(string, string)] = []) =
  send(res, HttpCode(code), body, contentType, headers)

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
               headers: openArray[(string, string)] = []) {.raises: [].} =
  ## Begin a streaming response: send the status line and headers, then emit
  ## the body incrementally with `write` and terminate with `finish`. No
  ## Content-Length is sent (HTTP/1.1 uses chunked framing). Loop-thread only
  ## (call from the handler or an async/onDrain callback, not a worker).
  ## `{.raises: [].}` (contained) so it composes in strict-effect async bodies.
  try:
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
    let chunked = c.parser.minor >= 1     # HTTP/1.0 clients: close-delimited
    c.respChunked = chunked
    appendStreamHead(c.wbuf, code, res.core.dateStr, res.core.serverHeader,
                     contentType, headers, chunked, keepAlive = ka,
                     announceKeepAlive = ka and c.parser.minor == 0,
                     altSvc = res.core.altSvc)
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
          return h3StreamWrite(h3c, uint64(res.stream), data) < respHighWater
      return false
    var c = conn(res.core, res.fd, res.gen)
    if c == nil: return false
    if res.stream != 0:
      let backlog = h2StreamWrite(c, res.stream, data)
      flushConn(res)
      return backlog < respHighWater
    if not c.respStreaming: return false
    if c.parser.httpMethod == HttpHead: return true   # no body on HEAD
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
          h3StreamFinish(h3c, uint64(res.stream))
      return
    let c = conn(res.core, res.fd, res.gen)
    if c == nil: return
    if res.stream != 0:
      h2StreamFinish(c, res.stream)
      flushConn(res)
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
                 headers: openArray[(string, string)], body: untyped) =
  ## A block form of a streamed response: sends the head, runs `body` (which
  ## calls `res.write(...)` for each chunk), and terminates the stream
  ## afterwards even if `body` raises. Best for producing the whole body inline
  ## (e.g. a file download loop); for a backpressure-driven or async producer,
  ## drive `sendHead`/`write`/`finish`/`onDrain` directly.
  ##
  ##   res.stream(Http200, "text/plain"):
  ##     for chunk in chunks: res.write(chunk)
  ##
  ## If `body` raises, the stream is aborted (not finished) so the client sees
  ## an incomplete transfer rather than a well-formed but truncated body, and
  ## the exception propagates.
  sendHead(res, code, contentType, headers)
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
