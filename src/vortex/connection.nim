## Per-connection state. Connections live in a fixed pool indexed by fd;
## slots are recycled with a generation counter so late responses (from
## worker threads or deferred handlers) can never touch a connection that
## has since been closed and reused.

import std/[locks, uri, tables, json]
from std/selectors import SelectEvent, trigger, newSelectEvent, close
import ./http1/parser

type
  PathParams* = seq[(string, string)]
    ## Route parameters captured by the router; exposed as req.params.

  ReqKey* = (int32, uint32, uint32)
    ## Identifies an in-flight request/stream: (fd, generation, stream id).
    ## HTTP/1 uses stream 0; h2/h3 use the stream id. Keys the pending
    ## `res.headers` store below.

  ResponseHeaders* = object
    ## Response headers accumulated via `res.headers` before `send` is called.
    ## `[]=` overwrites by name (case-insensitive); `add` keeps duplicates (for
    ## Set-Cookie and friends). Operators live in request.nim (which is exported).
    s*: seq[(string, string)]

  OutMsgKind* = enum
    omHttp,                   ## data is a packed HTTP response (see packResponse)
    omWs,                     ## data is a ready-to-write WebSocket frame
    omWsClose,                ## data is a WebSocket close frame; close after flush
    omWsDone,                 ## a ws.blocking worker finished: unpin and resume
    omFileStart,              ## begin a streamed file: head + first chunk
    omFileChunk,              ## one more chunk of a streamed file
    omBlockingDone            ## an awaitable req.blocking worker finished: `user`
                              ## is a BlockingResultBase; run its completion

  OutMsg* = object
    ## A message produced off-loop (worker thread), routed back to the
    ## owning event loop. HTTP responses arrive in protocol-neutral packed
    ## form (the loop serializes them as HTTP/1 bytes or HTTP/2 frames);
    ## WebSocket frames arrive already serialized (server frames are
    ## unmasked and self-contained), the loop just appends them.
    kind*: OutMsgKind         ## omHttp by default (existing response path)
    fd*: int32
    gen*: uint32
    stream*: uint32           ## 0 for HTTP/1
    code*: int32
    data*: string             ## packed response, WS frame, or a file chunk
    # File-streaming (omFileStart/omFileChunk): the loop-pull mechanism carries
    # the next read request + the worker proc that services it, so the loop
    # stays stateless between chunks.
    aux*: string              ## next read request ("path\0off\0len\0remaining")
    user*: pointer            ## the chunk-reader proc (a BlockingDataProc)
    buf*: pointer             ## omFileChunk: the pooled read buffer (code = bytes read)
    n64*: int64               ## total Content-Length (omFileStart)
    last*: bool               ## this chunk completes the file
    keepPin*: bool            ## this response was produced by an awaitable
                              ## req.blocking body: its connection/slot pin is
                              ## released by the task's later omBlockingDone, not
                              ## by applying this message, so the apply path must
                              ## NOT decrement the pin (double-dec -> UAF). See
                              ## request.blockingResultTrampoline / eventloop.

  Outbox* = object
    ## MPSC channel into an event loop: workers push, the loop drains on
    ## its wakeup event. Lives in shared memory (createShared).
    lock*: Lock
    msgs*: seq[OutMsg]
    ev*: SelectEvent

  ConnState* = enum
    csFree,      ## slot unused
    csActive,    ## reading/handling requests
    csClosing,   ## flush pending output, then close
    csDraining   ## half-closed; read and discard peer bytes, then close

  DeadlineKind* = enum
    dkNone, dkHeader, dkBody, dkIdle, dkDrain,
    dkResponse, ## request fully read, waiting for a deferred/async response
    dkWsPing,   ## WebSocket idle: send a keepalive ping when it expires
    dkWsPong    ## ping sent: close the connection if it expires with no reply

  RespDrainCb* = proc (core: ptr LoopCore, fd: int32, gen: uint32,
                       stream: uint32) {.gcsafe.}
    ## A streaming response's onDrain: called on the loop thread when the
    ## write backlog empties. Reconstructs a Response from the handle words
    ## and invokes the user callback (request.nim). Loop-thread only.

  BodyCb* = proc (chunk: openArray[char], last: bool) {.gcsafe.}
    ## An inbound streaming body sink (req.onBody): called on the loop thread
    ## as request body bytes arrive, `last` true on the final chunk. Set by a
    ## streaming handler dispatched at headers-complete.

  StreamRouteCb* = proc (core: ptr LoopCore, fd: int32, gen: uint32,
                         stream: uint32): bool {.gcsafe.}
    ## Opt-in predicate: given a request whose head is parsed, returns whether
    ## it should be dispatched as a streaming route (handler runs at
    ## headers-complete, body delivered via onBody) instead of buffered. Set
    ## per loop from the router / start; nil = every request is buffered (the
    ## default, zero cost). Reconstructs a Request from the handle words.

  RawClosure* = tuple[prc, env: pointer]
    ## A closure's ABI (its proc + environment) captured as plain, untraced
    ## pointers. `start()` copies its handler/stream-route into every per-core
    ## loop thread; holding those as traced closures would incref/decref one
    ## shared environment concurrently across threads, racing its non-atomic
    ## ORC refcount (TSan-confirmed) -- the same reason the adapter hooks above
    ## are `nimcall` proc pointers, not closures. Storing the raw pair on the
    ## loop instead keeps all refcounting off the loop threads; the environment
    ## stays alive for the server's lifetime via the traced copy in
    ## LoopThreadArg, which is refcounted only on the main thread. A closure is
    ## exactly `tuple[prc, env]` at the ABI level, so `cast` reinterprets it
    ## without a refcount, and calling `prc` with `env` as the trailing
    ## argument is precisely how the compiler invokes a closure. `prc == nil`
    ## means unset.

  Connection* = object
    fd*: int32
    gen*: uint32              ## bumped on close; part of the Request handle
    state*: ConnState
    remoteAddr*: string       ## peer IP captured at accept (TCP; "" for HTTP/3)
    rbuf*: string             ## receive buffer (grows, reused)
    rlen*: int                ## valid bytes in rbuf
    wbuf*: string             ## pending output
    wpos*: int                ## bytes of wbuf already written to the socket
    parser*: RequestParser
    chunkBody*: string        ## decoded chunked request body (reused)
    bodyDecoded*: string      ## decompressed request body (Content-Encoding); used
    bodyDecodedSet*: bool     ## when set, req.body returns it instead of rbuf
    ssl*: pointer             ## SSL* for TLS connections, nil for plaintext
    handshaking*: bool        ## TLS handshake still in progress
    awaitingProxy*: bool      ## reading a PROXY-protocol header before TLS/HTTP
    alpn*: string             ## negotiated protocol ("" until known)
    h2*: RootRef              ## http2.codec.H2Conn; nil = HTTP/1 (loop-only)
    ws*: RootRef              ## websocket.codec.WsConn; nil = not upgraded
    deadline*: int64          ## coarse monotonic seconds; 0 = no timeout
    dlKind*: DeadlineKind
    writeDeadline*: int64     ## coarse monotonic seconds; 0 = none. Independent
                              ## of `deadline`: set when output is pending but the
                              ## socket is unwritable, so a slow-reading client
                              ## that stalls the write is closed (writeTimeout)
                              ## without clobbering the request/idle deadline.
    writeArmed*: bool         ## selector currently watching writability
    registered*: bool         ## fd registered with the selector
    pinned*: int32            ## outstanding worker tasks; slot can't recycle
    filePinned*: int32        ## subset of `pinned` that are sendFile chunk reads
                              ## (dispatchNextRead). Such a worker only reads a
                              ## file -- it never touches the HTTP/2 stream table --
                              ## so h2 input (flow-control frames, other streams'
                              ## data) is safe to process while ONLY file pins are
                              ## held. That keeps a streamed response's own
                              ## WINDOW_UPDATEs flowing while it is mid-stream,
                              ## instead of starving them until the read unpins.
    closeRequested*: bool     ## close deferred until unpinned
    responded*: bool          ## current request has been answered
    sent100*: bool            ## 100 Continue already sent for this request
    requestCount*: int        ## HTTP/1 requests served on this connection
    urlCached*: bool          ## lazy per-request caches (see request.url)
    queryCached*: bool
    jsonCached*: bool
    cachedUrl*: Uri
    cachedQuery*: Table[string, string]
    cachedJson*: JsonNode
    pathParams*: PathParams   ## written by the router at match time
    awaitingResponse*: bool   ## handler deferred; parsing is paused
    closeAfterFlush*: bool
    lingerClose*: bool        ## drain peer before close (reliable error delivery)
    peerHalfClosed*: bool     ## peer sent FIN (half-close): no more requests,
                              ## but a buffered one still gets its response
    # Streaming response state (res.sendHead/write/finish). HTTP/1 only;
    # h2/h3 keep their streaming flags on the per-stream struct.
    respStreaming*: bool      ## a chunked/close-delimited response is open
    respChunked*: bool        ## true = Transfer-Encoding: chunked framing
    respCLDelimited*: bool     ## streaming with a known Content-Length (keep-alive
                               ## survives finish; not close-delimited)
    respComp*: RootRef        ## streaming compressor (Gzip/BrotliStream upcast);
                               ## nil = identity. Its =destroy frees the codec
                               ## state when the connection is reset/closed.
    respEnc*: string          ## "gzip"/"br" for respComp (empty = none)
    respBackedUp*: bool       ## write() reported backpressure; onDrain pending
    onRespDrain*: RespDrainCb
    # Inbound streaming (req.onBody). A streaming route is dispatched at
    # headers-complete; body bytes are delivered incrementally instead of
    # buffered whole.
    reqStreaming*: bool       ## dispatched early; body flows to onBody
    bodyFed*: int             ## body bytes already delivered to onBody
    onBodyCb*: BodyCb

  H3SlotEntry* = object
    ## HTTP/3 connections aren't fd-backed; they live in per-loop slots.
    ## A Request handle encodes slot i as fd = -(i+2).
    conn*: RootRef            ## http3.codec.H3Conn; nil = free slot
    gen*: uint32
    pinned*: int32            ## outstanding worker tasks
    closeReq*: bool           ## free deferred until unpinned

  ChunkPool* = object
    ## Loop-owned free-list of raw `fileChunkCap` buffers for streamed file
    ## reads (res.sendFile). A worker fills a borrowed buffer (it never
    ## allocates); the loop copies it into the response and returns it here.
    ## alloc/free stay on the loop thread and buffers are recycled, so a
    ## slow-drained download no longer churns a fresh chunk per read hop through
    ## the per-thread allocator (which is what ballooned RSS under load).
    free*: seq[pointer]       ## available buffers (loop thread only)
    all*: seq[pointer]        ## every buffer created, for teardown

  LoopCore* = object
    ## The part of an event loop's state that `Request` handles must reach:
    ## connection slots plus per-loop cached strings. Lives inside the Loop
    ## object (stable address for the server's lifetime).
    conns*: seq[Connection]
    h3slots*: seq[H3SlotEntry]
    altSvc*: string           ## advertised on h1/h2 responses when h3 is on
    dateStr*: string          ## cached RFC 7231 date, refreshed once/second
    serverHeader*: string
    secHeaders*: seq[(string, string)]  ## OWASP baseline injected on responses
                                        ## when settings.securityHeaders is set
                                        ## (loop-thread only, precomputed once)
    nowSec*: int64            ## coarse monotonic seconds, updated per tick
    maxWsMessage*: int        ## largest inbound WebSocket message (bytes)
    wsPingInterval*: int      ## WebSocket idle before a keepalive ping (0 disables)
    wsPongTimeout*: int       ## after a keepalive ping, seconds to wait for a reply
    wsIdle*: seq[RootRef]     ## h2/h3 WebSocket streams tracked for idle keepalive
                              ## (WsConn upcast; h1 uses the connection deadline wheel)
    wsCompression*: bool      ## negotiate permessage-deflate (only with -d:wsDeflate)
    compress*: bool           ## gzip/brotli eligible responses (needs the flags)
    decompressRequest*: bool  ## decode gzip/br/zstd request bodies into req.body
    maxDecompressedBody*: int ## cap on a decoded request body (decompression bomb)
    trustedProxies*: seq[string]  ## CIDR/IP allowlist; forwarded headers
                                  ## (X-Forwarded-*, RFC 7239) are honored only
                                  ## from a peer in this list (empty = none)
    threadId*: int            ## owning thread; respond() routes on this
    pool*: pointer            ## ptr WorkerPool (untyped to avoid a cycle)
    outbox*: ptr Outbox
    chunkPool*: ChunkPool     ## recycled sendFile read buffers (loop-owned)
    respHeaders*: Table[ReqKey, ResponseHeaders]
      ## Pending `res.headers` per in-flight request, merged in at send and
      ## dropped once the response is emitted (loop-thread only). Empty for the
      ## common case, so a non-user pays only one failed lookup per response.
    respTrailers*: Table[ReqKey, ResponseHeaders]
      ## Pending `res.trailers` per in-flight streamed response, emitted by
      ## `res.finish` after the body (loop-thread only). Empty for the common
      ## case, so a response that sets no trailers pays only one failed lookup.
    # Async-adapter integration (see adapters/). All loop-thread only.
    loopPtr*: pointer         ## the owning Loop, for kick
    pumpHook*: proc (): int {.nimcall, gcsafe.}
      ## Registered by an adapter; called once per loop iteration to run
      ## ready async callbacks. Returns a max selector timeout in ms, or
      ## -1 for no constraint.
    teardownHook*: proc () {.nimcall, gcsafe.}
      ## Registered by an adapter alongside pumpHook; called once when the loop
      ## thread exits, to release the adapter's thread-local dispatcher (its
      ## selector fd and any lingering futures). Without it, a loop thread that
      ## used async leaks the dispatcher on exit (each server restart leaks one).
    kick*: proc (loopPtr: pointer, fd: int32, gen: uint32,
                 stream: uint32) {.nimcall, gcsafe.}
      ## Flush/resume after a deferred same-thread respond (async
      ## completion). Set by the event loop; safe to call redundantly.
    flushHook*: proc (loopPtr: pointer, fd: int32,
                      gen: uint32) {.nimcall, gcsafe.}
      ## Flush a connection's write buffer now. Used by a loop-thread
      ## WebSocket send outside the read path. Set by the event loop.
    wsStreamLookup*: proc (c: pointer, stream: uint32): RootRef
                       {.nimcall, gcsafe.}
      ## Resolve an HTTP/2 (RFC 8441) WebSocket stream's WsConn from a
      ## `WebSocket` handle. Set by the h2 codec; the WebSocket layer cannot
      ## import the h2 codec, so it reaches per-stream state through this.
    wsH3Lookup*: proc (core: pointer, fd: int32, gen: uint32,
                       stream: uint32): RootRef {.nimcall, gcsafe.}
      ## Resolve an HTTP/3 (RFC 9220) WebSocket stream's WsConn. Set by the h3
      ## codec. h3 handles have `fd < 0` (an h3 slot, not a `ptr Connection`),
      ## so this takes the whole handle rather than a connection pointer.
    streamRouteRaw*: RawClosure
      ## Opt-in inbound-streaming predicate (see StreamRouteCb), stored as a
      ## raw closure (see RawClosure) so it doesn't refcount across loop
      ## threads. `prc == nil` unless the server was started with streaming
      ## routes; the loop only consults it when set, so the buffered path pays
      ## nothing.
    pendingBlockingResults*: int
      ## Async `req.blocking` tasks dispatched but whose `omBlockingDone` the loop
      ## has not processed yet (loop-thread only). The graceful drain waits for
      ## this to reach 0 so a worker's completion always runs `onDone` (completing
      ## the awaiting future) before the loop exits -- otherwise a shutdown that
      ## races the worker would orphan the future + its suspended continuation
      ## (the response releases the connection pin one message before
      ## `omBlockingDone`, so the connection count alone can hit 0 too early).

proc hasStreamRoute*(core: ptr LoopCore): bool {.inline.} =
  ## True when a streaming predicate is configured (see streamRouteRaw).
  core.streamRouteRaw.prc != nil

proc callStreamRoute*(core: ptr LoopCore, fd: int32, gen: uint32,
                      stream: uint32): bool {.inline.} =
  ## Invoke the streaming predicate from its raw (proc, env) pair -- exactly how
  ## the compiler calls a closure -- without touching any refcount. See
  ## RawClosure. Only call when hasStreamRoute(core).
  cast[proc (core: ptr LoopCore, fd: int32, gen: uint32, stream: uint32,
             env: pointer): bool {.nimcall, gcsafe.}](
    core.streamRouteRaw.prc)(core, fd, gen, stream, core.streamRouteRaw.env)

proc newOutbox*(): ptr Outbox =
  result = createShared(Outbox)
  initLock result.lock
  result.ev = newSelectEvent()

proc freeOutbox*(ob: ptr Outbox) =
  ## Only after all loops and workers using it have stopped.
  close(ob.ev)
  deinitLock ob.lock
  ob.msgs = @[]
  deallocShared ob

proc push*(ob: ptr Outbox, msg: sink OutMsg) =
  acquire ob.lock
  ob.msgs.add msg
  release ob.lock
  trigger ob.ev

proc drain*(ob: ptr Outbox, into: var seq[OutMsg]) =
  ## Swap out all pending messages; `into` should be empty.
  acquire ob.lock
  swap(into, ob.msgs)
  release ob.lock

proc addU32(s: var string, v: uint32) =
  s.add char(uint8(v))
  s.add char(uint8(v shr 8))
  s.add char(uint8(v shr 16))
  s.add char(uint8(v shr 24))

proc getU32(s: string, pos: int): uint32 =
  uint32(uint8(s[pos])) or (uint32(uint8(s[pos+1])) shl 8) or
  (uint32(uint8(s[pos+2])) shl 16) or (uint32(uint8(s[pos+3])) shl 24)

proc packResponse*(contentType: string,
                   headers: openArray[(string, string)],
                   body: openArray[char]): string =
  ## Protocol-neutral response payload for OutMsg.data.
  result = newStringOfCap(32 + contentType.len + body.len)
  result.addU32 uint32(contentType.len)
  result.add contentType
  result.addU32 uint32(headers.len)
  for (n, v) in headers:
    result.addU32 uint32(n.len)
    result.add n
    result.addU32 uint32(v.len)
    result.add v
  let old = result.len
  if body.len > 0:
    result.setLen(old + body.len)
    copyMem(addr result[old], unsafeAddr body[0], body.len)

proc unpackResponse*(data: string):
    tuple[contentType: string, headers: seq[(string, string)],
          bodyStart: int] =
  var pos = 0
  let ctLen = int(getU32(data, pos)); pos += 4
  result.contentType = data.substr(pos, pos + ctLen - 1); pos += ctLen
  let n = int(getU32(data, pos)); pos += 4
  for i in 0 ..< n:
    let nl = int(getU32(data, pos)); pos += 4
    let name = data.substr(pos, pos + nl - 1); pos += nl
    let vl = int(getU32(data, pos)); pos += 4
    let val = data.substr(pos, pos + vl - 1); pos += vl
    result.headers.add (name, val)
  result.bodyStart = pos

proc conn*(core: ptr LoopCore, fd: int32, gen: uint32): ptr Connection =
  ## Resolve a (fd, gen) handle; nil if the connection is gone.
  if fd < 0 or int(fd) >= core.conns.len: return nil
  result = addr core.conns[int(fd)]
  if result.gen != gen or result.state == csFree: return nil

const fileChunkCap* = 128 * 1024
  ## Size of a pooled sendFile read buffer (one worker read hop).

proc chunkTake*(p: var ChunkPool): pointer =
  ## Borrow a buffer for a file-read worker to fill (loop thread only).
  if p.free.len > 0: return p.free.pop()
  result = alloc(fileChunkCap)
  p.all.add result

proc chunkReturn*(p: var ChunkPool, buf: pointer) =
  ## Return a buffer after the loop copied it into the response (loop thread).
  if buf != nil: p.free.add buf

proc chunkPoolFree*(p: var ChunkPool) =
  ## Free every pooled buffer at loop teardown (workers already joined).
  for b in p.all: dealloc(b)
  p.free.setLen 0
  p.all.setLen 0

const respHighWater* = 256 * 1024
  ## write() reports backpressure once the unsent backlog reaches this many
  ## bytes; the producer should pause and resume from onDrain. Lives here (not
  ## request.nim) so the HTTP/2 codec can apply the same connection-level cap.

proc pendingOut*(c: ptr Connection): int {.inline.} =
  c.wbuf.len - c.wpos

proc clearRespHeaders*(core: ptr LoopCore, fd: int32, gen: uint32) =
  ## Drop any pending `res.headers` for a connection/slot being torn down (a
  ## request that set headers but never sent). No-op when unused; the table is
  ## normally near-empty, so the scan is cheap.
  if core.respHeaders.len > 0:
    var stale: seq[ReqKey]
    for k in core.respHeaders.keys:
      if k[0] == fd and k[1] == gen: stale.add k
    for k in stale: core.respHeaders.del k
  if core.respTrailers.len > 0:
    var stale: seq[ReqKey]
    for k in core.respTrailers.keys:
      if k[0] == fd and k[1] == gen: stale.add k
    for k in stale: core.respTrailers.del k

proc resetForNextRequest*(c: var Connection) =
  ## Compact consumed bytes and prepare the parser for a pipelined or
  ## subsequent keep-alive request.
  let consumed = c.parser.pos
  if consumed >= c.rlen:
    c.rlen = 0
  else:
    moveMem(addr c.rbuf[0], addr c.rbuf[consumed], c.rlen - consumed)
    c.rlen -= consumed
  c.chunkBody.setLen(0)
  c.urlCached = false
  c.queryCached = false
  c.jsonCached = false
  c.pathParams.setLen(0)
  c.responded = false
  c.sent100 = false
  c.awaitingResponse = false
  c.respStreaming = false
  c.respChunked = false
  c.respCLDelimited = false
  c.respComp = nil            # frees the streaming codec state (=destroy)
  c.respEnc = ""
  c.respBackedUp = false
  c.onRespDrain = nil
  c.reqStreaming = false
  c.bodyFed = 0
  c.onBodyCb = nil
  c.bodyDecoded.setLen(0)
  c.bodyDecodedSet = false
  c.parser.reset(0)

proc clear*(c: var Connection, initialBufSize: int) =
  ## Recycle a slot for a fresh connection (fd stays, gen already bumped).
  const shrinkThreshold = 256 * 1024
  if c.rbuf.len == 0 or c.rbuf.len > shrinkThreshold:
    c.rbuf = newString(initialBufSize)
  if c.wbuf.len > shrinkThreshold:
    c.wbuf.setLen(0)
    c.wbuf = ""
  c.wbuf.setLen(0)
  c.remoteAddr = ""
  c.rlen = 0
  c.wpos = 0
  c.chunkBody.setLen(0)
  c.bodyDecoded.setLen(0)
  c.bodyDecodedSet = false
  c.ssl = nil                # owner (closeConn) frees before recycling
  c.handshaking = false
  c.awaitingProxy = false
  c.alpn = ""
  c.h2 = nil
  c.ws = nil
  c.deadline = 0
  c.dlKind = dkNone
  c.writeArmed = false
  c.pinned = 0
  c.closeRequested = false
  c.urlCached = false
  c.queryCached = false
  c.jsonCached = false
  c.pathParams.setLen(0)
  c.responded = false
  c.sent100 = false
  c.awaitingResponse = false
  c.closeAfterFlush = false
  c.lingerClose = false
  c.peerHalfClosed = false
  c.respStreaming = false
  c.respChunked = false
  c.respCLDelimited = false
  c.respComp = nil
  c.respEnc = ""
  c.respBackedUp = false
  c.onRespDrain = nil
  c.reqStreaming = false
  c.bodyFed = 0
  c.onBodyCb = nil
  c.requestCount = 0
  c.parser.reset(0)
  c.state = csActive
