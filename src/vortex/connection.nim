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

  PinKind* = enum
    ## Why an outstanding worker task pins a connection/h3 slot (typed pin
    ## accounting). Every acquisition names its kind and every release must
    ## name the same kind, so a mismatched or double release is a caught
    ## defect instead of a silently-masked counter imbalance.
    pkBlocking,   ## sync `blocking:` / `blocking(args)` body, or the sendFile
                  ## INITIAL read (serveResolved reads request headers /
                  ## preconditions, so it is a normal pin); pauses input
    pkAwait,      ## awaitable `req.blocking`; held until its omBlockingDone
                  ## (the body's own responses carry release = prNone); pauses
                  ## input
    pkFileChunk,  ## sendFile chunk read (dispatchNextRead): the worker only
                  ## reads a file, never protocol state, so it does NOT pause
                  ## input -- h2 flow-control frames keep flowing mid-stream
    pkWsBlocking  ## h1 `ws.blocking` (stream 0); pauses ws frame dispatch

  PinRelease* = enum
    ## Which pin (if any) applying an outbox message releases. The message IS
    ## the release token: the trampoline that owns a worker task decides the
    ## kind once (Response.relKind), the emit path stamps it into exactly one
    ## message, and processOutbox releases exactly that -- no ambient
    ## thread-local state, no per-message-kind release rules to keep in sync.
    prNone,       ## releases nothing (ws frames, an awaitable body's own
                  ## responses, duplicate sends). The default.
    prBlocking,   ## releases one pkBlocking (a sync task's first response)
    prAwait,      ## releases one pkAwait (omBlockingDone only)
    prFileChunk,  ## releases one pkFileChunk (a chunk-read task's message)
    prWsBlocking  ## releases one pkWsBlocking (omWsDone, h1 stream 0)

  PinSet* = object
    ## Typed pin counts for one carrier (Connection / H3SlotEntry). A value
    ## embedded in both, so the `for k in PinKind` accounting lives once instead
    ## of being re-implemented per carrier. Loop-thread only; the counts are
    ## non-atomic int32.
    counts: array[PinKind, int32]

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
    release*: PinRelease      ## the pin this message releases when applied
                              ## (prNone = none). Exactly one message per pin
                              ## acquisition carries a non-prNone release: a
                              ## sync task's first response carries prBlocking,
                              ## a chunk read's omFileChunk carries prFileChunk,
                              ## an awaitable task's omBlockingDone carries
                              ## prAwait (its body's own responses carry
                              ## prNone -- releasing there too would double-dec
                              ## and free the slot under the worker, UAF), and
                              ## an h1 ws.blocking omWsDone carries prWsBlocking.

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

  RespFraming* = enum
    ## How an open HTTP/1 streaming response body is delimited.
    rfNone,           ## no streaming response open / framing not decided
    rfChunked,        ## Transfer-Encoding: chunked
    rfContentLength,  ## known Content-Length (keep-alive survives finish)
    rfCloseDelimited  ## HTTP/1.0 with unknown length; close ends the body

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

  RequestState* = object
    ## Per-request state common to every protocol carrier: the Connection for
    ## HTTP/1, an H2Stream, and an H3Stream each embed one as `rs`, so
    ## request.nim can resolve a single RequestState (see request.reqState)
    ## instead of re-implementing the h3/h2/h1 discrimination per accessor.
    ## Only the exact intersection lives here; carrier-specific request state
    ## (h1 sent100/respFraming, h2/h3 isHead/trailers/...) stays on the carrier.
    responded*: bool          ## current request has been answered
    urlCached*: bool          ## lazy per-request caches (see request.url)
    queryCached*: bool
    jsonCached*: bool
    cachedUrl*: Uri
    cachedQuery*: Table[string, string]
    cachedJson*: JsonNode
    pathParams*: PathParams   ## written by the router at match time
    respStreaming*: bool      ## a streamed response is open (res.sendHead)
    respComp*: RootRef        ## streaming compressor (Gzip/BrotliStream upcast);
                              ## nil = identity. Its =destroy frees the codec
                              ## state when the carrier is reset/deleted.
    respEnc*: string          ## "gzip"/"br" for respComp (empty = none)
    onRespDrain*: RespDrainCb ## streamed-response drain callback
    reqStreaming*: bool       ## dispatched early; body flows to onBody
    onBodyCb*: BodyCb         ## inbound streaming sink (req.onBody)
    bodyManualAck*: bool      ## defer flow-control credit to req.ackBody (the
                              ## async adapters set this; HTTP/1 then read-ahead-
                              ## bounds the socket, HTTP/2 the stream window)
    fwdCached*: bool          ## RFC 7239 Forwarded parsed once per request
    cachedForwarded*: seq[tuple[forr, proto, host: string]]
                              ## its elements, reused by forwardedProto/Host/clientIp

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
    pins*: PinSet
                              ## outstanding worker tasks by pin kind; the slot
                              ## can't recycle while any is held (totalPins).
                              ## pkFileChunk workers only read a file -- never
                              ## the HTTP/2 stream table -- so h2 input (flow
                              ## control frames, other streams' data) is safe to
                              ## process while only file pins are held
                              ## (inputPausePins excludes them). That keeps a
                              ## streamed response's own WINDOW_UPDATEs flowing
                              ## while it is mid-stream, instead of starving
                              ## them until the read unpins. Loop-thread only.
    flushHold*: int32         ## > 0 while a batch of loop-thread output is being
                              ## produced on this connection (a WebSocket read
                              ## batch, an outbox drain). Producers still append
                              ## to `wbuf`, but the opportunistic "push it to the
                              ## socket now" hook (LoopCore.hooks.flushHook) is
                              ## skipped, so N frames dispatched from one recv()
                              ## cost one send() instead of N (#333). Contract:
                              ## whoever takes a hold releases it in the same loop
                              ## turn (holdFlush/releaseFlushHold) and flushes once
                              ## when the count reaches 0; a direct flushOut is
                              ## always allowed (holding is an optimization, never
                              ## an ordering rule -- wbuf stays FIFO either way),
                              ## and the hook still flushes past respHighWater so a
                              ## handler that emits megabytes inside one dispatch
                              ## cannot buffer them all. Loop thread only.
    closeRequested*: bool     ## close deferred until unpinned
    rs*: RequestState         ## per-request state shared with the h2/h3 streams
    sent100*: bool            ## 100 Continue already sent for this request
    requestCount*: int        ## HTTP/1 requests served on this connection
    awaitingResponse*: bool   ## handler deferred; parsing is paused
    closeAfterFlush*: bool
    lingerClose*: bool        ## drain peer before close (reliable error delivery)
    peerHalfClosed*: bool     ## peer sent FIN (half-close): no more requests,
                              ## but a buffered one still gets its response
    # HTTP/1-only streaming state; the shared flags/callbacks live in `rs`.
    respFraming*: RespFraming ## how the open streaming body is delimited
    respBackedUp*: bool       ## write() reported backpressure; onDrain pending
    bodyFed*: int             ## body bytes already delivered to onBody
    bodyUnacked*: int         ## manualAck streaming body: bytes delivered to
                              ## onBody but not yet ackBody'd. Bounds read-ahead
                              ## so an async pull-reader (await req.read) can't
                              ## buffer the whole upload faster than it hashes.
    bodyReadPaused*: bool     ## reads paused: bodyUnacked hit the high-water, so
                              ## the socket recv loop stops pulling (kernel holds
                              ## the rest as TCP backpressure) until ackBody drains
                              ## the debt below the low-water. The fd stays armed;
                              ## the loop caps its selector wait while any such
                              ## connection exists so the async consumer still
                              ## drains on the pump (see eventloop bodyPausedConns)
    respContentLength*: int64 ## declared Content-Length of an open rfContentLength
                              ## streamed response (-1 = not length-delimited);
                              ## reconciled against respBodyWritten at finish()
    respBodyWritten*: int64   ## body bytes written so far on that stream (#248)

  H3SlotEntry* = object
    ## HTTP/3 connections aren't fd-backed; they live in per-loop slots.
    ## A Request handle encodes slot i as fd = -(i+2); see h3SlotFd/h3SlotOf.
    conn*: RootRef            ## http3.codec.H3Conn; nil = free slot
    gen*: uint32
    pins*: PinSet
                              ## outstanding worker tasks by pin kind. Same
                              ## type as Connection for one code path; the h3
                              ## shim is driven by h3Drive (no input pause), so
                              ## only totalPins is ever consulted here.
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

  LoopConfig* = object
    ## Read-only per-loop policy, populated once from `settings` when the loop
    ## starts. Grouped out of LoopCore's mutable/per-tick fields so the static
    ## knobs a Request consults live together. Loop-thread only (never mutated
    ## after start).
    maxWsMessage*: int        ## largest inbound WebSocket message (bytes)
    wsPingInterval*: int      ## WebSocket idle before a keepalive ping (0 disables)
    wsPongTimeout*: int       ## after a keepalive ping, seconds to wait for a reply
    wsCompression*: bool      ## negotiate permessage-deflate (only with -d:wsDeflate)
    compress*: bool           ## gzip/brotli eligible responses (needs the flags)
    decompressRequest*: bool  ## decode gzip/br/zstd request bodies into req.body
    maxDecompressedBody*: int ## cap on a decoded request body (decompression bomb)
    trustedProxies*: seq[string]  ## CIDR/IP allowlist; forwarded headers
                                  ## (X-Forwarded-*, RFC 7239) are honored only
                                  ## from a peer in this list (empty = none)

  AdapterHooks* = object
    ## The proc-pointer vtable an async adapter / the event loop registers on a
    ## LoopCore (all loop-thread only). Grouped so the hand-rolled hooks live in
    ## one place instead of loose fields on LoopCore.
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
    resumeBodyHook*: proc (loopPtr: pointer, fd: int32, gen: uint32,
                           n: int) {.nimcall, gcsafe.}
      ## HTTP/1 flow-control credit (req.ackBody) for a manualAck streaming
      ## body: subtract `n` consumed bytes from the connection's read-ahead
      ## debt and, if reads were paused at the high-water, resume them. Set by
      ## the event loop; the HTTP/2/3 windows have their own ack paths.
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
    config*: LoopConfig       ## read-only per-loop policy derived from settings
    wsIdle*: seq[RootRef]     ## h2/h3 WebSocket streams tracked for idle keepalive
                              ## (WsConn upcast; h1 uses the connection deadline wheel)
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
    hooks*: AdapterHooks      ## adapter/event-loop proc-pointer vtable (below)
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

func h3SlotFd*(slot: int): int32 {.inline.} =
  ## Encode h3 slot index `slot` as a Request-handle fd: a negative fd tags an
  ## h3 slot (not a socket); the -2 offset keeps -1 free as the conventional
  ## invalid-fd sentinel (e.g. "no HTTP/3" udpFd), so slot 0 encodes as -2.
  int32(-(slot + 2))

func h3SlotOf*(fd: int32): int {.inline.} =
  ## Decode a negative h3 Request-handle fd back to its slot index (inverse of
  ## h3SlotFd). Callers must bounds/gen-check the slot; only valid for fd < 0.
  int(-fd) - 2

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
  ## Queue a message for the owning loop, waking it only on the empty ->
  ## non-empty transition (#338): a worker streaming frames used to pay a wakeup
  ## write() per message and the loop woke for one-message batches. Coalescing is
  ## safe because `drain` empties the queue in one swap under the same lock:
  ##  * A push that finds the queue non-empty is covered by the trigger of the
  ##    push that made it non-empty. That trigger is either still pending (the
  ##    loop has not drained yet, and the drain takes this message too) or was
  ##    already consumed -- in which case the loop's drain runs after it, again
  ##    taking this message, since both the append and the drain hold the lock.
  ##  * A push that finds it empty always triggers, so the queue can never go
  ##    from empty to non-empty without a wakeup. The trigger is issued outside
  ##    the lock, so a thread descheduled between the two can delay a wakeup, but
  ##    never drop it: it always runs, and the next drain takes everything.
  ##  * The loop never sleeps holding messages: after `drain` the queue is empty,
  ##    so the next push is a transition and triggers.
  acquire ob.lock
  let wasEmpty = ob.msgs.len == 0
  ob.msgs.add msg
  release ob.lock
  if wasEmpty: trigger ob.ev

proc drain*(ob: ptr Outbox, into: var seq[OutMsg]) =
  ## Swap out all pending messages; `into` should be empty. Must take ALL of them
  ## (never a partial batch) -- push's wakeup coalescing above relies on the queue
  ## being empty when this returns.
  acquire ob.lock
  swap(into, ob.msgs)
  release ob.lock

func bodilessStatus*(code: int): bool {.inline.} =
  ## RFC 9110 8.6: 1xx, 204, and 304 responses carry no representation, so
  ## they must not advertise Content-Length (or Content-Type). Distinct from
  ## HEAD, which keeps the Content-Length a GET would have sent.
  code in 100 .. 199 or code == 204 or code == 304

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

proc setSlice(dst: var string, src: string, start, n: int) {.inline.} =
  ## Overwrite `dst` with src[start ..< start+n], reusing dst's existing buffer
  ## (no allocation once it is large enough).
  dst.setLen(n)
  if n > 0: copyMem(addr dst[0], unsafeAddr src[start], n)

proc unpackResponseInto*(data: string, contentType: var string,
                         headers: var seq[(string, string)]): int =
  ## Decode a packed response (see packResponse) into caller-owned, reusable
  ## buffers instead of freshly-allocated strings + seq, and return bodyStart.
  ## The loop drains many worker responses per wakeup; reusing one `contentType`
  ## string and one `headers` seq (whose slot strings are overwritten in place)
  ## makes that path allocation-free after warmup -- the former unpackResponse
  ## allocated the seq plus a substr per header name and value every time. The
  ## buffers are only valid until the next call, which is fine: the loop copies
  ## them into the write buffer / header block before draining the next message.
  ## Loop-thread only.
  var pos = 0
  let ctLen = int(getU32(data, pos)); pos += 4
  contentType.setSlice(data, pos, ctLen); pos += ctLen
  let n = int(getU32(data, pos)); pos += 4
  headers.setLen(n)                 # keeps the seq buffer + surviving slot strings
  for i in 0 ..< n:
    let nl = int(getU32(data, pos)); pos += 4
    headers[i][0].setSlice(data, pos, nl); pos += nl
    let vl = int(getU32(data, pos)); pos += 4
    headers[i][1].setSlice(data, pos, vl); pos += vl
  result = pos

proc conn*(core: ptr LoopCore, fd: int32, gen: uint32): ptr Connection =
  ## Resolve a (fd, gen) handle; nil if the connection is gone.
  if fd < 0 or int(fd) >= core.conns.len: return nil
  result = addr core.conns[int(fd)]
  if result.gen != gen or result.state == csFree: return nil

# --- typed pin accounting ---------------------------------------------------

func total*(ps: PinSet): int32 {.inline.} =
  ## Sum across every pin kind (the loop that used to be repeated per carrier).
  for k in PinKind: result += ps.counts[k]

func `[]`*(ps: PinSet, k: PinKind): int32 {.inline.} = ps.counts[k]
proc inc*(ps: var PinSet, k: PinKind) {.inline.} = inc ps.counts[k]
proc dec*(ps: var PinSet, k: PinKind) {.inline.} = dec ps.counts[k]
proc reset*(ps: var PinSet) {.inline.} =
  for k in PinKind: ps.counts[k] = 0

func totalPins*(c: Connection): int32 {.inline.} =
  ## Any outstanding worker task: the slot must not recycle, `conns` must not
  ## realloc, and the loop must not touch the carrier's ORC-counted protocol
  ## refs. Replaces every former `pinned > 0` gate.
  c.pins.total

func totalPins*(c: ptr Connection): int32 {.inline.} = totalPins(c[])

func totalPins*(s: H3SlotEntry): int32 {.inline.} = s.pins.total

func totalPins*(s: ptr H3SlotEntry): int32 {.inline.} = totalPins(s[])

func inputPausePins*(c: Connection): int32 =
  ## Pins that must pause input processing (their workers may read live
  ## request state: rbuf slices, the h2 stream table). Every kind except
  ## pkFileChunk -- file-chunk workers only read a file, so flow-control
  ## frames keep flowing while a streamed sendFile is mid-flight (the former
  ## `pinned > filePinned` gate).
  c.pins[pkBlocking] + c.pins[pkAwait] + c.pins[pkWsBlocking]

func inputPausePins*(c: ptr Connection): int32 {.inline.} = inputPausePins(c[])

func pinKindOf*(r: PinRelease): PinKind =
  ## The pin kind a non-prNone release names. Callers gate on prNone first.
  case r
  of prBlocking: pkBlocking
  of prAwait: pkAwait
  of prFileChunk: pkFileChunk
  of prWsBlocking: pkWsBlocking
  of prNone: raiseAssert "prNone names no pin kind"

var pinThreadId {.threadvar.}: int

proc onOwnLoopThread(core: ptr LoopCore): bool {.inline.} =
  ## Same cached-getThreadId pattern as request.currentThreadId (a syscall on
  ## Linux; caching matters on per-chunk paths).
  if pinThreadId == 0: pinThreadId = getThreadId()
  pinThreadId == core.threadId

proc acquirePin*(core: ptr LoopCore, c: ptr Connection, k: PinKind) {.inline.} =
  ## Pin `c` for one worker task of kind `k`. Loop thread only, by API
  ## contract; the doAssert turns the (unsupported) cross-thread acquisition --
  ## e.g. res.sendFile called from inside a `blocking:` body, a non-atomic
  ## int32 inc racing the loop -- from silent UB into a caught defect.
  doAssert onOwnLoopThread(core),
    "pins may only be acquired on the owning loop thread"
  c.pins.inc k

proc acquirePin*(core: ptr LoopCore, s: ptr H3SlotEntry,
                 k: PinKind) {.inline.} =
  doAssert onOwnLoopThread(core),
    "pins may only be acquired on the owning loop thread"
  s.pins.inc k

proc releasePin*(c: ptr Connection, k: PinKind) {.inline.} =
  ## Bare counter release (loop thread). Outbox message application must go
  ## through the eventloop wrapper, which adds the post-release hooks
  ## (deferred close, input resume); this primitive backs that wrapper and the
  ## same-stretch refusal path (request.undoPin), where no message applies.
  doAssert c.pins[k] > 0, "pin release without a matching acquire"
  c.pins.dec k

proc releasePin*(s: ptr H3SlotEntry, k: PinKind) {.inline.} =
  doAssert s.pins[k] > 0, "pin release without a matching acquire"
  s.pins.dec k

const fileChunkCap* = 256 * 1024
  ## Size of a pooled sendFile read buffer (one worker read hop). MUST stay >=
  ## staticfiles.fileStreamChunk (the bytes a hop reads into it); the two are
  ## kept equal. Larger chunks cut the per-hop reopen overhead (issue #274).

proc chunkTake*(p: var ChunkPool): pointer =
  ## Borrow a buffer for a file-read worker to fill (loop thread only).
  if p.free.len > 0: return p.free.pop()
  result = alloc(fileChunkCap)
  p.all.add result

const chunkPoolMaxFree* = 16
  ## Cap on idle pooled buffers kept per loop (16 x 256KiB = 4MiB). Without a cap
  ## the free-list floats to peak-ever concurrency and pins that memory for the
  ## loop's life after a burst subsides; buffers returned past the cap are freed.

proc chunkReturn*(p: var ChunkPool, buf: pointer) =
  ## Return a buffer after the loop copied it into the response (loop thread).
  ## Recycle up to the cap; free the rest so idle memory tracks current demand.
  if buf == nil: return
  if p.free.len < chunkPoolMaxFree:
    p.free.add buf
  else:
    dealloc(buf)
    for i in 0 ..< p.all.len:      # drop from the teardown list (small: ~peak concurrency)
      if p.all[i] == buf:
        p.all[i] = p.all[^1]; p.all.setLen(p.all.len - 1); break

proc chunkPoolFree*(p: var ChunkPool) =
  ## Free every pooled buffer at loop teardown (workers already joined).
  for b in p.all: dealloc(b)
  p.free.setLen 0
  p.all.setLen 0

const respHighWater* = 64 * 1024
  ## write() reports backpressure once the unsent backlog reaches this many
  ## bytes; the producer should pause and resume from onDrain. Lives here (not
  ## request.nim) so the HTTP/2 codec can apply the same connection-level cap.
  ## 64KiB (was 256KiB): the kernel socket send buffer already pipelines, so a
  ## smaller app-level high-water keeps the wire full while cutting the retained
  ## per-connection wbuf and per-stream pendingBody backlog ~4x (streamdownload
  ## RSS). Well above one segment batch, so streaming throughput is unaffected.

proc pendingOut*(c: ptr Connection): int {.inline.} =
  c.wbuf.len - c.wpos

proc holdFlush*(c: ptr Connection) {.inline.} =
  ## Take one flush hold for the batch about to run (see Connection.flushHold).
  ## Loop thread only; pair with releaseFlushHold in the same loop turn.
  inc c.flushHold

proc releaseFlushHold*(c: ptr Connection): bool {.inline.} =
  ## Drop one flush hold; true when it was the last one, i.e. the caller now owes
  ## the single end-of-batch flush. Nested holds (an outbox batch whose message
  ## resumes a WebSocket read batch) collapse to one flush, by the outermost.
  if c.flushHold > 0: dec c.flushHold
  c.flushHold == 0

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

proc resetRequest*(rs: var RequestState) =
  ## Clear every shared per-request field for carrier reuse. cachedUrl and
  ## cachedQuery deliberately keep their storage (the `urlCached`/`queryCached`
  ## flags guard reads, and the lazy caches overwrite in place on next use --
  ## see request.lazyQuery); cachedJson is dropped so a large parsed body is
  ## released between keep-alive requests.
  rs.responded = false
  rs.urlCached = false
  rs.queryCached = false
  rs.jsonCached = false
  rs.cachedJson = nil
  rs.pathParams.setLen(0)
  rs.respStreaming = false
  rs.respComp = nil           # frees the streaming codec state (=destroy)
  rs.respEnc = ""
  rs.onRespDrain = nil
  rs.reqStreaming = false
  rs.onBodyCb = nil
  rs.bodyManualAck = false
  rs.fwdCached = false        # keep cachedForwarded storage; overwritten on next use

proc resetRequestState(c: var Connection) =
  ## Clear the per-request fields shared by resetForNextRequest (keep-alive)
  ## and clear (slot recycling).
  c.chunkBody.setLen(0)
  c.bodyDecoded.setLen(0)
  c.bodyDecodedSet = false
  c.rs.resetRequest()
  c.sent100 = false
  c.awaitingResponse = false
  c.respFraming = rfNone
  c.respBackedUp = false
  c.bodyFed = 0
  c.bodyUnacked = 0
  c.bodyReadPaused = false
  c.respContentLength = -1
  c.respBodyWritten = 0
  c.parser.reset(0)

proc resetForNextRequest*(c: var Connection) =
  ## Compact consumed bytes and prepare the parser for a pipelined or
  ## subsequent keep-alive request.
  let consumed = c.parser.pos
  if consumed >= c.rlen:
    c.rlen = 0
  else:
    moveMem(addr c.rbuf[0], addr c.rbuf[consumed], c.rlen - consumed)
    c.rlen -= consumed
  c.resetRequestState()

proc clear*(c: var Connection, initialBufSize: int) =
  ## Recycle a slot for a fresh connection (fd stays, gen already bumped).
  const shrinkThreshold = 256 * 1024
  if c.rbuf.len == 0 or c.rbuf.len > shrinkThreshold:
    c.rbuf = newString(initialBufSize)
  if c.wbuf.len > shrinkThreshold:
    c.wbuf = ""
  c.wbuf.setLen(0)
  c.remoteAddr = ""
  c.rlen = 0
  c.wpos = 0
  c.ssl = nil                # owner (closeConn) frees before recycling
  c.handshaking = false
  c.awaitingProxy = false
  c.alpn = ""
  c.h2 = nil
  c.ws = nil
  c.deadline = 0
  c.dlKind = dkNone
  c.writeArmed = false
  # A recycled slot must never inherit pin residue (R4): leftover counts would
  # make totalPins/inputPausePins lie for the next occupant -- input running
  # under a live worker (UAF) or a permanently-paused fresh connection. A
  # nonzero count here means some release was mis-skipped upstream (e.g. by a
  # staleness-check bug); crash at the source in debug, scrub in release.
  doAssert c.totalPins == 0, "slot recycled with live worker pins"
  c.pins.reset()
  c.flushHold = 0            # a hold never outlives its loop turn; scrub anyway
  c.closeRequested = false
  c.closeAfterFlush = false
  c.lingerClose = false
  c.peerHalfClosed = false
  c.requestCount = 0
  c.resetRequestState()
  c.state = csActive
