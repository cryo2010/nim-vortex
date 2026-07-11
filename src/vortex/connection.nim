## Per-connection state. Connections live in a fixed pool indexed by fd;
## slots are recycled with a generation counter so late responses (from
## worker threads or deferred handlers) can never touch a connection that
## has since been closed and reused.

import std/[locks, uri, tables]
from std/selectors import SelectEvent, trigger, newSelectEvent, close
import ./http1/parser

type
  PathParams* = seq[(string, string)]
    ## Route parameters captured by the router; exposed as req.params.

  OutMsg* = object
    ## A response produced off-loop (worker thread), routed back to the
    ## owning event loop in protocol-neutral packed form (see packResponse);
    ## the loop serializes it as HTTP/1 bytes or HTTP/2 frames.
    fd*: int32
    gen*: uint32
    stream*: uint32           ## 0 for HTTP/1
    code*: int32
    data*: string             ## packed contentType + headers + body

  Outbox* = object
    ## MPSC channel into an event loop: workers push, the loop drains on
    ## its wakeup event. Lives in shared memory (createShared).
    lock*: Lock
    msgs*: seq[OutMsg]
    ev*: SelectEvent

  ConnState* = enum
    csFree,      ## slot unused
    csActive,    ## reading/handling requests
    csClosing    ## flush pending output, then close

  DeadlineKind* = enum
    dkNone, dkHeader, dkBody, dkIdle

  Connection* = object
    fd*: int32
    gen*: uint32              ## bumped on close; part of the Request handle
    state*: ConnState
    rbuf*: string             ## receive buffer (grows, reused)
    rlen*: int                ## valid bytes in rbuf
    wbuf*: string             ## pending output
    wpos*: int                ## bytes of wbuf already written to the socket
    parser*: RequestParser
    chunkBody*: string        ## decoded chunked request body (reused)
    ssl*: pointer             ## SSL* for TLS connections, nil for plaintext
    handshaking*: bool        ## TLS handshake still in progress
    alpn*: string             ## negotiated protocol ("" until known)
    h2*: RootRef              ## http2.codec.H2Conn; nil = HTTP/1 (loop-only)
    deadline*: int64          ## coarse monotonic seconds; 0 = no timeout
    dlKind*: DeadlineKind
    writeArmed*: bool         ## selector currently watching writability
    registered*: bool         ## fd registered with the selector
    pinned*: int32            ## outstanding worker tasks; slot can't recycle
    closeRequested*: bool     ## close deferred until unpinned
    responded*: bool          ## current request has been answered
    sent100*: bool            ## 100 Continue already sent for this request
    urlCached*: bool          ## lazy per-request caches (see request.url)
    queryCached*: bool
    cachedUrl*: Uri
    cachedQuery*: Table[string, string]
    pathParams*: PathParams   ## written by the router at match time
    awaitingResponse*: bool   ## handler deferred; parsing is paused
    closeAfterFlush*: bool

  H3SlotEntry* = object
    ## HTTP/3 connections aren't fd-backed; they live in per-loop slots.
    ## A Request handle encodes slot i as fd = -(i+2).
    conn*: RootRef            ## http3.codec.H3Conn; nil = free slot
    gen*: uint32
    pinned*: int32            ## outstanding worker tasks
    closeReq*: bool           ## free deferred until unpinned

  LoopCore* = object
    ## The part of an event loop's state that `Request` handles must reach:
    ## connection slots plus per-loop cached strings. Lives inside the Loop
    ## object (stable address for the server's lifetime).
    conns*: seq[Connection]
    h3slots*: seq[H3SlotEntry]
    altSvc*: string           ## advertised on h1/h2 responses when h3 is on
    dateStr*: string          ## cached RFC 7231 date, refreshed once/second
    serverHeader*: string
    nowSec*: int64            ## coarse monotonic seconds, updated per tick
    threadId*: int            ## owning thread; respond() routes on this
    pool*: pointer            ## ptr WorkerPool (untyped to avoid a cycle)
    outbox*: ptr Outbox
    # Async-adapter integration (see adapters/). All loop-thread only.
    loopPtr*: pointer         ## the owning Loop, for kick
    pumpHook*: proc (): int {.nimcall, gcsafe.}
      ## Registered by an adapter; called once per loop iteration to run
      ## ready async callbacks. Returns a max selector timeout in ms, or
      ## -1 for no constraint.
    kick*: proc (loopPtr: pointer, fd: int32, gen: uint32,
                 stream: uint32) {.nimcall, gcsafe.}
      ## Flush/resume after a deferred same-thread respond (async
      ## completion). Set by the event loop; safe to call redundantly.

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

proc pendingOut*(c: ptr Connection): int {.inline.} =
  c.wbuf.len - c.wpos

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
  c.pathParams.setLen(0)
  c.responded = false
  c.sent100 = false
  c.awaitingResponse = false
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
  c.rlen = 0
  c.wpos = 0
  c.chunkBody.setLen(0)
  c.ssl = nil                # owner (closeConn) frees before recycling
  c.handshaking = false
  c.alpn = ""
  c.h2 = nil
  c.deadline = 0
  c.dlKind = dkNone
  c.writeArmed = false
  c.pinned = 0
  c.closeRequested = false
  c.urlCached = false
  c.queryCached = false
  c.pathParams.setLen(0)
  c.responded = false
  c.sent100 = false
  c.awaitingResponse = false
  c.closeAfterFlush = false
  c.parser.reset(0)
  c.state = csActive
