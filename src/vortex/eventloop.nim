## The per-thread event loop: kqueue/epoll readiness via std/selectors,
## nonblocking accept/read/write, request dispatch, and a coarse 1-second
## timeout sweep (slowloris protection without per-connection timers).

import std/[selectors, net, nativesockets, posix, httpcore, times, monotimes,
            atomics, oserrors]
import ./settings
import ./connection
import ./request
import ./http1/parser as h1parser
import ./http1/codec as h1codec
import ./http2/codec as h2codec
import ./websocket/codec as wscodec
from ./http2/frames import connectionPreface
when not defined(plainHttp):
  import ./transport/tls
  import ./transport/quic
  import ./http3/codec as h3codec

when defined(macosx):
  const SO_NOSIGPIPE = cint(0x1022)
when defined(linux):
  # MSG_NOSIGNAL; std/posix exports it as an importc var on some targets,
  # which cannot initialize a const. The value is uniform across Linux
  # architectures.
  const sendFlags = cint(0x4000)
else:
  const sendFlags = cint(0)

type
  FdKind = enum fkListen, fkClient, fkWakeup, fkQuic

  Loop* = ref object
    selector: Selector[FdKind]
    listenFd: int
    core*: LoopCore
    settings*: Settings
    limits: ParserLimits
    handler: RequestHandler
    stopFlag: ptr Atomic[bool]
    lastWallSec: int64
    pumpCap: int                 # adapter-suggested selector timeout cap
    outboxScratch: seq[OutMsg]   # reused drain buffer
    readyStreams: seq[uint32]    # reused h2 dispatch buffer
    tls: pointer                 # ptr TlsConfig; nil = plaintext
    udpFd: int                   # -1 = no HTTP/3
    quicListener: pointer        # SSL* listener
    h3Ready: seq[uint64]         # reused h3 dispatch buffer
    connCount: int               # live TCP connections (maxConnections cap)
    draining: bool               # graceful shutdown in progress
    drainDeadline: int64         # monotonic sec; force-close remaining after

proc monoSec(): int64 {.inline.} =
  getMonoTime().ticks div 1_000_000_000

proc openBoundSocket(host: string, port: Port, sockType: SockType,
                     proto: Protocol, reusePort: bool): SocketHandle =
  ## Resolve `host`, create a socket of the resolved address family, and bind
  ## it. An IPv6 wildcard ("::") is made dual-stack (IPV6_V6ONLY off) so it
  ## also accepts IPv4-mapped connections. Raises OSError on failure.
  let ai = getAddrInfo(host, port, Domain.AF_UNSPEC, sockType, proto)
  let fd = createNativeSocket(ai.ai_family, ai.ai_socktype, ai.ai_protocol)
  if fd == osInvalidSocket:
    freeAddrInfo(ai)
    raiseOSError(osLastError())
  var one = cint(1)
  discard setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                     addr one, SockLen(sizeof(one)))
  if reusePort:
    discard setsockopt(fd, SOL_SOCKET, SO_REUSEPORT,
                       addr one, SockLen(sizeof(one)))
  if ai.ai_family == posix.AF_INET6:
    var v6only = cint(0)               # accept IPv4-mapped too (dual-stack)
    discard setsockopt(fd, posix.IPPROTO_IPV6, posix.IPV6_V6ONLY,
                       addr v6only, SockLen(sizeof(v6only)))
  let bindRes = bindAddr(fd, ai.ai_addr, SockLen(ai.ai_addrlen))
  freeAddrInfo(ai)
  if bindRes < 0:
    fd.close()
    raiseOSError(osLastError())
  fd.setBlocking(false)
  fd

proc bindListener(settings: Settings, sockType: SockType,
                  proto: Protocol): SocketHandle =
  ## Bind with the configured address, or dual-stack ("::") by default.
  ## The default falls back to IPv4 ("0.0.0.0") on hosts without IPv6.
  let host = if settings.address.len > 0: settings.address else: "::"
  try:
    result = openBoundSocket(host, settings.port, sockType, proto,
                             settings.reusePort)
  except OSError:
    if settings.address.len > 0: raise
    result = openBoundSocket("0.0.0.0", settings.port, sockType, proto,
                             settings.reusePort)

proc newListenSocket*(settings: Settings): SocketHandle =
  ## Raw nonblocking listener fd. Plain data so it can cross threads;
  ## with reusePort every loop thread creates its own.
  result = bindListener(settings, SockType.SOCK_STREAM, Protocol.IPPROTO_TCP)
  if nativesockets.listen(result, cint(settings.listenBacklog)) < 0:
    result.close()
    raiseOSError(osLastError())

proc newUdpSocket*(settings: Settings): SocketHandle =
  ## Nonblocking SO_REUSEPORT UDP socket for QUIC, bound like the TCP one.
  bindListener(settings, SockType.SOCK_DGRAM, Protocol.IPPROTO_UDP)

proc boundPort*(fd: SocketHandle): Port =
  ## The actual bound port (useful after binding port 0 in tests). The port
  ## sits at the same offset in sockaddr_in and sockaddr_in6, so one cast
  ## works for both families.
  var sa: Sockaddr_storage
  var saLen = SockLen(sizeof(sa))
  if getsockname(fd, cast[ptr SockAddr](addr sa), addr saLen) < 0:
    raiseOSError(osLastError())
  Port(nativesockets.ntohs(cast[ptr Sockaddr_in](addr sa).sin_port))

proc refreshDate(loop: Loop) =
  let wallSec = getTime().toUnix
  if wallSec != loop.lastWallSec:
    loop.lastWallSec = wallSec
    loop.core.dateStr = httpDate(wallSec)

proc newLoop*(settings: Settings, handler: RequestHandler,
              stopFlag: ptr Atomic[bool], listenFd: SocketHandle,
              pool: pointer = nil, outbox: ptr Outbox = nil,
              tls: pointer = nil, quicCfg: pointer = nil,
              udpFd: SocketHandle = osInvalidSocket,
              streamRoute: StreamRouteCb = nil): Loop =
  result = Loop(
    selector: newSelector[FdKind](),
    listenFd: int(listenFd),
    settings: settings,
    limits: ParserLimits(
      maxHeaderSize: settings.maxHeaderSize,
      maxHeaderCount: settings.maxHeaderCount,
      maxBodySize: settings.maxBodySize),
    handler: handler,
    stopFlag: stopFlag,
    tls: tls,
    udpFd: -1)
  result.core.streamRoute = streamRoute
  result.core.serverHeader = settings.serverHeader
  result.core.maxWsMessage = settings.maxWsMessageSize
  result.core.wsPingInterval = settings.wsPingInterval
  result.core.wsCompression = settings.wsCompression
  result.core.nowSec = monoSec()
  result.core.pool = pool
  result.core.outbox = outbox
  result.core.loopPtr = cast[pointer](result)
  result.refreshDate()
  result.selector.registerHandle(listenFd, {Event.Read}, fkListen)
  if outbox != nil:
    result.selector.registerEvent(outbox.ev, fkWakeup)
  when not defined(plainHttp):
    if quicCfg != nil and udpFd != osInvalidSocket:
      result.quicListener = newQuicListener(
        cast[ptr TlsConfig](quicCfg), cint(udpFd))
      if result.quicListener != nil:
        result.udpFd = int(udpFd)
        result.selector.registerHandle(udpFd, {Event.Read}, fkQuic)
        result.core.altSvc = "h3=\":" & $int(settings.port) & "\"; ma=86400"

const drainTimeoutSec = 5    # bound on how long a lingering close waits

proc setDeadline(c: ptr Connection, loop: Loop, kind: DeadlineKind) =
  c.dlKind = kind
  let secs =
    case kind
    of dkHeader: loop.settings.headerTimeout
    of dkBody: loop.settings.bodyTimeout
    of dkIdle: loop.settings.keepAliveTimeout
    of dkDrain: drainTimeoutSec
    of dkWsPing: loop.settings.wsPingInterval
    of dkWsPong: loop.settings.wsPongTimeout
    of dkNone: 0
  c.deadline = if secs > 0: loop.core.nowSec + int64(secs) else: 0

proc closeConn(loop: Loop, c: ptr Connection) =
  if c.registered:
    loop.selector.unregister(int(c.fd))
    c.registered = false
  c.deadline = 0
  c.dlKind = dkNone
  if c.pinned > 0:
    # A worker still holds a Request handle into this slot: keep the fd
    # open (reserving the fd number and the slot) until it unpins.
    c.closeRequested = true
    c.state = csClosing
    return
  if c.ws != nil:
    wsClosed(addr loop.core, c)   # deliver onClose (1006 if no peer close)
  if c.h2 != nil:
    h2WsTeardownAll(c)            # onClose for every RFC 8441 WebSocket stream
  when not defined(plainHttp):
    if c.ssl != nil:
      if not c.handshaking:
        tlsShutdown(c.ssl)
      freeTlsSession(c.ssl)
      c.ssl = nil
  c.h2 = nil
  discard posix.close(cint(c.fd))
  inc c.gen
  c.state = csFree
  c.closeRequested = false
  dec loop.connCount

proc armWrite(loop: Loop, c: ptr Connection) =
  if not c.writeArmed:
    c.writeArmed = true
    loop.selector.updateHandle(int(c.fd), {Event.Read, Event.Write})

proc disarmWrite(loop: Loop, c: ptr Connection) =
  if c.writeArmed:
    c.writeArmed = false
    loop.selector.updateHandle(int(c.fd), {Event.Read})

proc beginLingerClose(loop: Loop, c: ptr Connection) =
  ## Half-close after flushing an error response, then drain the peer's
  ## remaining bytes so close() sends a clean FIN instead of a RST that
  ## would truncate the error the client hasn't read yet. Bounded by the
  ## drain deadline and the connection cap.
  when not defined(plainHttp):
    if c.ssl != nil:
      loop.closeConn(c)          # TLS has its own close_notify; skip drain
      return
  discard shutdown(SocketHandle(c.fd), cint(SHUT_WR))
  c.state = csDraining
  c.setDeadline(loop, dkDrain)

proc handleDrain(loop: Loop, c: ptr Connection) =
  ## Read and discard peer bytes until EOF (clean close) or the drain
  ## deadline; never processed as HTTP.
  var scratch: array[8192, char]
  while true:
    let n = recv(SocketHandle(c.fd), addr scratch[0], scratch.len, cint(0))
    if n > 0: continue
    elif n == 0:
      loop.closeConn(c)          # peer FIN: recv buffer empty, no RST
      return
    else:
      let err = cint(osLastError())
      if err == EINTR: continue
      if err == EAGAIN or err == EWOULDBLOCK: return
      loop.closeConn(c)
      return

proc flushOut(loop: Loop, c: ptr Connection) =
  ## Write as much pending output as the socket accepts; arm write
  ## interest only when the kernel buffer is full.
  while c.pendingOut > 0:
    when not defined(plainHttp):
      if c.ssl != nil:
        let (n, st) = tlsWrite(c.ssl, addr c.wbuf[c.wpos], c.pendingOut)
        case st
        of tlsOk:
          c.wpos += n
          continue
        of tlsWantWrite:
          if c.ws != nil: wsBackpressure(c)
          loop.armWrite(c)
          return
        of tlsWantRead:
          return               # retried after the next read event
        of tlsClosed, tlsError:
          loop.closeConn(c)
          return
    let n = send(SocketHandle(c.fd), addr c.wbuf[c.wpos],
                 c.pendingOut, sendFlags)
    if n > 0:
      c.wpos += n
    else:
      let err = cint(osLastError())
      if err == EINTR: continue
      if err == EAGAIN or err == EWOULDBLOCK:
        if c.ws != nil: wsBackpressure(c)
        loop.armWrite(c)
        return
      loop.closeConn(c)
      return
  c.wbuf.setLen(0)
  c.wpos = 0
  loop.disarmWrite(c)
  if c.closeAfterFlush:
    if c.lingerClose:
      loop.beginLingerClose(c)   # drain peer so the error is delivered
    else:
      loop.closeConn(c)
  elif c.ws != nil:
    wsDrained(addr loop.core, c)   # fire onDrain if this WS was backed up
  elif c.respStreaming and c.respBackedUp:
    c.respBackedUp = false
    if c.onRespDrain != nil:
      c.onRespDrain(addr loop.core, c.fd, c.gen, 0)  # resume a streamed body

proc respondError(loop: Loop, c: ptr Connection, code: HttpCode) =
  let msg = $code
  appendResponse(c.wbuf, code, loop.core.dateStr, loop.core.serverHeader,
                 "text/plain", msg, [], keepAlive = false, skipBody = false)
  c.responded = true
  c.closeAfterFlush = true
  c.lingerClose = true       # drain the peer so the error is delivered, no RST
  c.state = csClosing

proc h2Input(loop: Loop, c: ptr Connection) =
  ## Feed buffered bytes to the HTTP/2 codec and dispatch ready streams.
  if c.pinned > 0:
    # A worker holds a Request into this connection: pause input so the
    # streams table isn't mutated under it. Resumed after unpin.
    return
  loop.readyStreams.setLen(0)
  h2Feed(c, loop.readyStreams)
  for sid in loop.readyStreams:
    if c.state == csClosing: break
    # Rapid Reset: a stream can be RST in the same read batch after it was
    # queued as ready. Skip it so the handler (and any blocking: worker
    # task) never runs for an already-cancelled request.
    if not h2StreamAlive(c, sid): continue
    let req = Request(core: addr loop.core, fd: c.fd, gen: c.gen,
                      stream: sid)
    try:
      {.gcsafe.}:
        loop.handler(req, response(req))
    except CatchableError:
      applyResponse(addr loop.core, c, sid, 500, "text/plain", [],
                    "500 Internal Server Error")
  if c.state == csActive:
    if h2ActiveStreams(c) == 0:
      if c.dlKind != dkIdle:
        c.setDeadline(loop, dkIdle)
    else:
      c.deadline = 0
      c.dlKind = dkNone

proc initH2(loop: Loop, c: ptr Connection) =
  c.h2 = newH2Conn(addr loop.core,
                   loop.settings.maxBodySize, loop.settings.maxHeaderSize,
                   loop.settings.maxConcurrentStreams,
                   loop.settings.maxResetStreams,
                   loop.settings.maxControlFrames)

proc feedBody(loop: Loop, c: ptr Connection, last: bool) =
  ## Deliver newly-arrived request-body bytes to a streaming handler's onBody.
  ## `c.bodyFed` tracks how much has been delivered; `last` is set once the
  ## whole body is in so the final call carries the tail with last=true.
  if c.onBodyCb == nil: return
  let cb = c.onBodyCb
  if c.parser.chunked:
    # Decoded chunk bytes accumulate in c.chunkBody; end-of-body (the 0-chunk)
    # is only known when the parser reaches prComplete, i.e. `last`.
    let avail = c.chunkBody.len - c.bodyFed
    if avail <= 0 and not last: return
    if avail > 0:
      cb(toOpenArray(c.chunkBody, c.bodyFed, c.chunkBody.len - 1), last)
      c.bodyFed = c.chunkBody.len
    elif last:
      cb(toOpenArray(c.chunkBody, 0, -1), true)   # empty final chunk
  else:
    # Content-Length. Deliver the buffered body bytes, then drop them from rbuf
    # so an arbitrarily large upload streams in O(read-burst) memory instead of
    # being held whole. The parser stays authoritative: bodyStart is fixed and
    # the consumed count is subtracted from parser.bodyLen, so ppBody still
    # reaches prComplete when the final bytes arrive; parser.pos is set to the
    # tail so resetForNextRequest (here or via the deferred-resume path) drops
    # exactly the head + consumed body and keeps any pipelined next request.
    let bodyStart = c.parser.bodyStart
    let avail = min(c.rlen - bodyStart, c.parser.bodyLen)
    if avail <= 0:
      if last and c.parser.bodyLen == 0:
        cb(toOpenArray(c.rbuf, 0, -1), true)    # empty body
      return
    cb(toOpenArray(c.rbuf, bodyStart, bodyStart + avail - 1),
       avail == c.parser.bodyLen)
    let tailLen = c.rlen - (bodyStart + avail)
    if tailLen > 0:                              # a pipelined request follows
      moveMem(addr c.rbuf[bodyStart], addr c.rbuf[bodyStart + avail], tailLen)
    c.rlen = bodyStart + tailLen
    c.parser.bodyLen -= avail
    c.parser.pos = bodyStart                     # tail now begins here

proc startStreamingDispatch(loop: Loop, c: ptr Connection) =
  ## Dispatch a streaming route's handler at headers-complete so it can
  ## register `req.onBody` before the body arrives. Handles both
  ## Content-Length and chunked (Transfer-Encoding) request bodies.
  if not loop.core.streamRoute(addr loop.core, c.fd, c.gen, 0): return
  c.reqStreaming = true
  c.bodyFed = 0
  let req = Request(core: addr loop.core, fd: c.fd, gen: c.gen)
  try:
    {.gcsafe.}:
      loop.handler(req, response(req))
  except CatchableError:
    if not c.responded:
      loop.respondError(c, Http500)

proc processInput(loop: Loop, c: ptr Connection) =
  ## Parse and dispatch as many complete pipelined requests as the buffer
  ## holds. Parsing pauses while a response is outstanding (deferred
  ## handlers) so responses stay ordered.
  if c.ws != nil:
    # Pause frame dispatch while a ws.blocking worker holds the connection:
    # buffered frames wait until it unpins (one message at a time).
    if c.pinned == 0:
      wsInput(addr loop.core, c)
    return
  if c.h2 != nil:
    loop.h2Input(c)
    return
  if c.awaitingResponse or c.state == csClosing:
    return
  if not c.parser.started and c.rlen > 0 and c.rbuf[0] == 'P' and
      (c.ssl == nil or c.alpn == "h2"):
    # Possible h2 connection preface ("PRI * HTTP/2.0..."): prior
    # knowledge on cleartext, or ALPN-negotiated h2 after the handshake.
    var isPreface = true
    for i in 0 ..< min(c.rlen, connectionPreface.len):
      if c.rbuf[i] != connectionPreface[i]:
        isPreface = false
        break
    if isPreface:
      if c.rlen < connectionPreface.len:
        return                       # wait for the full preface
      loop.initH2(c)
      loop.h2Input(c)
      return
  while true:
    let res = c.parser.parse(c.rbuf, c.rlen, loop.limits, c.chunkBody)
    case res
    of prNeedMore:
      if c.parser.inBody:
        if c.parser.expectContinue and not c.sent100:
          c.sent100 = true
          c.wbuf.add continue100
        if c.dlKind != dkBody:
          c.setDeadline(loop, dkBody)
        # Streaming route: dispatch at headers-complete, then feed the body
        # incrementally to onBody instead of waiting for the whole request.
        if loop.core.streamRoute != nil and not c.reqStreaming and
            not c.responded:
          loop.startStreamingDispatch(c)
        if c.reqStreaming:
          loop.feedBody(c, last = false)
      elif c.rlen > c.parser.reqStart and c.dlKind != dkHeader:
        # Bytes of the next request head are pending.
        c.setDeadline(loop, dkHeader)
      return
    of prError:
      loop.respondError(c, c.parser.errorStatus)
      return
    of prComplete:
      c.deadline = 0
      c.dlKind = dkNone
      inc c.requestCount
      # Bound keep-alive request count: the last allowed request is answered
      # with Connection: close (respond reads keepAlive).
      if loop.settings.maxRequestsPerSocket > 0 and
          c.requestCount >= loop.settings.maxRequestsPerSocket:
        c.parser.keepAlive = false
      # A whole streaming request that arrived in one read never hit the
      # prNeedMore path, so try to dispatch it here (startStreamingDispatch
      # evaluates the predicate and sets reqStreaming only for a stream route).
      if not c.reqStreaming and loop.core.streamRoute != nil:
        loop.startStreamingDispatch(c)
      if c.reqStreaming:
        # Streaming handler already ran (early or just now): deliver the tail.
        loop.feedBody(c, last = true)
      else:
        let req = Request(core: addr loop.core, fd: c.fd, gen: c.gen)
        try:
          {.gcsafe.}:
            loop.handler(req, response(req))
        except CatchableError:
          if not c.responded:
            loop.respondError(c, Http500)
            return
      if not c.responded:
        # Deferred response (worker pool / adapter); pause until respond.
        c.awaitingResponse = true
        return
      if c.respStreaming:
        # A streaming response is open (sendHead sent, not finished): pause
        # the pipeline until finish() resumes it via kick.
        c.awaitingResponse = true
        return
      if c.ws != nil:
        # Handler upgraded to WebSocket: the 101 is queued; the loop
        # flushes it and all further bytes flow through wsInput.
        return
      if c.closeAfterFlush:
        c.state = csClosing
        return
      c[].resetForNextRequest()
      if c.rlen == 0:
        c.setDeadline(loop, dkIdle)
        return
      # Loop again: pipelined request already buffered.

proc resumeAfterRespond(loop: Loop, c: ptr Connection, stream: uint32) =
  ## Flush a response that was produced outside the dispatch call
  ## (worker outbox or same-thread async completion) and, for HTTP/1,
  ## resume the paused pipeline.
  if stream != 0:
    loop.flushOut(c)
    if c.state != csFree and c.pinned == 0:
      loop.processInput(c)       # resume input paused during pinning
      if c.state != csFree and c.pendingOut > 0:
        loop.flushOut(c)
  elif c.closeAfterFlush:
    c.state = csClosing
    loop.flushOut(c)
  else:
    c[].resetForNextRequest()
    loop.flushOut(c)
    if c.state == csFree: return
    loop.processInput(c)         # pipelined requests may be buffered
    if c.state == csFree: return
    if c.pendingOut > 0:
      loop.flushOut(c)
    if c.state == csActive and c.rlen == 0 and not c.awaitingResponse:
      c.setDeadline(loop, dkIdle)

proc kickImpl(loopPtr: pointer, fd: int32, gen: uint32,
              stream: uint32) {.nimcall, gcsafe.} =
  ## LoopCore.kick: adapters call this on the loop thread after a
  ## deferred respond. Redundant calls are harmless.
  {.gcsafe.}:
    let loop = cast[Loop](loopPtr)
    if fd < 0:
      return                     # h3 responses flush inside h3Respond
    let c = conn(addr loop.core, fd, gen)
    if c == nil: return
    if stream == 0 and not (c.awaitingResponse and c.responded):
      return                     # nothing deferred is pending
    loop.resumeAfterRespond(c, stream)

proc flushImpl(loopPtr: pointer, fd: int32, gen: uint32) {.nimcall, gcsafe.} =
  ## LoopCore.flushHook: write a connection's pending output now. Used by a
  ## loop-thread WebSocket send outside the read path.
  {.gcsafe.}:
    let loop = cast[Loop](loopPtr)
    let c = conn(addr loop.core, fd, gen)
    if c != nil and c.pendingOut > 0:
      loop.flushOut(c)

const h2RecvBufferCap = 1024 * 1024
  ## Hard ceiling on an HTTP/2 connection's receive buffer. With
  ## process-and-compact it is never approached in practice (a single
  ## frame is <= max frame size); it only bounds backpressure while a
  ## `blocking:` worker has the connection pinned.

proc handleRead(loop: Loop, c: ptr Connection) =
  while true:
    if c.rlen == c.rbuf.len:
      if c.h2 != nil:
        # HTTP/2: process buffered frames to compact consumed bytes, so the
        # receive buffer stays small regardless of total upload size and is
        # not clipped by a tight h1 body limit. Grow only if nothing could
        # be compacted (e.g. pinned by a worker), up to a hard ceiling.
        loop.processInput(c)
        if c.state != csActive: return
        if c.rlen == c.rbuf.len:
          if c.rbuf.len >= h2RecvBufferCap:
            loop.closeConn(c)
            return
          c.rbuf.setLen(c.rbuf.len * 2)
      else:
        # Flood guard on the receive buffer. A WebSocket frame can be as
        # large as one whole message; HTTP/1 never buffers more than a
        # single request head plus body. parseFrame rejects an oversized
        # frame from its length header before this cap is reached, so for
        # a WebSocket this is only a backstop.
        let cap =
          if c.ws != nil: loop.settings.maxWsMessageSize + 1024
          else: loop.settings.maxHeaderSize + loop.settings.maxBodySize
        if c.rlen > cap:
          loop.closeConn(c)
          return
        c.rbuf.setLen(c.rbuf.len * 2)
    let wanted = c.rbuf.len - c.rlen
    when not defined(plainHttp):
      if c.ssl != nil:
        # SSL buffers internally, so keep reading until WANT_READ; a
        # level-triggered fd event won't refire for buffered TLS data.
        let (n, st) = tlsRead(c.ssl, addr c.rbuf[c.rlen], wanted)
        case st
        of tlsOk:
          c.rlen += n
          continue
        of tlsWantRead:
          break
        of tlsWantWrite:
          loop.armWrite(c)
          break
        of tlsClosed, tlsError:
          loop.closeConn(c)
          return
    let n = recv(SocketHandle(c.fd), addr c.rbuf[c.rlen], wanted, cint(0))
    if n > 0:
      c.rlen += n
      if n < wanted:
        break                  # kernel buffer drained; skip the EAGAIN syscall
    elif n == 0:
      # Peer sent FIN. For HTTP/1 it may have half-closed its write side after
      # a complete request and is now waiting for the response (a legitimate
      # client pattern), so process what is buffered and close after replying
      # rather than dropping the request. h2/ws treat a bare FIN as the
      # connection going away.
      if c.h2 != nil or c.ws != nil:
        loop.closeConn(c)
        return
      c.peerHalfClosed = true
      break
    else:
      let err = cint(osLastError())
      if err == EINTR: continue
      if err == EAGAIN or err == EWOULDBLOCK: break
      loop.closeConn(c)
      return
  loop.processInput(c)
  if c.state != csFree and (c.pendingOut > 0 or c.closeAfterFlush):
    loop.flushOut(c)
  if c.peerHalfClosed and c.state == csActive and not c.respStreaming:
    # The peer will send no more requests: close once any response has been
    # written (the deferred/worker case sets closeAfterFlush and closes when
    # the response arrives). A streaming response is exempt -- the client may
    # half-close its write side and keep reading; finish() closes it.
    if c.awaitingResponse or c.pendingOut > 0:
      c.closeAfterFlush = true
    else:
      loop.closeConn(c)

when not defined(plainHttp):
  proc driveHandshake(loop: Loop, c: ptr Connection) =
    case tlsHandshake(c.ssl)
    of tlsOk:
      c.handshaking = false
      c.alpn = tlsSelectedAlpn(c.ssl)
      if c.alpn == "h2":
        loop.initH2(c)
      loop.disarmWrite(c)
      loop.handleRead(c)       # first request may already be buffered
    of tlsWantRead:
      discard                  # wait for the next read event
    of tlsWantWrite:
      loop.armWrite(c)
    of tlsClosed, tlsError:
      loop.closeConn(c)

proc handleAccept(loop: Loop) =
  while true:
    var sa: Sockaddr_storage
    var saLen = SockLen(sizeof(sa))
    let client = posix.accept(SocketHandle(loop.listenFd),
                              cast[ptr SockAddr](addr sa), addr saLen)
    if cint(client) < 0:
      let err = cint(osLastError())
      if err == EINTR: continue
      return                   # EAGAIN or transient error: back to the loop
    setBlocking(client, false)
    var one = cint(1)
    discard setsockopt(client, IPPROTO_TCP, TCP_NODELAY,
                       addr one, SockLen(sizeof(one)))
    when defined(macosx):
      discard setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE,
                         addr one, SockLen(sizeof(one)))
    let fd = int(client)
    # Connection cap: accept then immediately drop beyond the limit, which
    # keeps the accept queue clear rather than letting it back up.
    if loop.settings.maxConnections > 0 and
        loop.connCount >= loop.settings.maxConnections:
      discard posix.close(client)
      continue
    if fd >= loop.core.conns.len:
      loop.core.conns.setLen(fd + 64)
    let c = addr loop.core.conns[fd]
    c.fd = int32(fd)
    c[].clear(loop.settings.initialBufferSize)
    inc loop.connCount
    when not defined(plainHttp):
      if loop.tls != nil:
        c.ssl = newTlsSession(cast[ptr TlsConfig](loop.tls), cint(fd))
        if c.ssl == nil:
          discard posix.close(client)
          inc c.gen
          c.state = csFree
          dec loop.connCount
          continue
        c.handshaking = true
    c.setDeadline(loop, dkHeader)   # handshake counts toward header timeout
    loop.selector.registerHandle(client, {Event.Read}, fkClient)
    c.registered = true

when not defined(plainHttp):
  proc h3FreeSlot(loop: Loop, idx: int) =
    let slot = addr loop.core.h3slots[idx]
    if slot.pinned > 0:
      slot.closeReq = true
      return
    if slot.conn != nil:
      h3Free(H3Conn(slot.conn))
      slot.conn = nil
    inc slot.gen
    slot.closeReq = false

  proc h3Drive(loop: Loop) =
    ## Advance the QUIC stack: timers/retransmits, new connections, and
    ## all request streams; dispatch completed requests.
    quicHandleEvents(loop.quicListener)
    while true:
      let connSsl = quicAcceptConnection(loop.quicListener)
      if connSsl == nil: break
      var idx = -1
      for i in 0 ..< loop.core.h3slots.len:
        if loop.core.h3slots[i].conn == nil and
            loop.core.h3slots[i].pinned == 0:
          idx = i
          break
      if idx < 0:
        loop.core.h3slots.add H3SlotEntry()
        idx = loop.core.h3slots.len - 1
      loop.core.h3slots[idx].conn =
        newH3Conn(addr loop.core, connSsl, idx, loop.settings.maxBodySize,
                  loop.settings.maxConcurrentStreams)
    for idx in 0 ..< loop.core.h3slots.len:
      let slot = addr loop.core.h3slots[idx]
      if slot.conn == nil: continue
      if slot.closeReq:
        loop.h3FreeSlot(idx)
        continue
      if slot.pinned > 0: continue     # paused while a worker holds it
      let conn = H3Conn(slot.conn)
      if quicConnDead(conn.ssl):
        loop.h3FreeSlot(idx)
        continue
      loop.h3Ready.setLen(0)
      h3Pump(conn, loop.h3Ready)
      for sid in loop.h3Ready:
        let req = Request(core: addr loop.core, fd: int32(-(idx + 2)),
                          gen: slot.gen, stream: uint32(sid))
        try:
          {.gcsafe.}:
            loop.handler(req, response(req))
        except CatchableError:
          h3Apply(addr loop.core, int32(-(idx + 2)), slot.gen, uint32(sid),
                  500, "text/plain", [], "500 Internal Server Error")

proc processOutbox(loop: Loop) =
  ## Apply worker-produced responses: unpin, write out, resume parsing.
  loop.outboxScratch.setLen(0)
  drain(loop.core.outbox, loop.outboxScratch)
  var h3Touched = false
  for m in loop.outboxScratch.mitems:
    if m.fd < 0:
      when not defined(plainHttp):
        let idx = int(-m.fd) - 2
        if idx >= loop.core.h3slots.len: continue
        let slot = addr loop.core.h3slots[idx]
        # RFC 9220 WebSocket messages use per-stream pinning, not the slot
        # pin, so they route ahead of the omHttp response path.
        if slot.conn != nil and slot.gen == m.gen and
            m.kind in {omWs, omWsClose, omWsDone}:
          let conn = H3Conn(slot.conn)
          if m.kind == omWsDone:
            h3WsResume(addr loop.core, conn, uint64(m.stream))
          else:
            let w = wsConnForH3(addr loop.core, m.fd, m.gen, m.stream)
            if w != nil:
              wsFlushRaw(addr loop.core, nil, w, m.data, m.kind == omWsClose)
          h3Touched = true
          continue
        if slot.pinned > 0: dec slot.pinned
        if slot.gen != m.gen or slot.conn == nil: continue
        if slot.closeReq:
          if slot.pinned == 0: loop.h3FreeSlot(idx)
          continue
        let (contentType, headers, bodyStart) = unpackResponse(m.data)
        h3Apply(addr loop.core, m.fd, m.gen, m.stream, int(m.code),
                contentType, headers,
                m.data.toOpenArray(bodyStart, m.data.len - 1))
        h3Touched = true
      continue
    if int(m.fd) >= loop.core.conns.len: continue
    let c = addr loop.core.conns[int(m.fd)]
    if c.gen != m.gen or c.state == csFree: continue
    if m.kind == omWs or m.kind == omWsClose:
      # A WebSocket frame from an off-loop sender (already serialized): route
      # to the h1 connection or the h2 stream, then flush.
      let w = wsConnForStream(addr loop.core, c, m.stream)
      if w != nil:
        wsFlushRaw(addr loop.core, c, w, m.data, m.kind == omWsClose)
        loop.flushOut(c)
      continue
    if m.kind == omWsDone:
      # A ws.blocking worker finished: unpin and resume dispatching the
      # frames held back while it ran (connection pin for h1, stream for h2).
      if m.stream == 0:
        if c.pinned > 0: dec c.pinned
        if c.closeRequested:
          loop.closeConn(c)        # close was deferred while pinned
          continue
        if c.pinned == 0 and c.ws != nil:
          loop.processInput(c)     # dispatch the next buffered message
          if c.state != csFree and c.pendingOut > 0:
            loop.flushOut(c)
      else:
        let w = wsConnForStream(addr loop.core, c, m.stream)
        if w != nil:
          wsResume(addr loop.core, c, w)
          if c.state != csFree and c.pendingOut > 0:
            loop.flushOut(c)
      continue
    if c.pinned > 0: dec c.pinned
    if c.closeRequested:
      loop.closeConn(c)          # connection died while the task ran
      continue
    let (contentType, headers, bodyStart) = unpackResponse(m.data)
    applyResponse(addr loop.core, c, m.stream, int(m.code), contentType,
                  headers, m.data.toOpenArray(bodyStart, m.data.len - 1))
    loop.resumeAfterRespond(c, m.stream)
  when not defined(plainHttp):
    if h3Touched and loop.quicListener != nil:
      loop.h3Drive()             # flush unpinned conns, dispatch new work

proc sweepWsPing(loop: Loop, c: ptr Connection) =
  ## A WebSocket has been idle: send a keepalive ping and wait for any
  ## frame (pong or data) until the pong deadline, after which the peer is
  ## treated as gone.
  if c.ws == nil:
    loop.closeConn(c)
    return
  wsAppendPing(c)
  c.setDeadline(loop, dkWsPong)
  loop.flushOut(c)

proc sweepTimeouts(loop: Loop) =
  for i in 0 ..< loop.core.conns.len:
    let c = addr loop.core.conns[i]
    if c.state == csFree or c.deadline == 0 or c.deadline > loop.core.nowSec:
      continue
    if c.dlKind == dkWsPing:
      loop.sweepWsPing(c)          # idle: ping, then wait for the pong
    else:
      loop.closeConn(c)            # includes dkWsPong: no reply, peer is gone

proc tick(loop: Loop) =
  let now = monoSec()
  if now != loop.core.nowSec:
    loop.core.nowSec = now
    loop.refreshDate()
    loop.sweepTimeouts()

# --- graceful shutdown ------------------------------------------------------

proc activeH3Conns(loop: Loop): int =
  when not defined(plainHttp):
    for slot in loop.core.h3slots:
      if slot.conn != nil: inc result

proc markDrain(loop: Loop, c: ptr Connection) =
  ## Signal one TCP connection to finish its in-flight work and close.
  if c.state != csActive: return
  if c.h2 != nil:
    h2Goaway(c)                           # refuse new streams, send GOAWAY
    if h2ActiveStreams(c) == 0:
      c.closeAfterFlush = true
    loop.flushOut(c)
  elif c.ws != nil:
    # HTTP/1 WebSocket: server-initiated 1001 (going away) close handshake.
    wscodec.close(WebSocket(core: addr loop.core, fd: c.fd, gen: c.gen,
                            stream: 0), 1001, "going away")
  elif c.awaitingResponse or c.pendingOut > 0:
    c.parser.keepAlive = false            # finish the in-flight response, then close
    c.closeAfterFlush = true
    loop.flushOut(c)
  else:
    loop.closeConn(c)                     # idle keep-alive / partial request

proc beginDrain(loop: Loop) =
  ## Enter graceful shutdown: stop accepting, tell live connections to finish,
  ## and arm the grace deadline.
  loop.draining = true
  if loop.listenFd >= 0:
    try: loop.selector.unregister(loop.listenFd)
    except CatchableError: discard
    discard posix.close(cint(loop.listenFd))   # free the port for a replacement
    loop.listenFd = -1
  for fd in 0 ..< loop.core.conns.len:
    loop.markDrain(addr loop.core.conns[fd])
  when not defined(plainHttp):
    for slot in loop.core.h3slots:
      if slot.conn != nil: h3Goaway(H3Conn(slot.conn))   # RFC 9114 GOAWAY
  let grace = max(0, loop.settings.shutdownGrace)
  loop.drainDeadline = loop.core.nowSec + int64(grace)

proc drainSweep(loop: Loop) =
  ## Close connections that finished their in-flight work this iteration.
  for fd in 0 ..< loop.core.conns.len:
    let c = addr loop.core.conns[fd]
    if c.state != csActive: continue
    if c.h2 != nil:
      if h2Conn(c).goingAway and h2ActiveStreams(c) == 0:
        if c.pendingOut > 0: c.closeAfterFlush = true
        else: loop.closeConn(c)
    elif c.ws == nil and not c.awaitingResponse and c.pendingOut == 0:
      loop.closeConn(c)                   # h1 became idle after its response
  when not defined(plainHttp):
    for i in 0 ..< loop.core.h3slots.len:
      let slot = addr loop.core.h3slots[i]
      if slot.conn != nil and H3Conn(slot.conn).h3StreamCount == 0:
        loop.h3FreeSlot(i)                # no in-flight request streams left

proc forceCloseAll(loop: Loop) =
  ## Grace expired: drop whatever is still open.
  for fd in 0 ..< loop.core.conns.len:
    let c = addr loop.core.conns[fd]
    if c.state != csFree:
      c.pinned = 0
      loop.closeConn(c)
  when not defined(plainHttp):
    for i in 0 ..< loop.core.h3slots.len:
      loop.core.h3slots[i].pinned = 0
      loop.h3FreeSlot(i)

proc drainDone(loop: Loop): bool {.inline.} =
  loop.connCount == 0 and loop.activeH3Conns == 0

proc run*(loop: Loop) =
  loop.core.threadId = getThreadId()
  loop.core.kick = kickImpl
  loop.core.flushHook = flushImpl
  installWsHooks(addr loop.core)   # h2 WebSocket (RFC 8441) stream lookup
  when not defined(plainHttp):
    installH3WsHooks(addr loop.core)   # h3 WebSocket (RFC 9220) stream lookup
  loop.pumpCap = -1
  var keys: array[256, ReadyKey]
  while true:
    if loop.stopFlag[].load(moRelaxed) and not loop.draining:
      loop.tick()                     # refresh nowSec before arming the deadline
      loop.beginDrain()
    if loop.draining and loop.drainDone():
      break
    var timeoutMs = 1000
    if loop.draining:
      timeoutMs = 100                 # check the grace deadline promptly
    if loop.pumpCap >= 0:
      # An adapter has pending async operations: bound the wait so
      # timer/IO completions from its dispatcher aren't starved.
      timeoutMs = min(timeoutMs, max(1, loop.pumpCap))
    when not defined(plainHttp):
      if loop.quicListener != nil:
        let qt = quicEventTimeoutMs(loop.quicListener)
        if qt >= 0:
          timeoutMs = max(1, min(timeoutMs, qt))
    var n = 0
    try:
      n = loop.selector.selectInto(timeoutMs, keys)
    except IOSelectorsException, OSError:
      continue                 # interrupted by a signal
    var quicWork = false
    for i in 0 ..< n:
      let key = keys[i]
      if Event.User in key.events:
        loop.processOutbox()
        continue
      if key.fd == loop.listenFd:
        loop.handleAccept()
        continue
      if key.fd == loop.udpFd:
        quicWork = true
        continue
      if key.fd >= loop.core.conns.len:
        continue
      let c = addr loop.core.conns[key.fd]
      if c.state == csFree:
        continue
      if c.state == csDraining:
        loop.handleDrain(c)      # read-discard until EOF/deadline, then close
        continue
      try:
        when not defined(plainHttp):
          if c.handshaking:
            loop.driveHandshake(c)
            continue
        if Event.Write in key.events:
          loop.flushOut(c)
          if c.state == csFree:
            continue
        # A peer FIN arrives as Event.Error (kqueue EV_EOF) alongside any
        # buffered request. Read it -- handleRead drains the request, responds,
        # and closes gracefully on the EOF -- rather than resetting, which
        # would discard a response the peer half-closed to wait for.
        if Event.Read in key.events or Event.Error in key.events:
          loop.handleRead(c)
      except Exception:
        # A per-connection bug must never take down the loop thread.
        if c.state != csFree:
          loop.closeConn(c)
    when not defined(plainHttp):
      if loop.quicListener != nil:
        # Drive QUIC on datagrams, timer expiry, and every wakeup: the
        # stack owns its own retransmission/idle timers.
        discard quicWork
        try:
          loop.h3Drive()
        except Exception:
          discard
    if loop.core.pumpHook != nil:
      # Pump at the end of the iteration so callbacks scheduled while
      # handling this batch (e.g. an await that completed immediately)
      # finish in the same pass instead of after a selector timeout.
      loop.pumpCap = loop.core.pumpHook()
    loop.tick()
    if loop.draining:
      loop.drainSweep()               # close connections that just finished
      if loop.drainDone():
        break
      if loop.core.nowSec >= loop.drainDeadline:
        loop.forceCloseAll()          # grace expired: drop the rest
        break
  when not defined(plainHttp):
    if loop.quicListener != nil:
      for i in 0 ..< loop.core.h3slots.len:
        loop.core.h3slots[i].pinned = 0
        loop.h3FreeSlot(i)
      quicFree(loop.quicListener)
      discard posix.close(cint(loop.udpFd))
  loop.selector.close()
  if loop.listenFd >= 0:                 # beginDrain may have closed it already
    discard posix.close(cint(loop.listenFd))

type LoopThreadArg* = tuple
  ## Plain-data bundle for starting a loop on its own thread; the Loop
  ## itself is constructed inside the thread (refs never cross threads).
  ## The outbox is created by the caller (see connection.newOutbox) and
  ## freed by the caller after workers and loops have stopped.
  settings: Settings
  handler: RequestHandler
  stopFlag: ptr Atomic[bool]
  listenFd: SocketHandle
  pool: pointer
  outbox: ptr Outbox
  tls: pointer
  quicCfg: pointer
  udpFd: SocketHandle
  streamRoute: StreamRouteCb

proc runLoopThread*(arg: LoopThreadArg) {.thread, gcsafe.} =
  let loop = newLoop(arg.settings, arg.handler, arg.stopFlag, arg.listenFd,
                     arg.pool, arg.outbox, arg.tls, arg.quicCfg, arg.udpFd,
                     arg.streamRoute)
  loop.run()
