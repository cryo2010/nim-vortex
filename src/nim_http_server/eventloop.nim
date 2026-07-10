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

proc monoSec(): int64 {.inline.} =
  getMonoTime().ticks div 1_000_000_000

proc newListenSocket*(settings: Settings): SocketHandle =
  ## Raw nonblocking listener fd. Plain data so it can cross threads;
  ## with reusePort every loop thread creates its own.
  let fd = createNativeSocket(Domain.AF_INET, SockType.SOCK_STREAM,
                              Protocol.IPPROTO_TCP)
  if fd == osInvalidSocket:
    raiseOSError(osLastError())
  var one = cint(1)
  discard setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                     addr one, SockLen(sizeof(one)))
  if settings.reusePort:
    discard setsockopt(fd, SOL_SOCKET, SO_REUSEPORT,
                       addr one, SockLen(sizeof(one)))
  let host = if settings.address.len > 0: settings.address else: "0.0.0.0"
  let ai = getAddrInfo(host, settings.port, Domain.AF_INET)
  let bindRes = bindAddr(fd, ai.ai_addr, SockLen(ai.ai_addrlen))
  freeAddrInfo(ai)
  if bindRes < 0:
    fd.close()
    raiseOSError(osLastError())
  if nativesockets.listen(fd, cint(settings.listenBacklog)) < 0:
    fd.close()
    raiseOSError(osLastError())
  fd.setBlocking(false)
  fd

proc newUdpSocket*(settings: Settings): SocketHandle =
  ## Nonblocking SO_REUSEPORT UDP socket for QUIC, bound like the TCP one.
  let fd = createNativeSocket(Domain.AF_INET, SockType.SOCK_DGRAM,
                              Protocol.IPPROTO_UDP)
  if fd == osInvalidSocket:
    raiseOSError(osLastError())
  var one = cint(1)
  discard setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                     addr one, SockLen(sizeof(one)))
  if settings.reusePort:
    discard setsockopt(fd, SOL_SOCKET, SO_REUSEPORT,
                       addr one, SockLen(sizeof(one)))
  let host = if settings.address.len > 0: settings.address else: "0.0.0.0"
  let ai = getAddrInfo(host, settings.port, Domain.AF_INET,
                       SockType.SOCK_DGRAM, Protocol.IPPROTO_UDP)
  let bindRes = bindAddr(fd, ai.ai_addr, SockLen(ai.ai_addrlen))
  freeAddrInfo(ai)
  if bindRes < 0:
    fd.close()
    raiseOSError(osLastError())
  fd.setBlocking(false)
  fd

proc boundPort*(fd: SocketHandle): Port =
  ## The actual bound port (useful after binding port 0 in tests).
  var sa: Sockaddr_in
  var saLen = SockLen(sizeof(sa))
  if getsockname(fd, cast[ptr SockAddr](addr sa), addr saLen) < 0:
    raiseOSError(osLastError())
  Port(nativesockets.ntohs(sa.sin_port))

proc refreshDate(loop: Loop) =
  let wallSec = getTime().toUnix
  if wallSec != loop.lastWallSec:
    loop.lastWallSec = wallSec
    loop.core.dateStr = httpDate(wallSec)

proc newLoop*(settings: Settings, handler: RequestHandler,
              stopFlag: ptr Atomic[bool], listenFd: SocketHandle,
              pool: pointer = nil, outbox: ptr Outbox = nil,
              tls: pointer = nil, quicCfg: pointer = nil,
              udpFd: SocketHandle = osInvalidSocket): Loop =
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
  result.core.serverHeader = settings.serverHeader
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

proc setDeadline(c: ptr Connection, loop: Loop, kind: DeadlineKind) =
  c.dlKind = kind
  let secs =
    case kind
    of dkHeader: loop.settings.headerTimeout
    of dkBody: loop.settings.bodyTimeout
    of dkIdle: loop.settings.keepAliveTimeout
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

proc armWrite(loop: Loop, c: ptr Connection) =
  if not c.writeArmed:
    c.writeArmed = true
    loop.selector.updateHandle(int(c.fd), {Event.Read, Event.Write})

proc disarmWrite(loop: Loop, c: ptr Connection) =
  if c.writeArmed:
    c.writeArmed = false
    loop.selector.updateHandle(int(c.fd), {Event.Read})

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
        loop.armWrite(c)
        return
      loop.closeConn(c)
      return
  c.wbuf.setLen(0)
  c.wpos = 0
  loop.disarmWrite(c)
  if c.closeAfterFlush:
    loop.closeConn(c)

proc respondError(loop: Loop, c: ptr Connection, code: HttpCode) =
  let msg = $code
  appendResponse(c.wbuf, code, loop.core.dateStr, loop.core.serverHeader,
                 "text/plain", msg, [], keepAlive = false, skipBody = false)
  c.responded = true
  c.closeAfterFlush = true
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
    let req = Request(core: addr loop.core, fd: c.fd, gen: c.gen,
                      stream: sid)
    try:
      {.gcsafe.}:
        loop.handler(req)
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
  c.h2 = newH2Conn(loop.settings.maxBodySize, loop.settings.maxHeaderSize)

proc processInput(loop: Loop, c: ptr Connection) =
  ## Parse and dispatch as many complete pipelined requests as the buffer
  ## holds. Parsing pauses while a response is outstanding (deferred
  ## handlers) so responses stay ordered.
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
      let req = Request(core: addr loop.core, fd: c.fd, gen: c.gen)
      try:
        {.gcsafe.}:
          loop.handler(req)
      except CatchableError:
        if not c.responded:
          loop.respondError(c, Http500)
          return
      if not c.responded:
        # Deferred response (worker pool / adapter); pause until respond.
        c.awaitingResponse = true
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

proc handleRead(loop: Loop, c: ptr Connection) =
  while true:
    if c.rlen == c.rbuf.len:
      # Flood guard: never buffer more than one max-size request head+body.
      if c.rlen > loop.settings.maxHeaderSize + loop.settings.maxBodySize:
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
      loop.closeConn(c)        # peer closed
      return
    else:
      let err = cint(osLastError())
      if err == EINTR: continue
      if err == EAGAIN or err == EWOULDBLOCK: break
      loop.closeConn(c)
      return
  loop.processInput(c)
  if c.state != csFree and (c.pendingOut > 0 or c.closeAfterFlush):
    loop.flushOut(c)

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
    if fd >= loop.core.conns.len:
      loop.core.conns.setLen(fd + 64)
    let c = addr loop.core.conns[fd]
    c.fd = int32(fd)
    c[].clear(loop.settings.initialBufferSize)
    when not defined(plainHttp):
      if loop.tls != nil:
        c.ssl = newTlsSession(cast[ptr TlsConfig](loop.tls), cint(fd))
        if c.ssl == nil:
          discard posix.close(client)
          inc c.gen
          c.state = csFree
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
        newH3Conn(connSsl, idx, loop.settings.maxBodySize)
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
            loop.handler(req)
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

proc sweepTimeouts(loop: Loop) =
  for i in 0 ..< loop.core.conns.len:
    let c = addr loop.core.conns[i]
    if c.state != csFree and c.deadline != 0 and
        c.deadline <= loop.core.nowSec:
      loop.closeConn(c)

proc tick(loop: Loop) =
  let now = monoSec()
  if now != loop.core.nowSec:
    loop.core.nowSec = now
    loop.refreshDate()
    loop.sweepTimeouts()

proc run*(loop: Loop) =
  loop.core.threadId = getThreadId()
  loop.core.kick = kickImpl
  loop.pumpCap = -1
  var keys: array[256, ReadyKey]
  while not loop.stopFlag[].load(moRelaxed):
    var timeoutMs = 1000
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
      if Event.Error in key.events:
        loop.closeConn(c)
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
        if Event.Read in key.events:
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
  when not defined(plainHttp):
    if loop.quicListener != nil:
      for i in 0 ..< loop.core.h3slots.len:
        loop.core.h3slots[i].pinned = 0
        loop.h3FreeSlot(i)
      quicFree(loop.quicListener)
      discard posix.close(cint(loop.udpFd))
  loop.selector.close()
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

proc runLoopThread*(arg: LoopThreadArg) {.thread, gcsafe.} =
  let loop = newLoop(arg.settings, arg.handler, arg.stopFlag, arg.listenFd,
                     arg.pool, arg.outbox, arg.tls, arg.quicCfg, arg.udpFd)
  loop.run()
