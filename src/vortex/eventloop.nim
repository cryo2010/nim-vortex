## The per-thread event loop: kqueue/epoll readiness via std/selectors,
## nonblocking accept/read/write, request dispatch, and a coarse 1-second
## timeout sweep (slowloris protection without per-connection timers).

import std/[selectors, httpcore, times, monotimes, atomics, oserrors]
when defined(nimdoc):
  # `nim doc` defines `nimdoc`, which flips std/net & std/nativesockets to their
  # winlean (Windows) socket types so Windows APIs document on any host -- that
  # collides with the std/posix syscalls this module uses (SocketHandle,
  # Sockaddr_*, SockLen, recv/send/setsockopt/... exist in both winlean and
  # posix). For doc builds ONLY, take the platform socket types from posix (one
  # consistent family) and stub the nativesockets handle-returning helpers to
  # posix types so the bodies type-check. The real build (`else`) is unchanged.
  import std/nativesockets except SocketHandle, AddrInfo, SockAddr, SockLen,
    Sockaddr_in, Sockaddr_storage, MSG_PEEK, SOL_SOCKET, SO_REUSEADDR,
    SO_REUSEPORT, close, createNativeSocket, getAddrInfo, freeAddrInfo,
    bindAddr, setBlocking, osInvalidSocket, getAddrString
  import std/posix
  proc getAddrString(sockAddr: ptr SockAddr): string = ""
  const osInvalidSocket = SocketHandle(-1)
  proc createNativeSocket(domain, sockType, protocol: cint): SocketHandle =
    SocketHandle(-1)
  proc getAddrInfo(address: string, port: Port, domain = Domain.AF_INET,
                   sockType = SockType.SOCK_STREAM,
                   protocol = Protocol.IPPROTO_TCP): ptr AddrInfo = nil
  proc freeAddrInfo(ai: ptr AddrInfo) = discard
  proc bindAddr(socket: SocketHandle, name: ptr SockAddr,
                namelen: SockLen): cint = 0
  proc setBlocking(socket: SocketHandle, blocking: bool) = discard
  proc close(socket: SocketHandle) = discard   # nativesockets' close is void
else:
  import std/[net, nativesockets, posix]
import ./settings
import ./connection
import ./request
import ./proxyprotocol
import ./http1/parser as h1parser
import ./http1/codec as h1codec
import ./http2/codec as h2codec
import ./websocket/codec as wscodec
from ./http2/frames import connectionPreface
when not defined(plainHttp):
  import ./transport/tls
  import ./http3/ngtcp2/backend as h3codec   # HTTP/3 over ngtcp2 + nghttp3

  proc tlsVerifyMode*(v: ClientVerify): cint =
    ## Map the public verify enum to OpenSSL's SSL_VERIFY_* mode.
    case v
    of ClientVerify.None: TlsVerifyNone
    of ClientVerify.Optional: TlsVerifyOptional
    of ClientVerify.Require: TlsVerifyRequire

  proc toSniCerts*(s: VortexConfig): seq[SniCert] =
    ## Convert the plain-data SNI entries into TLS-layer SniCerts.
    for e in s.sni:
      result.add SniCert(host: e.host, material: TlsMaterial(
        certFile: e.certFile, keyFile: e.keyFile, certPem: e.certPem,
        keyPem: e.keyPem, pkcs12File: e.pkcs12File, pkcs12: e.pkcs12,
        keyPassword: e.keyPassword))

  proc tlsMaxVer*(v: TlsVersion): clong =
    ## Map the max-version enum to an OpenSSL version number (0 = no cap).
    case v
    of TlsVersion.None: 0
    of TlsVersion.V12: TLS1_2_VERSION
    of TlsVersion.V13: TLS1_3_VERSION

  proc ocspBytes*(s: VortexConfig): string =
    ## The DER OCSP response to staple: in-memory bytes, else the file, else "".
    if s.ocspResponse.len > 0: s.ocspResponse
    elif s.ocspFile.len > 0:
      try: readFile(s.ocspFile) except CatchableError: ""
    else: ""

  proc ocspSourceFile*(s: VortexConfig): string =
    ## The staple's source path to remember for empty-arg reload re-reads: "" when
    ## in-memory `ocspResponse` takes precedence (it has no file to re-read).
    if s.ocspResponse.len > 0: "" else: s.ocspFile

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
    settings*: VortexConfig
    limits: ParserLimits
    handlerRaw: RawClosure       # the request handler as a raw (proc, env) pair
                                 # so it never refcounts across loop threads
                                 # (see RawClosure); kept alive by the traced
                                 # copy in LoopThreadArg.
    stopFlag: ptr Atomic[bool]
    lastWallSec: int64
    pumpCap: int                 # adapter-suggested selector timeout cap
    outboxScratch: seq[OutMsg]   # reused drain buffer
    pendingFlush: seq[(int32, uint32)]
                                 # connections holding a flush for the outbox
                                 # batch being applied (one entry per hold taken,
                                 # so the counts always balance); drained at the
                                 # end of processOutbox, which flushes each
                                 # connection once (#333)
    readyStreams: seq[uint32]    # reused h2 dispatch buffer
    unpackCt: string             # reused worker-response unpack buffers, so
    unpackHeaders: seq[(string, string)]  # draining the outbox allocates no
                                 # per-header string/seq (see unpackResponseInto)
    tls: pointer                 # ptr TlsConfig; nil = plaintext
    udpFd: int                   # -1 = no HTTP/3
    quicReload: pointer          # ptr CertReload: main-thread reload signal
    quicReloadSeen: int          # last reload generation this loop applied
    connCount: int               # live TCP connections (maxConnections cap)
    draining: bool               # graceful shutdown in progress
    drainDeadline: int64         # monotonic sec; force-close remaining after
    asyncDrainDeadline: int64    # monotonic sec; bound the wait for pending async
                                 # continuations once all connections are gone
    warnedDrainStuck: bool       # one-time warning emitted when graceful
                                 # shutdown is blocked by a still-running worker
    acceptSuspendedUntil: int64  # monotonic sec; while > nowSec the listener is
                                 # deregistered after an fd/memory-exhaustion
                                 # accept() error (EMFILE/ENFILE/...), then
                                 # re-armed in tick(). 0 = listener armed.
    bodyPausedConns: int         # HTTP/1 streaming connections whose socket read
                                 # is paused at the read-ahead high-water (the recv
                                 # loop stops pulling; the fd stays armed). While
                                 # > 0 the selector wait is capped short so the
                                 # async pump keeps draining the consumer (whose
                                 # ack un-pauses the read); without the cap an idle
                                 # dispatcher would only wake on the 1s tick and
                                 # stall the drain (see the select below).

when defined(linux):
  const clockMonotonicCoarse = ClockId(6)
    ## CLOCK_MONOTONIC_COARSE (Linux 2.6.32+, stable kernel ABI value 6): a
    ## cheaper, vDSO-served monotonic clock. tick() only needs whole seconds, so
    ## its coarser (~jiffy) resolution is irrelevant; this avoids the finer
    ## CLOCK_MONOTONIC read getMonoTime() does on every loop iteration. Hardcoding
    ## the value (vs importing the C macro) keeps it independent of feature-test
    ## macros. Falls back to getMonoTime if the call ever fails.
  proc monoSec(): int64 {.inline.} =
    var ts: Timespec
    if clock_gettime(clockMonotonicCoarse, ts) == 0:
      return int64(clong(ts.tv_sec))
    getMonoTime().ticks div 1_000_000_000
else:
  proc monoSec(): int64 {.inline.} =
    getMonoTime().ticks div 1_000_000_000

proc callHandler(loop: Loop, req: Request, res: Response) {.inline.} =
  ## Invoke the request handler from its raw (proc, env) pair. This is exactly
  ## how the compiler calls a closure -- prc(args..., env) -- so it works for
  ## both a capturing closure (router.toHandler) and a bare top-level proc
  ## (nil env, ignored), without touching any refcount. See RawClosure.
  when defined(httpGzip) or defined(httpBrotli) or defined(httpZstd):
    # Transparently decode a gzip/br/zstd request body (opt-in) before dispatch; a
    # bomb/corrupt body is rejected (413/400) without running the handler. No-op
    # for streaming routes (their body isn't buffered here).
    if not decodeRequestBody(req, res): return
  cast[proc (req: Request, res: Response, env: pointer) {.nimcall, gcsafe.}](
    loop.handlerRaw.prc)(req, res, loop.handlerRaw.env)

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

proc bindListener(settings: VortexConfig, sockType: SockType,
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

proc newListenSocket*(settings: VortexConfig): SocketHandle =
  ## Raw nonblocking listener fd. Plain data so it can cross threads;
  ## with reusePort every loop thread creates its own.
  result = bindListener(settings, SockType.SOCK_STREAM, Protocol.IPPROTO_TCP)
  if posix.listen(result, cint(settings.listenBacklog)) < 0:
    result.close()
    raiseOSError(osLastError())

proc newUdpSocket*(settings: VortexConfig): SocketHandle =
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

proc newLoop*(settings: VortexConfig, handler: RequestHandler,
              stopFlag: ptr Atomic[bool], listenFd: SocketHandle,
              pool: pointer = nil, outbox: ptr Outbox = nil,
              tls: pointer = nil,
              udpFd: SocketHandle = osInvalidSocket,
              streamRoute: StreamRouteCb = nil,
              quicReload: pointer = nil): Loop =
  result = Loop(
    selector: newSelector[FdKind](),
    listenFd: int(listenFd),
    settings: settings,
    limits: ParserLimits(
      maxHeaderSize: settings.maxHeaderSize,
      maxHeaderCount: settings.maxHeaderCount,
      maxBodySize: settings.maxBodySize),
    handlerRaw: cast[RawClosure](handler),   # raw pair: no cross-thread refcount
    stopFlag: stopFlag,
    tls: tls,
    udpFd: -1)
  result.core.streamRouteRaw = cast[RawClosure](streamRoute)
  result.core.serverHeader = settings.serverHeader
  if settings.securityHeaders:
    # OWASP Secure Headers baseline auto-injected on every response (skipping any
    # a handler set). CSP is deliberately excluded -- a forced content-security
    # policy breaks apps; set it per response via securityHeaders() instead.
    # HSTS only when this server terminates TLS (a whole listener is TLS or not).
    result.core.secHeaders = @[
      ("X-Content-Type-Options", "nosniff"),
      ("X-Frame-Options", "DENY"),
      ("Referrer-Policy", "no-referrer")]
    if settings.hasTls:
      result.core.secHeaders.add ("Strict-Transport-Security",
                                  "max-age=63072000; includeSubDomains")
  result.core.config.maxWsMessage = settings.maxWsMessageSize
  result.core.config.wsPingInterval = settings.wsPingInterval
  result.core.config.wsPongTimeout = settings.wsPongTimeout
  result.core.config.wsCompression = settings.wsCompression
  result.core.config.compress = settings.compress
  result.core.config.decompressRequest = settings.decompressRequest
  result.core.config.trustedProxies = settings.trustedProxies
  result.core.config.maxDecompressedBody = settings.maxBodySize
  result.core.nowSec = monoSec()
  result.core.pool = pool
  result.core.outbox = outbox
  result.core.loopPtr = cast[pointer](result)
  # Modestly preallocate the connection table so the common fd range never
  # reallocates it (growing it moves every Connection, which would dangle a
  # `addr core.conns[fd]` a blocking: worker holds -- see handleAccept, which
  # refuses to grow while any slot is pinned). A large fd rlimit is NOT used as
  # the size: preallocating millions of slots wastes memory and startup time.
  result.core.conns = newSeq[Connection](1024)
  result.refreshDate()
  result.selector.registerHandle(int(listenFd), {Event.Read}, fkListen)
  if outbox != nil:
    result.selector.registerEvent(outbox.ev, fkWakeup)
  when not defined(plainHttp):
    if udpFd != osInvalidSocket:
      # A valid udpFd means the server enabled h3 and validated the TLS cert.
      # The ngtcp2/nghttp3 C++ shim owns the QUIC engine + TLS for this loop.
      result.quicReload = quicReload
      if ngSetup(addr result.core, cint(udpFd), settings.certFile,
                 settings.keyFile, settings.maxBodySize,
                 settings.maxConcurrentStreams, settings.maxHeaderSize,
                 certPem = settings.certPem, keyPem = settings.keyPem,
                 keyPassword = settings.keyPassword,
                 pkcs12File = settings.pkcs12File, pkcs12 = settings.pkcs12,
                 streamRecvWindow = settings.h3StreamWindow,
                 connRecvWindow = settings.h3ConnWindow,
                 maxConnections = settings.maxConnections,
                 maxResetStreams = settings.maxResetStreams):
        result.udpFd = int(udpFd)
        result.selector.registerHandle(int(udpFd), {Event.Read}, fkQuic)
        result.core.altSvc = "h3=\":" & $int(settings.port) & "\"; ma=86400"
      else:
        # http3 was requested (a udpFd was bound) but the QUIC engine could not
        # start -- most often TLS material the ngtcp2 ossl backend can't load
        # (e.g. a cert/key that failed makeCtx's check). Surface it instead of
        # silently serving h1/h2 with a bound-but-unused UDP socket and no
        # Alt-Svc. h1/h2 keep working; only h3 is unavailable on this loop.
        try:
          stderr.writeLine("vortex: HTTP/3 engine setup failed; serving " &
                           "HTTP/1.1 and HTTP/2 only on this loop " &
                           "(check the TLS certificate/key for QUIC)")
        except IOError, OSError: discard

const drainTimeoutSec = 5    # bound on how long a lingering close waits

proc setDeadline(c: ptr Connection, loop: Loop, kind: DeadlineKind) =
  c.dlKind = kind
  let secs =
    case kind
    of dkHeader: loop.settings.headerTimeout
    of dkBody: loop.settings.bodyTimeout
    of dkIdle: loop.settings.keepAliveTimeout
    of dkResponse: loop.settings.responseTimeout
    of dkDrain: drainTimeoutSec
    of dkWsPing: loop.settings.wsPingInterval
    of dkWsPong: loop.settings.wsPongTimeout
    of dkNone: 0
  c.deadline = if secs > 0: loop.core.nowSec + int64(secs) else: 0

proc closeConn(loop: Loop, c: ptr Connection) =
  if c.bodyReadPaused and loop.bodyPausedConns > 0:
    # A body-paused connection is going away: release its slot in the paused-conns
    # count so the selector wait un-caps once none remain.
    dec loop.bodyPausedConns
  c.bodyReadPaused = false
  if c.registered:
    loop.selector.unregister(int(c.fd))
    c.registered = false
  c.deadline = 0
  c.dlKind = dkNone
  c.writeDeadline = 0
  if c.totalPins > 0:
    # A worker still holds a Request handle into this slot: keep the fd
    # open (reserving the fd number and the slot) until it unpins.
    c.closeRequested = true
    c.state = csClosing
    return
  # Committed to freeing this slot: mark it closing BEFORE firing any teardown
  # callback below. Those callbacks resume suspended producers/consumers so their
  # finally-cleanup runs, but a resumed handler may reach for the dispatch API
  # (e.g. a streamed sendFile's parked onRespDrain calls dispatchNextRead, or an
  # onClose body calls ws.blocking) -- which would acquire a fresh worker pin on
  # a connection we are about to free, tripping the totalPins invariant below.
  # acquireDispatchPin treats a closing connection as gone and refuses to pin, so
  # any such dispatch becomes a graceful no-op (the caller reclaims its buffer /
  # sends nowhere) instead of re-pinning a dead slot.
  c.closeRequested = true
  if c.rs.onBodyCb != nil:
    # A streaming request's body sink is still open (the client disconnected
    # mid-upload). Deliver a final last=true so an async adapter suspended in
    # await req.read() resumes at end-of-body and its Future / reader-table
    # entry are released instead of leaking forever (the entry is keyed by the
    # about-to-be-bumped generation and would never be reused or deleted).
    let cb = c.rs.onBodyCb
    c.rs.onBodyCb = nil
    var empty: string
    try: cb(toOpenArray(empty, 0, -1), true)
    except CatchableError: discard
  if c.ws != nil:
    wsClosed(addr loop.core, c)   # deliver onClose (1006 if no peer close)
  if c.h2 != nil:
    h2NotifyClosed(c)             # last=true for every streaming request sink
    h2WsTeardownAll(c)            # onClose for every RFC 8441 WebSocket stream
  when not defined(plainHttp):
    if c.ssl != nil:
      if not c.handshaking:
        tlsShutdown(c.ssl)
      freeTlsSession(c.ssl)
      c.ssl = nil
  c.h2 = nil
  clearRespHeaders(addr loop.core, c.fd, c.gen)  # drop pending res.headers, if any
  # Actually freeing: no worker task may still pin this slot (R2). The guard at
  # the top defers while pinned, and c.closeRequested (set above) makes
  # acquireDispatchPin refuse a re-pin from any teardown callback, so this can
  # only fire on a genuine accounting defect -- catch it, don't mask it.
  doAssert c.totalPins == 0, "connection freed with live worker pins"
  discard posix.close(cint(c.fd))
  # Return the read/write buffers to the allocator now, rather than pinning their
  # peak capacity until the slot is reused (which may never happen). setLen(0) on
  # flush/reset keeps capacity, and clear()'s wbuf shrink check reads .len (0 after
  # a flush) so it never fires -- without this a slot that once streamed a large
  # body or response holds its high-water buffers for the server's lifetime. clear()
  # reallocates both from initialBufferSize on the next accept into this slot.
  c.rbuf = ""
  c.wbuf = ""
  c.rlen = 0
  c.wpos = 0
  inc c.gen
  c.state = csFree
  c.closeRequested = false
  dec loop.connCount

proc setInterest(loop: Loop, c: ptr Connection, events: set[Event]) =
  ## Point the selector at exactly `events` for c's fd: register the fd if it was
  ## unregistered (e.g. re-arming a connection parked half-closed for a deferred
  ## response), else update it, keeping c.registered / c.writeArmed in sync. The
  ## caller owns deadlines; dropping the fd entirely is disarmForResponse's job,
  ## not an empty event set here.
  if not c.registered:
    loop.selector.registerHandle(int(c.fd), events, fkClient)
    c.registered = true
  else:
    loop.selector.updateHandle(int(c.fd), events)
  c.writeArmed = Event.Write in events

proc armWrite(loop: Loop, c: ptr Connection) =
  # The socket could not take all pending output: arm a write-stall deadline so a
  # slow-reading client that never drains the response is closed (writeTimeout).
  # Idle (re-armed each time we block on write), so a response that keeps making
  # progress is never cut off; independent of c.deadline so it doesn't clobber a
  # request/idle/response deadline. sweepTimeouts enforces it. (No-op if off.)
  if loop.settings.writeTimeout > 0:
    c.writeDeadline = loop.core.nowSec + int64(loop.settings.writeTimeout)
  if not c.registered:
    # Re-arm a connection unregistered while it waited half-closed for a deferred
    # response (see disarmForResponse): there is output to flush now. Read
    # interest is added once the write drains (disarmWrite).
    loop.setInterest(c, {Event.Write})
  elif not c.writeArmed:
    loop.setInterest(c, {Event.Read, Event.Write})

proc disarmWrite(loop: Loop, c: ptr Connection) =
  c.writeDeadline = 0            # output fully flushed: the write is not stalled
  if c.writeArmed:
    if c.registered:
      loop.setInterest(c, {Event.Read})
    else:
      c.writeArmed = false

proc disarmForResponse(loop: Loop, c: ptr Connection) =
  ## The peer half-closed and we are waiting for a deferred/worker response.
  ## The selector always arms EPOLLRDHUP, so a half-closed fd is persistently
  ## EOF-ready and leaving it registered busy-spins the loop for the whole wait.
  ## Unregister it -- the response arrives via the outbox/kick, not this fd, and
  ## armWrite re-registers it if the flush needs write interest.
  if c.registered:
    loop.selector.unregister(int(c.fd))
    c.registered = false
    c.writeArmed = false

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
  # Ensure the fd watches Read so handleDrain observes the peer FIN and reaps
  # promptly. It may be unregistered (disarmForResponse parked a deferred
  # response before this close) or write-armed; without read interest the
  # connection would strand in csDraining until the drain deadline (5s), holding
  # an fd + connCount slot for every such close.
  if not c.registered or c.writeArmed:
    loop.setInterest(c, {Event.Read})
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

const h2MaxRefillRounds = 16
  ## How many times one flushOut call may refill c.wbuf from the HTTP/2 write
  ## scheduler and write it straight back out (#332). h2DrainResume tops the
  ## buffer up to respHighWater (64 KiB), so this bounds one connection at ~1 MiB
  ## of h2 output per flushOut before it must yield to the selector. Without a
  ## bound a producer that refills forever (a large file, a generated stream)
  ## would starve every other fd in the loop; with one, a fast peer still gets
  ## ~1 MiB per loop iteration instead of the 64 KiB an arm/wait/disarm round
  ## trip per chunk used to allow.

proc flushOut(loop: Loop, c: ptr Connection) =
  ## Write as much pending output as the socket accepts; arm write
  ## interest only when the kernel buffer is full.
  ##
  ## For HTTP/2 the write scheduler is the source of the bytes, so a drained
  ## buffer is not the end of the work: refill it and keep writing while the
  ## socket still takes bytes, up to h2MaxRefillRounds. Returning to the selector
  ## after every 64 KiB refill (the pre-#332 behaviour) capped an h2 download at
  ## loop-iterations x respHighWater.
  template drainResume() =
    ## Refill from the write scheduler and resume producers parked on the buffer
    ## cap, with the flush held (#334): a resumed producer's res.write would
    ## otherwise re-enter flushOut through the flush hook and pay a send() per
    ## resumed stream, when this call is already either about to write the bytes
    ## itself (the refill branch) or has just armed write interest for them (the
    ## EAGAIN branches). Holding is never an ordering rule -- wbuf stays FIFO --
    ## so the bytes go out in the same order either way.
    holdFlush(c)
    h2codec.h2DrainResume(c, addr loop.core)
    discard releaseFlushHold(c)
  var refills = 0
  while true:
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
            if c.h2 != nil and c.pendingOut < respHighWater:
              drainResume()
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
          if c.h2 != nil and c.pendingOut < respHighWater:
            drainResume()
          return
        loop.closeConn(c)
        return
    c.wbuf.setLen(0)
    c.wpos = 0
    loop.disarmWrite(c)          # no-op once already disarmed, so looping is free
    if c.closeAfterFlush:
      # Close gracefully after writing a response on a plaintext HTTP/1 connection:
      # a bare close() while the kernel still holds untransmitted response bytes and
      # the peer has unread/half-closed can emit a RST that truncates the tail (a
      # slow-reading reverse proxy then reports an incomplete body). beginLingerClose
      # does shutdown(SHUT_WR) + drain so the send buffer flushes with a clean FIN.
      # This covers every close-after-response path (Connection: close, streaming
      # finish, drain shutdown, peer-half-close), not just error responses. TLS
      # (close_notify) and h2/ws keep the direct close unless lingerClose is set.
      if c.lingerClose or (c.h2 == nil and c.ws == nil):
        loop.beginLingerClose(c)
      else:
        loop.closeConn(c)
      return
    elif c.ws != nil:
      wsDrained(addr loop.core, c)   # fire onDrain if this WS was backed up
      return
    elif c.rs.respStreaming and c.respBackedUp:
      c.respBackedUp = false
      if c.rs.onRespDrain != nil:
        # Fire once, then clear -- the producer re-registers if it wants the next
        # drain (matches the h2/h3 codecs). One-shot is required by the file
        # streamer's read-ahead: it may prefetch the next chunk while still backed
        # up (no fresh onDrain registered), and a persistent callback would then
        # re-fire spuriously on the next full drain (issue #273).
        let cb = c.rs.onRespDrain
        c.rs.onRespDrain = nil
        cb(addr loop.core, c.fd, c.gen, 0)  # resume a streamed body
      return
    else:
      # HTTP/2: the socket drained c.wbuf; run the write scheduler to refill it
      # and resume producers parked on the cap (no-op for non-h2 connections).
      drainResume()
      if c.pendingOut == 0: return          # nothing more to send: done
      inc refills
      if refills >= h2MaxRefillRounds:
        # Yield: arm write so the fresh frames go out on the next writable and
        # the rest of the loop gets a turn.
        loop.armWrite(c)
        return
      # else: the socket was still accepting bytes a moment ago, so write the
      # refill now instead of paying an arm / wait / disarm round trip for it.

proc respondError(loop: Loop, c: ptr Connection, code: HttpCode) =
  let msg = $code
  appendResponse(c.wbuf, code, loop.core.dateStr, loop.core.serverHeader,
                 "text/plain", msg, [], keepAlive = false, skipBody = false)
  c.rs.responded = true
  c.closeAfterFlush = true
  c.lingerClose = true       # drain the peer so the error is delivered, no RST
  c.state = csClosing

proc h2Deadline(c: ptr Connection): DeadlineKind =
  ## Classify an active h2 connection's timeout policy for this pass:
  ##  - dkIdle: no streams open -- (re)arm keep-alive. This must refresh on every
  ##    pass that leaves zero active streams, not just the first: a fully
  ##    synchronous request opens and closes its stream within one processInput,
  ##    so activeStreams is 0 at both ends; freezing it at first-arm would let
  ##    sweepTimeouts close a busy connection keepAliveTimeout after it opened
  ##    (e.g. a client streaming SSE batches, one stream at a time).
  ##  - dkBody: a stream still awaits the client's request head/body (a slowloris
  ##    hold-open, bounded by bodyTimeout), OR every request has finished but the
  ##    server still owes response bytes parked on an exhausted send window -- the
  ##    client must send WINDOW_UPDATE, so its silence is a stall, not a legit
  ##    silent SSE/download (#236). A stream the client finished while the server
  ##    streams a long response back (endStreamSeen) is excluded by
  ##    h2AwaitingClient, so a legitimately-silent client is never wrongly reaped.
  ##  - dkNone: nothing to time.
  ##
  ## All three questions are answered from counters maintained at the state
  ## transitions (#339). This runs on every input event, and the two predicates
  ## used to walk the whole stream table with mpairs, so a 256-stream download
  ## scanned 256 entries twice for every inbound WINDOW_UPDATE batch. The
  ## debug-only audit below re-derives them by scanning, so a codec mutation
  ## site that forgets to update a counter fails the test suite.
  when not defined(release): h2CheckCounters(c)
  if h2ActiveStreams(c) == 0: dkIdle
  elif h2AwaitingClient(c): dkBody
  elif h2BlockedOnPeerWindow(c): dkBody
  else: dkNone

proc h2Input(loop: Loop, c: ptr Connection) =
  ## Feed buffered bytes to the HTTP/2 codec and dispatch ready streams.
  if c.inputPausePins > 0:
    # A general blocking:/awaitable worker holds a Request into this connection
    # (it reads req.body / req.header, which are slices of c.rbuf): pause input
    # so the streams table and receive buffer are not mutated under it.
    # sendFile chunk-read pins (pkFileChunk) are excluded -- those workers only
    # read a file, never the stream table, so processing input (flow-control
    # frames, other streams) is safe and keeps a streamed response's
    # WINDOW_UPDATEs flowing while it is mid-stream.
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
        loop.callHandler(req, response(req))
    except CatchableError:
      applyResponse(addr loop.core, c, sid, 500, "text/plain", [],
                    "500 Internal Server Error")
    # A freshly-accepted RFC 8441 WebSocket may hold frames the client
    # pipelined with the CONNECT handshake (buffered during accept). Pump them
    # now that the handler has installed onMessage; deliver a deferred
    # peer-close if the client half-closed before we accepted.
    if c.inputPausePins == 0 and h2StreamAlive(c, sid):
      let w = wsConnForStream(addr loop.core, c, sid)
      if w != nil and (w.inBuf.len > 0 or w.preAcceptFin):
        if w.inBuf.len > 0:
          wsFeed(addr loop.core, c, w, "")
        if w.preAcceptFin and h2StreamAlive(c, sid):
          w.preAcceptFin = false
          wsPeerClosed(addr loop.core, c, w)
        loop.flushOut(c)
  if c.state == csActive:
    let dk = h2Deadline(c)
    if dk == dkNone:
      c.deadline = 0
      c.dlKind = dkNone
    else:
      c.setDeadline(loop, dk)

proc initH2(loop: Loop, c: ptr Connection) =
  c.h2 = newH2Conn(addr loop.core,
                   loop.settings.maxBodySize, loop.settings.maxHeaderSize,
                   loop.settings.maxConcurrentStreams,
                   loop.settings.maxResetStreams,
                   loop.settings.maxControlFrames,
                   loop.settings.h2StreamWindow,
                   loop.settings.h2ConnWindow)

const
  streamBodyHighWater = 1024 * 1024
    ## HTTP/1 manualAck read-ahead ceiling (one streamRecvBufferCap worth): pause
    ## the socket recv loop once this many delivered-but-unacked body bytes are
    ## outstanding. An async pull-reader (await req.read) drains the delivered
    ## chunks into its own queue and acks on consume; without this bound the loop
    ## reads (and copies into that queue) the whole upload far faster than the
    ## handler hashes it -- ~maxBodySize buffered per connection, gigabytes across
    ## many concurrent uploads (OOM). The sync auto-ack path hashes inline and
    ## never accrues debt, so it is unaffected.
  streamBodyLowWater = streamBodyHighWater div 4
    ## Resume reading once ackBody brings the debt back below this (hysteresis so
    ## a resume isn't immediately re-paused after one small ack).

proc feedBody(loop: Loop, c: ptr Connection, last: bool) =
  ## Deliver newly-arrived request-body bytes to a streaming handler's onBody.
  ## `c.bodyFed` tracks how much has been delivered; `last` is set once the
  ## whole body is in so the final call carries the tail with last=true.
  if c.rs.onBodyCb == nil: return
  let cb = c.rs.onBodyCb
  if c.parser.chunked:
    # Decoded chunk bytes accumulate in c.chunkBody; end-of-body (the 0-chunk)
    # is only known when the parser reaches prComplete, i.e. `last`.
    let avail = c.chunkBody.len - c.bodyFed
    if avail > 0:
      cb(toOpenArray(c.chunkBody, c.bodyFed, c.chunkBody.len - 1), last)
      if c.rs.bodyManualAck: c.bodyUnacked += avail
      # Drop the delivered bytes so a streaming chunked upload stays O(read
      # burst) in memory, matching the Content-Length path. The parser keeps
      # appending to the now-empty buffer; because it bounds chunkBody.len (not a
      # running total) against maxBodySize, this also lifts that cap for a
      # streaming route -- only the undelivered tail needs bounding. A buffered
      # chunked request has no onBodyCb, so it is never truncated and stays
      # capped.
      c.chunkBody.setLen(0)
      c.bodyFed = 0
    elif last:
      cb(toOpenArray(c.chunkBody, 0, -1), true)   # empty final chunk
    if not last and c.parser.pos > c.parser.bodyStart:
      # Compact the *raw* receive buffer. The parser copied the consumed chunk
      # data into c.chunkBody (delivered above), but the raw chunk framing still
      # occupies rbuf up to parser.pos. Drop it -- keep the request head
      # [reqStart, bodyStart) (req.header still reads it during onBody) and the
      # unparsed tail [pos, rlen) -- so a streaming chunked upload stays O(read
      # burst) in rbuf instead of retaining every raw body byte. Without this
      # rbuf grows to the whole body on each connection; across many concurrent
      # uploads that is gigabytes (OOM). The Content-Length branch below already
      # compacts this way; here bodyStart marks the head end (see parser).
      let headEnd = c.parser.bodyStart
      let tailLen = c.rlen - c.parser.pos
      if tailLen > 0:
        moveMem(addr c.rbuf[headEnd], addr c.rbuf[c.parser.pos], tailLen)
      c.rlen = headEnd + tailLen
      c.parser.pos = headEnd
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
    if c.rs.bodyManualAck: c.bodyUnacked += avail
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
  if not callStreamRoute(addr loop.core, c.fd, c.gen, 0): return
  c.rs.reqStreaming = true
  c.bodyFed = 0
  c.bodyUnacked = 0
  c.bodyReadPaused = false
  let req = Request(core: addr loop.core, fd: c.fd, gen: c.gen)
  try:
    {.gcsafe.}:
      loop.callHandler(req, response(req))
  except CatchableError:
    if not c.rs.responded:
      loop.respondError(c, Http500)

proc processInput(loop: Loop, c: ptr Connection) =
  ## Parse and dispatch as many complete pipelined requests as the buffer
  ## holds. Parsing pauses while a response is outstanding (deferred
  ## handlers) so responses stay ordered.
  if c.ws != nil:
    # Pause frame dispatch while a ws.blocking worker holds the connection:
    # buffered frames wait until it unpins (one message at a time).
    if c.inputPausePins == 0:
      # Hold the socket flush for the whole read batch (#333): frames produced by
      # the onMessage handlers land in c.wbuf and go out in one send() here,
      # instead of one send() (plus an armWrite/disarmWrite pair on every EAGAIN)
      # per echoed message. A handler that closes mid-batch only sets
      # closeAfterFlush, so the close still rides this flush.
      holdFlush(c)
      wsInput(addr loop.core, c)
      if releaseFlushHold(c) and c.state != csFree and
          (c.pendingOut > 0 or c.closeAfterFlush):
        loop.flushOut(c)
    else:
      # We can't parse frames to observe the peer's pong while pinned, but this
      # call is driven by inbound bytes, which prove the peer is alive. Refresh
      # the idle-ping deadline so sweepWsPing's pong timeout can't close a
      # healthy connection whose pong sits unparsed in rbuf. h2/h3 get this for
      # free: wsFeed updates lastRx on raw bytes even while a worker holds it.
      armWsPing(addr loop.core, c)
    return
  if c.h2 != nil:
    # Hold the socket flush for the whole frame batch (#334), as the WebSocket
    # read batch above does (#333): every handler dispatched from this batch --
    # and every res.write a streamed producer does inside it -- lands in c.wbuf
    # and goes out in one send() here, instead of one send() per response and
    # per chunk. A write that fills the buffer past respHighWater still meets the
    # socket immediately (flushImpl ignores the hold there), so a producer that
    # emits megabytes inside one dispatch is unchanged.
    holdFlush(c)
    loop.h2Input(c)
    if releaseFlushHold(c) and c.state != csFree and
        (c.pendingOut > 0 or c.closeAfterFlush):
      loop.flushOut(c)
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
        # bodyTimeout is an *idle* timeout: re-arm on every read that carries
        # body bytes (processInput runs per readable event), so a large upload
        # that keeps making progress is never cut off. Arming it once at
        # headers-complete made it a total-duration cap that rejected any body
        # taking longer than bodyTimeout even while actively transferring (a
        # 1 GiB upload on a slow link always failed). Only a genuine stall -- no
        # bytes for bodyTimeout -- now fires; maxBodySize still bounds the total.
        c.setDeadline(loop, dkBody)
        # Streaming route: dispatch at headers-complete, then feed the body
        # incrementally to onBody instead of waiting for the whole request.
        # 100 Continue is sent implicitly when the handler first reads
        # (req.onBody / req.read), Go-style; a handler that responds before
        # reading (a reject) never prompts the body.
        if hasStreamRoute(addr loop.core) and not c.rs.reqStreaming and
            not c.rs.responded:
          loop.startStreamingDispatch(c)
        if c.rs.reqStreaming:
          loop.feedBody(c, last = false)
        elif c.parser.expectContinue and not c.sent100 and not c.rs.responded:
          # Buffered route: the loop must receive the whole body to dispatch, so
          # prompt an Expect: 100-continue client to send it (buffering is the
          # read).
          c.sent100 = true
          c.wbuf.add continue100
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
      if not c.rs.reqStreaming and hasStreamRoute(addr loop.core):
        loop.startStreamingDispatch(c)
      if c.rs.reqStreaming:
        # Streaming handler already ran (early or just now): deliver the tail.
        loop.feedBody(c, last = true)
      else:
        let req = Request(core: addr loop.core, fd: c.fd, gen: c.gen)
        try:
          {.gcsafe.}:
            loop.callHandler(req, response(req))
        except CatchableError:
          if not c.rs.responded:
            loop.respondError(c, Http500)
            return
          if c.rs.respStreaming:
            # Raised after sendHead: the chunked body can't be terminated and
            # the connection can't be reused, so close after flushing the
            # partial response rather than parking it forever (below).
            c.rs.respStreaming = false
            c.closeAfterFlush = true
      if not c.rs.responded:
        # Deferred response (worker pool / adapter); pause until respond.
        c.awaitingResponse = true
        # Backstop a stuck/never-arriving deferred response with responseTimeout
        # (opt-in, 0 = off), but not while pinned: a blocking: worker may take
        # arbitrarily long and always responds (blockingTrampoline guarantees
        # it), so timing it out would kill legitimate long jobs.
        if c.totalPins == 0 and loop.settings.responseTimeout > 0:
          c.setDeadline(loop, dkResponse)
        return
      if c.rs.respStreaming:
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
    if c.state != csFree and c.inputPausePins == 0:
      loop.processInput(c)       # resume input paused during pinning
      if c.state != csFree and c.pendingOut > 0:
        loop.flushOut(c)
  elif c.closeAfterFlush:
    c.state = csClosing
    loop.flushOut(c)
  elif c.rs.respStreaming:
    # The response was left mid-stream: a handler (or its async future) failed
    # or completed without calling finish(). The chunked body was never
    # terminated, so the connection cannot be safely reused -- reusing it would
    # let the next response's bytes be read as chunk data of this one (response
    # desync). Flush whatever is buffered and close instead of resetting.
    c.rs.respStreaming = false
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

proc releasePin(loop: Loop, c: ptr Connection, k: PinKind): bool {.discardable.} =
  ## Release one typed pin after applying its outbox message, then run the
  ## post-release hooks that used to be scattered per message kind:
  ##  * honor a close deferred while pinned (closeRequested -> closeConn), and
  ##  * the generalized input resume (formerly only on the omFile* branch): the
  ##    moment no input-pausing pin remains and bytes are buffered, re-process
  ##    input. A WINDOW_UPDATE or pipelined request parked in rbuf while input
  ##    was paused has NO other re-processing trigger once the socket goes
  ##    idle (the #167 deadlock class), so this is a property of every release,
  ##    not of specific message kinds. Note this means input can now resume one
  ##    message earlier than before (e.g. on omBlockingDone) -- strictly less
  ##    stall, and every path below the resume tolerates a state change.
  ## Returns false when the connection is no longer safe to touch (the
  ## deferred close ran, or the resume freed the slot).
  ##
  ## No-pool servers dispatch inline without acquiring pins but still route
  ## omBlockingDone/omFile* through the outbox: skip the counter (releasePin
  ## would underflow a pin that was never taken), keep the hooks.
  if loop.core.pool != nil:
    releasePin(c, k)               # doAssert-guarded dec (connection.nim)
  if c.closeRequested:
    loop.closeConn(c)              # re-defers if other pins remain
    return false
  if c.inputPausePins == 0 and c.rlen > 0:
    loop.processInput(c)
    if c.state == csFree: return false
  true

proc releasePin(loop: Loop, slot: ptr H3SlotEntry, k: PinKind) =
  ## h3 twin: slots have no input to pause and their deferred free must
  ## `continue` the outbox message loop, so it stays at the call sites
  ## (unpinH3AndSkipIfClosing / omBlockingDone). Counter only.
  if loop.core.pool != nil:
    releasePin(slot, k)

proc kickImpl(loopPtr: pointer, fd: int32, gen: uint32,
              stream: uint32) {.nimcall, gcsafe.} =
  ## LoopCore.hooks.kick: adapters call this on the loop thread after a
  ## deferred respond. Redundant calls are harmless.
  {.gcsafe.}:
    let loop = cast[Loop](loopPtr)
    if fd < 0:
      return                     # h3 responses flush inside h3Respond
    let c = conn(addr loop.core, fd, gen)
    if c == nil: return
    if stream == 0 and not (c.awaitingResponse and c.rs.responded):
      return                     # nothing deferred is pending
    loop.resumeAfterRespond(c, stream)

proc flushImpl(loopPtr: pointer, fd: int32, gen: uint32) {.nimcall, gcsafe.} =
  ## LoopCore.hooks.flushHook: write a connection's pending output now. Used by a
  ## loop-thread WebSocket send outside the read path.
  {.gcsafe.}:
    let loop = cast[Loop](loopPtr)
    let c = conn(addr loop.core, fd, gen)
    if c == nil or c.pendingOut <= 0: return
    if c.flushHold > 0 and c.pendingOut < respHighWater:
      # A batch is dispatching on this connection (a WebSocket read batch, an
      # outbox drain): the frames this send produced are already in wbuf and the
      # batch owner flushes once when its hold drops, so one recv() carrying N
      # messages costs one send() instead of N (#333). Past respHighWater the
      # hold is ignored: a handler that emits megabytes inside a single dispatch
      # must still meet the socket (and its EAGAIN -> wsBackpressure/onDrain
      # signal) rather than buffering the whole burst in wbuf.
      return
    loop.flushOut(c)

const h2RecvBufferCap = 1024 * 1024
  ## Hard ceiling on an HTTP/2 connection's receive buffer. With
  ## process-and-compact it is never approached in practice (a single
  ## frame is <= max frame size); it only bounds backpressure while a
  ## `blocking:` worker has the connection pinned.

const streamRecvBufferCap = 1024 * 1024
  ## Ceiling on an HTTP/1 connection's receive buffer while it streams a request
  ## body to a `req.onBody` handler. Past this, compact (feed onBody + drop the
  ## delivered bytes) instead of doubling toward maxHeaderSize+maxBodySize, so a
  ## fast upload can't pin ~maxBodySize of receive buffer per connection --
  ## across many concurrent uploads that is gigabytes (OOM). A buffered (non
  ## streaming) request still grows to the body cap, as it must hold the whole
  ## body to dispatch.

proc handleRead(loop: Loop, c: ptr Connection) =
  # processInput (called from the grow branches below) can transition the
  # connection out of csActive -- e.g. a frame-size / protocol error queues a
  # GOAWAY and sets csClosing. Returning straight out of handleRead would skip
  # the post-read flush at the end, stranding that GOAWAY unsent, so the socket
  # never closes and the peer times out (h2spec 4.2). This only surfaces when the
  # error frame does not fit in one buffer-fill (so it is handled from the grow
  # branch rather than after the read loop). Flush the pending output here before
  # unwinding. csFree means processInput already closed the slot: nothing to
  # flush -- just return.
  template returnAfterStateChange() =
    if c.state != csFree and (c.pendingOut > 0 or c.closeAfterFlush):
      loop.flushOut(c)
    return
  template compactThenRetry() =
    ## rbuf is full at a soft compaction threshold (the streaming-body or
    ## header-size ceiling handled below): let the parser consume + compact the
    ## buffered bytes instead of doubling toward the whole-body cap (a fast upload
    ## or header flood would otherwise pin far more than advertised). Bail if that
    ## closed/transitioned the connection; re-read into any room it freed;
    ## otherwise fall through to the grow-or-close below.
    loop.processInput(c)
    if c.state != csActive: returnAfterStateChange()
    if c.rlen < c.rbuf.len: continue
  while true:
    if c.rs.bodyManualAck and c.bodyUnacked >= streamBodyHighWater:
      # A manualAck streaming body (an async await-req.read consumer) has fallen
      # behind: >= high-water bytes are delivered-but-unacked (its queue is full).
      # Stop pulling more -- the unread tail waits in the kernel as TCP
      # backpressure. The fd stays selector-armed; handleRead's tail flags the
      # connection so the selector wait is capped short (bodyPausedConns), keeping
      # the async pump cycling to drain the consumer without a busy-spin, and the
      # recv loop resumes on the next readable event once ackBody drains the debt.
      break
    if c.rlen == c.rbuf.len:
      if c.h2 != nil:
        # HTTP/2: process buffered frames to compact consumed bytes, so the
        # receive buffer stays small regardless of total upload size and is
        # not clipped by a tight h1 body limit. Grow only if nothing could
        # be compacted (e.g. pinned by a worker), up to a hard ceiling.
        loop.processInput(c)
        if c.state != csActive: returnAfterStateChange()
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
        if c.totalPins > 0:
          # A blocking: worker holds a Request into this connection and may be
          # reading req.body/req.header, which are slices of c.rbuf. Growing it
          # reallocates the buffer and moves those bytes, a use-after-free on the
          # worker thread. Stop reading instead: the bytes stay in the kernel
          # (backpressure) and are consumed once the worker unpins. The current
          # request is already fully buffered; only the next pipelined one waits.
          break
        if c.rs.reqStreaming and c.rs.onBodyCb != nil and
            c.rbuf.len >= streamRecvBufferCap:
          # Streaming request body at the ceiling: feed the buffered bytes to
          # onBody and drop them (feedBody compacts rbuf) instead of doubling
          # toward the whole-body cap. A fast h1 upload would otherwise pin
          # ~maxBodySize per connection; across many concurrent uploads that is
          # gigabytes -> OOM. Mirrors the h2 process-and-compact path above.
          compactThenRetry()
        if c.ws == nil and not c.parser.inBody and
            c.rbuf.len >= loop.settings.maxHeaderSize:
          # Still parsing the request head at the header-size ceiling: run the
          # parser now so its own cap trips (431/414) instead of doubling the
          # buffer toward maxHeaderSize+maxBodySize. Otherwise a header flood (no
          # terminating blank line) pins far more than the advertised header
          # limit before rejection (#246). Mirrors the streaming/h2 branches.
          compactThenRetry()
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
  # Read-ahead backpressure bookkeeping for a manualAck streaming body. Decide on
  # the LIVE bodyUnacked after this read: the consumer's acks fire synchronously
  # from inside feedBody (onConsume runs when a fed chunk completes a parked
  # reader), so a connection that looked behind mid-recv may already be caught up
  # here. While paused, bodyPausedConns caps the selector wait so the async pump
  # keeps draining the consumer even though this fd has no new readable event; the
  # recv loop above stops pulling until ackBody's resume drains the debt.
  let nowPaused = c.state == csActive and c.rs.reqStreaming and
      c.rs.bodyManualAck and c.bodyUnacked >= streamBodyHighWater
  if nowPaused and not c.bodyReadPaused:
    c.bodyReadPaused = true
    inc loop.bodyPausedConns
  elif not nowPaused and c.bodyReadPaused:
    c.bodyReadPaused = false
    if loop.bodyPausedConns > 0: dec loop.bodyPausedConns
  if c.peerHalfClosed and c.state == csActive and not c.rs.respStreaming:
    # The peer will send no more requests: close once any response has been
    # written (the deferred/worker case sets closeAfterFlush and closes when
    # the response arrives). A streaming response is exempt -- the client may
    # half-close its write side and keep reading; finish() closes it.
    if c.awaitingResponse or c.pendingOut > 0:
      # flushOut linger-closes (plaintext h1) once the response is written, so the
      # send buffer flushes with a clean FIN rather than a RST that truncates the
      # tail for a slow-reading peer. The deferred/worker case still disarms the
      # fd until the response arrives via the outbox/kick.
      c.closeAfterFlush = true
      if c.awaitingResponse and c.pendingOut == 0:
        # No output yet -- the deferred/worker response arrives via the outbox
        # or kick, not this fd. Stop watching the fd so the persistent EOF
        # (EPOLLRDHUP) does not busy-spin the loop until the response lands.
        loop.disarmForResponse(c)
    else:
      # Response already handed to the kernel (pendingOut == 0) but not
      # necessarily transmitted; linger-close so the send buffer flushes with a
      # FIN instead of a possible RST that would truncate it.
      loop.beginLingerClose(c)

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

proc resumeBodyImpl(loopPtr: pointer, fd: int32, gen: uint32,
                    n: int) {.nimcall, gcsafe.} =
  ## LoopCore.hooks.resumeBodyHook: HTTP/1 req.ackBody credit. Repay `n` bytes of
  ## read-ahead debt and, once it falls below the low-water, clear the pause so the
  ## recv loop pulls the kernel-buffered tail again. The fd stays selector-armed
  ## throughout, so clearing the flag is enough -- the next readable event (kept
  ## prompt by the bodyPausedConns wait cap) resumes the recv loop. Called on the
  ## loop thread; may run re-entrantly (the consumer's onConsume fires from inside
  ## feedBody's onBody callback, itself inside handleRead), so it must not re-enter
  ## the recv loop -- doing so would corrupt the shared rbuf mid-move.
  {.gcsafe.}:
    let loop = cast[Loop](loopPtr)
    if fd < 0: return
    let c = conn(addr loop.core, fd, gen)
    if c == nil: return
    c.bodyUnacked -= n
    if c.bodyUnacked < 0: c.bodyUnacked = 0
    if not c.bodyReadPaused or c.bodyUnacked >= streamBodyLowWater: return
    c.bodyReadPaused = false          # below the low-water: let the recv loop pull
    if loop.bodyPausedConns > 0: dec loop.bodyPausedConns

proc startTls(loop: Loop, c: ptr Connection): bool =
  ## Begin TLS for a TLS listener (leave plaintext otherwise). Returns false if
  ## the session could not be created. Called at accept, or after a PROXY header
  ## is consumed when proxyProtocol is enabled.
  when not defined(plainHttp):
    if loop.tls != nil:
      c.ssl = newTlsSession(cast[ptr TlsConfig](loop.tls), cint(c.fd))
      if c.ssl == nil: return false
      c.handshaking = true
  true

proc suspendAccept(loop: Loop) =
  ## fd/memory exhaustion during accept(): deregister the listener for a short
  ## spell and re-arm it in tick(). The listen fd is level-triggered, so simply
  ## returning would immediately re-fire Read -> accept() -> EMFILE -> ... and
  ## spin a whole CPU core (Go backs off on temporary accept errors instead).
  if loop.listenFd >= 0 and loop.acceptSuspendedUntil == 0:
    try: loop.selector.unregister(loop.listenFd)
    except CatchableError: discard
    loop.acceptSuspendedUntil = loop.core.nowSec + 1
    try: stderr.writeLine("vortex: accept() hit fd/memory exhaustion; " &
                          "pausing new connections ~1s (raise the fd rlimit " &
                          "or lower maxConnections)")
    except IOError, OSError: discard

proc handleAccept(loop: Loop) =
  while true:
    var sa: Sockaddr_storage
    var saLen = SockLen(sizeof(sa))
    let client = posix.accept(SocketHandle(loop.listenFd),
                              cast[ptr SockAddr](addr sa), addr saLen)
    if cint(client) < 0:
      let err = cint(osLastError())
      if err == EINTR: continue
      if err == EAGAIN or err == EWOULDBLOCK:
        return                 # accept queue drained: wait for the next readable
      if err == ECONNABORTED:
        continue               # peer vanished before accept; skip to the next
      if err == EMFILE or err == ENFILE or err == ENOBUFS or err == ENOMEM:
        loop.suspendAccept()   # fd/memory exhaustion: back off, don't busy-spin
        return
      return                   # any other error: back to the loop
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
      # Grow the table for a higher fd, but only when nothing is pinned: a
      # realloc moves every Connection, and a blocking: worker may hold
      # `addr core.conns[oldFd]`. If a slot is pinned, refuse this connection
      # rather than dangle that pointer (a use-after-free). Rare in practice: a
      # new high fd must coincide with a running worker, and after warmup the
      # table stops growing. The scan is O(len) but only runs on a growth event.
      var pinnedAny = false
      for i in 0 ..< loop.core.conns.len:
        if loop.core.conns[i].totalPins > 0:
          pinnedAny = true
          break
      if pinnedAny:
        discard posix.close(client)
        continue
      loop.core.conns.setLen(fd + 64)
    let c = addr loop.core.conns[fd]
    c.fd = int32(fd)
    c[].clear(loop.settings.initialBufferSize)
    # Record the peer IP for req.remoteAddress (access logging, rate limiting,
    # audit). Best-effort: a formatting failure just leaves it empty.
    try: c.remoteAddr = getAddrString(cast[ptr SockAddr](addr sa))
    except CatchableError: discard
    inc loop.connCount
    if loop.settings.proxyProtocol != ProxyProtocol.Disabled:
      # Read (and strip) the PROXY header from the raw socket before starting
      # TLS or HTTP; the transport is set up in handleProxyHeader once done.
      c.awaitingProxy = true
    elif not loop.startTls(c):
      discard posix.close(client)
      inc c.gen
      c.state = csFree
      dec loop.connCount
      continue
    c.setDeadline(loop, dkHeader)   # handshake counts toward header timeout
    try:
      loop.selector.registerHandle(int(client), {Event.Read}, fkClient)
    except CatchableError:
      # registerHandle can raise (selector limits, a stale duplicate fd). Clean
      # up the fd and the connCount/slot we reserved rather than leaking them
      # and letting the exception unwind out of the loop thread (R11).
      discard posix.close(client)
      inc c.gen
      c.state = csFree
      dec loop.connCount
      continue
    c.registered = true

proc beginAfterProxy(loop: Loop, c: ptr Connection) =
  ## The PROXY phase is done (parsed, skipped, or absent): start the transport
  ## and process whatever bytes are already buffered in the socket.
  c.awaitingProxy = false
  if not loop.startTls(c):
    loop.closeConn(c)
    return
  when not defined(plainHttp):
    if c.handshaking:
      loop.driveHandshake(c)
      return
  loop.handleRead(c)

proc handleProxyHeader(loop: Loop, c: ptr Connection) =
  ## Peek the PROXY-protocol header (MSG_PEEK leaves the bytes in the kernel so
  ## the untouched TLS ClientHello / HTTP request that follows is read normally),
  ## and on a trusted peer consume exactly the header and override remoteAddr.
  var buf: array[536, char]
  let n = recv(SocketHandle(c.fd), addr buf[0], buf.len, cint(MSG_PEEK))
  if n == 0:
    loop.closeConn(c); return
  if n < 0:
    let err = cint(osLastError())
    if err == EAGAIN or err == EWOULDBLOCK or err == EINTR: return
    loop.closeConn(c); return

  let directPeer = c.remoteAddr    # the accept peer, before any override
  let trusted = isTrustedProxy(directPeer, loop.settings.trustedProxies)
  let require = loop.settings.proxyProtocol == ProxyProtocol.Require
  let res = parseProxyHeader(toOpenArray(buf, 0, n - 1))

  case res.kind
  of ppNeedMore:
    if n >= buf.len: loop.closeConn(c)   # over-long header: give up
    return
  of ppError:
    loop.closeConn(c); return
  of ppNotPresent:
    # No PROXY header. Mandatory under ProxyProtocol.Require; otherwise a direct client.
    if require: loop.closeConn(c)
    else: loop.beginAfterProxy(c)
    return
  of ppLocal, ppProxy:
    if not trusted:
      # A header from an untrusted source: never believe it. Require -> drop;
      # optional -> ignore it and treat the peer as a direct client (do NOT
      # consume, the bytes are the client's own data).
      if require: loop.closeConn(c)
      else: loop.beginAfterProxy(c)
      return
    # Trusted: consume exactly the header off the socket, then override.
    var scratch: array[536, char]
    var got = 0
    while got < res.consumed:
      let m = recv(SocketHandle(c.fd), addr scratch[0],
                   min(res.consumed - got, scratch.len), cint(0))
      if m <= 0: loop.closeConn(c); return
      got += m
    if res.kind == ppProxy and res.src.len > 0:
      c.remoteAddr = res.src           # the real client IP for req.remoteAddress
    loop.beginAfterProxy(c)

when not defined(plainHttp):
  proc h3FreeSlot(loop: Loop, idx: int) =
    let slot = addr loop.core.h3slots[idx]
    if slot.totalPins > 0:
      slot.closeReq = true
      return
    if slot.conn != nil:
      h3Free(H3Conn(slot.conn))
      slot.conn = nil
    clearRespHeaders(addr loop.core, h3SlotFd(idx), slot.gen)
    inc slot.gen
    slot.closeReq = false

  proc h3Drive(loop: Loop) =
    ## Advance the QUIC stack: the ngtcp2/nghttp3 shim accepts connections and
    ## parses HTTP/3 via its callbacks (which fill h3slots and the ready list);
    ## we drain UDP in, run timers, dispatch ready requests, and flush UDP out.
    ngReceive()
    for (slot, gen, sid) in ngTakeReady():
      if slot < loop.core.h3slots.len and
          loop.core.h3slots[slot].gen == gen and
          loop.core.h3slots[slot].conn != nil:
        let req = Request(core: addr loop.core, fd: h3SlotFd(slot),
                          gen: gen, stream: uint32(sid))
        try:
          {.gcsafe.}:
            loop.callHandler(req, response(req))
        except CatchableError:
          h3Apply(addr loop.core, h3SlotFd(slot), gen, uint32(sid),
                  500, "text/plain", [], "500 Internal Server Error")
    ngHandleExpiry()
    ngPump()
    for idx in 0 ..< loop.core.h3slots.len:
      if loop.core.h3slots[idx].conn != nil and
          loop.core.h3slots[idx].closeReq and
          loop.core.h3slots[idx].totalPins == 0:
        loop.h3FreeSlot(idx)

proc staleConn(c: ptr Connection, msgGen: uint32): bool {.inline.} =
  ## h1/h2: the message's connection died or its fd slot was reused. Every outbox
  ## branch checks the endpoint's generation BEFORE touching its pin -- a stale
  ## message must never dec a pin the *current* occupant took for an in-flight
  ## task, which would let the loop free the endpoint under a worker.
  c.gen != msgGen or c.state == csFree

when not defined(plainHttp):
  proc staleH3(slot: ptr H3SlotEntry, msgGen: uint32): bool {.inline.} =
    ## h3 twin of staleConn: the message's slot was freed (gen bumped) or holds
    ## no connection.
    slot.gen != msgGen or slot.conn == nil

  proc unpinH3ThenSkip(loop: Loop, slot: ptr H3SlotEntry, idx: int,
                       rel: PinRelease): bool =
    ## Release the pin the message names (prNone releases nothing -- e.g. an
    ## awaitable body's own response, whose pkAwait rides its later
    ## omBlockingDone) and honor a close deferred while pinned. Returns true when
    ## the caller should skip the payload: the slot is condemned (freed once the
    ## last pin drops), so there is nothing left to respond to.
    if rel != prNone: loop.releasePin(slot, pinKindOf(rel))
    if slot.closeReq:
      if slot.totalPins == 0: loop.h3FreeSlot(idx)
      return true
    false

proc applyFileMessage(loop: Loop, m: OutMsg) =
  ## Emit an omFileStart (head + first chunk) or omFileChunk (a later chunk) into
  ## its response. The apply is identical for h1/h2 and h3 (the pin release and
  ## post-apply resume differ and stay with each caller).
  let res = Response(core: addr loop.core, fd: m.fd, gen: m.gen, stream: m.stream)
  if m.kind == omFileStart:
    let bodyStart = unpackResponseInto(m.data, loop.unpackCt, loop.unpackHeaders)
    applyFileStart(res, int(m.code), loop.unpackCt, loop.unpackHeaders, m.n64,
                   m.data.toOpenArray(bodyStart, m.data.len - 1),
                   m.aux, m.user, m.last)
  else:
    applyFileChunk(res, m.buf, int(m.code), m.aux, m.user, m.last)

proc applyBlockingDone(loop: Loop, m: OutMsg, h3Touched: var bool) =
  ## An awaitable req.blocking worker finished. Release the boxed result and
  ## complete the future *regardless of connection state* -- on shutdown or after
  ## a client drop the connection may be gone, and a dead-conn skip would leak the
  ## box + future.
  let base = cast[BlockingResultBase](m.user)
  if base.onDone != nil: base.onDone(base)   # complete/fail the future (loop)
  GC_unref(base)                             # release the box
  if loop.core.pendingBlockingResults > 0:   # this task is no longer outstanding
    dec loop.core.pendingBlockingResults
  # The mapping is fixed: omBlockingDone is the one and only carrier of an
  # awaitable task's release (blockingResultTrampoline stamps it).
  doAssert m.release == prAwait, "omBlockingDone must release prAwait"
  if m.fd < 0:
    when not defined(plainHttp):
      let idx = h3SlotOf(m.fd)
      if idx < loop.core.h3slots.len and loop.core.h3slots[idx].gen == m.gen:
        let slot = addr loop.core.h3slots[idx]
        loop.releasePin(slot, pkAwait)
        if slot.closeReq and slot.totalPins == 0: loop.h3FreeSlot(idx)
        h3Touched = true
  elif int(m.fd) < loop.core.conns.len:
    let c = addr loop.core.conns[int(m.fd)]
    if not staleConn(c, m.gen):               # unpin/resume only if alive
      # releasePin's hook covers the deferred close, and also resumes buffered
      # input (e.g. pipelined h1 bytes after an awaitable body). That resume can
      # produce a synchronous response into wbuf; unlike omWsDone/omFileChunk/
      # omHttp this branch never flushed it, so it sat with write interest
      # disarmed until an unrelated event or the idle deadline. Flush it (#240.2).
      if loop.releasePin(c, pkAwait) and pendingOut(c) > 0:
        loop.flushOut(c)

when not defined(plainHttp):
  proc applyOutboxH3(loop: Loop, m: OutMsg, h3Touched: var bool) =
    ## Apply one non-blockingDone message on an h3 slot (m.fd < 0).
    let idx = h3SlotOf(m.fd)
    if idx >= loop.core.h3slots.len: return
    let slot = addr loop.core.h3slots[idx]
    # RFC 9220 WebSocket messages use per-stream pinning, not the slot pin.
    # Handle (or, when stale, drop) them entirely before the omHttp pin
    # bookkeeping: a stale ws message must never fall through to unpinH3ThenSkip
    # and steal a pin the slot's *current* occupant took for an in-flight
    # blocking: task (which would let the loop free the slot under that worker).
    if m.kind in {omWs, omWsClose, omWsDone}:
      if not staleH3(slot, m.gen):
        if m.kind == omWsDone:
          # An h3 ws.blocking worker finished: release the per-stream pin and pump
          # the frames buffered while it ran (h3 ws never carries a slot-pin
          # release -- per-stream pinnedByWorker instead).
          doAssert m.release == prNone
          let w = wsConnForH3(addr loop.core, m.fd, m.gen, m.stream)
          if w != nil: wsResume(addr loop.core, nil, w)
        else:
          let w = wsConnForH3(addr loop.core, m.fd, m.gen, m.stream)
          if w != nil: wsFlushRaw(addr loop.core, nil, w, m.data, m.kind == omWsClose)
        h3Touched = true
      return
    if staleH3(slot, m.gen): return
    if m.kind in {omFileStart, omFileChunk}:
      # The initial read (omFileStart <- serveResolved) holds pkBlocking (it reads
      # request headers -- risk R3: a file-classified release would let input
      # mutate state under it); chunk reads are pkFileChunk.
      doAssert (if m.kind == omFileStart: m.release != prFileChunk
                else: m.release in {prFileChunk, prNone})
      if loop.unpinH3ThenSkip(slot, idx, m.release): return
      loop.applyFileMessage(m)
      h3Touched = true
      return
    # omHttp releases what its task held: prBlocking, prFileChunk, or prNone (an
    # awaitable body's response; its pkAwait rides omBlockingDone). Never
    # prAwait/prWsBlocking, which have their own dedicated carrier messages.
    doAssert m.release notin {prAwait, prWsBlocking}
    if loop.unpinH3ThenSkip(slot, idx, m.release): return
    let bodyStart = unpackResponseInto(m.data, loop.unpackCt, loop.unpackHeaders)
    h3Apply(addr loop.core, m.fd, m.gen, m.stream, int(m.code),
            loop.unpackCt, loop.unpackHeaders,
            m.data.toOpenArray(bodyStart, m.data.len - 1))
    h3Touched = true

proc deferBatchFlush(loop: Loop, c: ptr Connection) =
  ## Hold this connection's flush for the rest of the outbox batch, to be released
  ## (and flushed, once) by processOutbox's tail (#333), so a worker's burst of
  ## frames costs one send() rather than one per message. The hold is taken BEFORE
  ## the operation it covers, so the counter and the pending list stay balanced
  ## even if that operation closes the connection. At most one hold (and one list
  ## entry) per connection per batch: `flushHold == 0` identifies the first
  ## message for this connection, since nothing else holds across messages -- a
  ## nested hold (processInput resuming a read batch) is taken and released within
  ## one message.
  if c.flushHold == 0:
    loop.pendingFlush.add (c.fd, c.gen)
    holdFlush(c)

proc applyOutboxConn(loop: Loop, m: OutMsg) =
  ## Apply one non-blockingDone message on an h1/h2 connection (m.fd >= 0).
  if int(m.fd) >= loop.core.conns.len: return
  let c = addr loop.core.conns[int(m.fd)]
  if staleConn(c, m.gen): return
  if m.kind == omWs or m.kind == omWsClose:
    # A WebSocket frame from an off-loop sender (already serialized): route to the
    # h1 connection or the h2 stream; the batch's single flush pushes it.
    let w = wsConnForStream(addr loop.core, c, m.stream)
    if w != nil:
      loop.deferBatchFlush(c)
      wsFlushRaw(addr loop.core, c, w, m.data, m.kind == omWsClose)
    return
  if m.kind == omWsDone:
    # A ws.blocking worker finished: release its pin and resume dispatching frames
    # held back while it ran. stream 0 (h1) holds a pkWsBlocking connection pin;
    # an h2 stream holds the per-stream pin, released by wsResume. Either path can
    # dispatch the next message (and its reply) inline, so hold the flush across
    # it and let the batch tail push everything at once.
    loop.deferBatchFlush(c)
    if m.stream == 0:
      # releasePin's hook covers the deferred close and, when frames are buffered,
      # dispatches the next message; its output rides the batch flush.
      doAssert m.release == prWsBlocking
      if not loop.releasePin(c, pkWsBlocking): return
    else:
      doAssert m.release == prNone
      let w = wsConnForStream(addr loop.core, c, m.stream)
      if w != nil:
        wsResume(addr loop.core, c, w)
    return
  if m.kind in {omFileStart, omFileChunk}:
    # Only chunk reads (dispatchNextRead -> omFileChunk) release prFileChunk. The
    # initial read (omFileStart -> serveResolved) reads req headers, so it releases
    # the pkBlocking pin it held (risk R3: never classify it as a file pin).
    # releasePin's hook covers the deferred close and the input resume (draining
    # buffered HTTP/2 frames -- chiefly the peer's WINDOW_UPDATEs a streamed
    # sendFile needs) the moment only file pins, if any, remain.
    doAssert (if m.kind == omFileStart: m.release != prFileChunk
              else: m.release in {prFileChunk, prNone})
    if m.release != prNone:
      if not loop.releasePin(c, pinKindOf(m.release)): return
    elif c.closeRequested:
      loop.closeConn(c)          # re-defers while other pins remain
      return
    if c.state != csActive: return
    # Several chunks of the same download can land in one outbox batch (the
    # read-ahead keeps one read in flight per stream, and a batch can carry the
    # replies of several streams on this connection). Hold the flush so they cost
    # one send() for the batch rather than one per chunk (#334); the tail below
    # no longer needs its own push, releaseBatchFlushes does it.
    loop.deferBatchFlush(c)
    loop.applyFileMessage(m)
    # The final chunk finished the response: reset and resume the pipeline (the
    # blocking-dispatch path doesn't set awaitingResponse, so finish()'s kick is a
    # no-op here -- mirror the buffered omHttp path explicitly).
    if m.last and not staleConn(c, m.gen):
      loop.resumeAfterRespond(c, m.stream)
    # Otherwise the batch tail flushes: the write scheduler fills c.wbuf up to
    # respHighWater and stops, and on a fast socket flushOut never hits EAGAIN, so
    # write interest is never armed and no later Write event would drain it. The
    # hold above makes that one send() for every chunk in this batch (#334).
    return
  # omHttp releases what its task held: prBlocking, prFileChunk, or prNone (an
  # awaitable body's response -- its pkAwait rides omBlockingDone -- or a send from
  # a non-task thread). Hook as above; the resume may run just before the apply
  # instead of just after -- one message earlier.
  doAssert m.release notin {prAwait, prWsBlocking}
  if m.release != prNone:
    if not loop.releasePin(c, pinKindOf(m.release)): return
  elif c.closeRequested:
    loop.closeConn(c)          # connection died while the task ran
    return
  let bodyStart = unpackResponseInto(m.data, loop.unpackCt, loop.unpackHeaders)
  applyResponse(addr loop.core, c, m.stream, int(m.code), loop.unpackCt,
                loop.unpackHeaders,
                m.data.toOpenArray(bodyStart, m.data.len - 1))
  loop.resumeAfterRespond(c, m.stream)

proc releaseBatchFlushes(loop: Loop) =
  ## One socket write per connection for the whole outbox batch (#333). Each entry
  ## is the one hold deferBatchFlush took for that connection, so dropping it
  ## flushes everything the batch produced there. A connection that died while the
  ## batch was applied resolves to nil (its generation was bumped) and its hold
  ## goes with the slot -- clear() scrubs the counter before it is reused. Runs
  ## even if applying a message raised, so a hold is never leaked onto a live
  ## connection (which would mute its flush hook until the next batch).
  for (fd, gen) in loop.pendingFlush:
    let c = conn(addr loop.core, fd, gen)
    if c == nil: continue
    if releaseFlushHold(c) and (c.pendingOut > 0 or c.closeAfterFlush):
      loop.flushOut(c)
  loop.pendingFlush.setLen(0)

proc processOutbox(loop: Loop) =
  ## Apply worker-produced responses: unpin, write out, resume parsing. Each
  ## message is dispatched to a per-transport handler (see applyBlockingDone /
  ## applyOutboxH3 / applyOutboxConn), which enforces the stale-generation
  ## invariant before any pin bookkeeping.
  loop.outboxScratch.setLen(0)
  drain(loop.core.outbox, loop.outboxScratch)
  var h3Touched = false
  try:
    for m in loop.outboxScratch.mitems:
      if m.kind == omBlockingDone:
        loop.applyBlockingDone(m, h3Touched)
      elif m.fd < 0:
        when not defined(plainHttp):
          loop.applyOutboxH3(m, h3Touched)
        else:
          discard
      else:
        loop.applyOutboxConn(m)
  finally:
    loop.releaseBatchFlushes()
  # Recycle every sendFile read buffer from this batch back to the pool -- once,
  # here, so a buffer is returned exactly once whether its stream was alive (the
  # data was copied above) or the connection had died (the data is discarded).
  for m in loop.outboxScratch:
    if m.kind == omFileChunk and m.buf != nil:
      loop.core.chunkPool.chunkReturn(m.buf)
  when not defined(plainHttp):
    if h3Touched and loop.udpFd >= 0:
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
    if c.state == csFree: continue
    if c.writeDeadline != 0 and c.writeDeadline <= loop.core.nowSec:
      # Output pending but the socket stayed unwritable past writeTimeout: a
      # slow/stalled reader. Close regardless of the request deadline (which is
      # 0 for a mid-stream or active-h2 connection).
      loop.closeConn(c)
      continue
    if c.deadline == 0 or c.deadline > loop.core.nowSec:
      continue
    if c.dlKind == dkWsPing:
      loop.sweepWsPing(c)          # idle: ping, then wait for the pong
    elif c.dlKind == dkResponse and not c.rs.responded and c.totalPins == 0:
      # A deferred/async response never arrived within responseTimeout: answer
      # 503 and close instead of hanging. A late response arriving afterward is
      # dropped by the generation check on the (by then torn-down) connection.
      loop.respondError(c, Http503)
      loop.flushOut(c)
    else:
      loop.closeConn(c)            # includes dkWsPong: no reply, peer is gone

proc sweepWsIdle(loop: Loop) =
  ## Per-stream WebSocket keepalive for h2/h3 (h1 rides the deadline wheel
  ## above). Runs once a second over the tracked WsConns: ping an idle stream,
  ## close an unresponsive one, and drop closed ones from tracking.
  if loop.core.wsIdle.len == 0: return
  var survivors: seq[RootRef]
  var h3Touched = false
  for r in loop.core.wsIdle:
    let w = WsConn(r)
    # h2 ws (fd >= 0) needs its Connection to flush; h3 ws (fd < 0) reaches the
    # stream through the WsConn. A vanished h2 connection means the ws is gone.
    let c = if w.fd >= 0: conn(addr loop.core, w.fd, w.gen) else: nil
    if w.fd >= 0 and c == nil: continue
    let done = wsSweepIdle(addr loop.core, c, w)
    if w.fd < 0: h3Touched = true
    elif c != nil and pendingOut(c) > 0:
      loop.flushOut(c)             # push the ping / close DATA to the socket
    if not done: survivors.add r
  loop.core.wsIdle = survivors
  when not defined(plainHttp):
    if h3Touched and loop.udpFd >= 0:
      loop.h3Drive()

proc applyQuicReload(loop: Loop) =
  ## Loop thread: apply a pending QUIC certificate reload to this loop's shim
  ## engine in place. New h3 handshakes present the new cert; in-flight keep
  ## theirs. A failed reload keeps the running cert and is logged (not silently
  ## dropped); the generation is consumed either way, so a permanently-bad cert
  ## does not spin -- the operator fixes the files and re-issues the reload.
  when not defined(plainHttp):
    if loop.quicReload == nil or loop.udpFd < 0: return
    var cf, kf: string
    let gen = pendingCertReload(cast[ptr CertReload](loop.quicReload),
                                loop.quicReloadSeen, cf, kf)
    if gen != loop.quicReloadSeen:
      var ok = false
      try: ok = ngReloadCert(readFile(cf), readFile(kf))
      except CatchableError: ok = false
      if not ok:
        try:
          stderr.writeLine("vortex: HTTP/3 certificate reload failed; " &
                           "keeping the current certificate on this loop")
        except IOError, OSError: discard
      loop.quicReloadSeen = gen

proc tick(loop: Loop) =
  let now = monoSec()
  if now != loop.core.nowSec:
    loop.core.nowSec = now
    loop.refreshDate()
    loop.sweepTimeouts()
    loop.sweepWsIdle()
    loop.applyQuicReload()
    if loop.acceptSuspendedUntil != 0 and now >= loop.acceptSuspendedUntil and
        loop.listenFd >= 0 and not loop.draining:
      # The accept() backoff (suspendAccept) elapsed: re-arm the listener. If
      # fds are still exhausted the next accept() re-suspends it for another spell.
      try:
        loop.selector.registerHandle(loop.listenFd, {Event.Read}, fkListen)
        loop.acceptSuspendedUntil = 0
      except CatchableError:
        loop.acceptSuspendedUntil = now + 1   # retry next tick

# --- graceful shutdown ------------------------------------------------------

proc activeH3Conns(loop: Loop): int =
  when not defined(plainHttp):
    # Index-based nil check: a `for slot in h3slots` value copy would materialize
    # slot.conn (an ORC ref) on every drainDone poll, racing an h3 worker that
    # holds the same ref. A `!= nil` on the indexed field is a plain pointer read.
    for i in 0 ..< loop.core.h3slots.len:
      if loop.core.h3slots[i].conn != nil: inc result

proc markDrain(loop: Loop, c: ptr Connection) =
  ## Signal one TCP connection to finish its in-flight work and close.
  if c.state != csActive: return
  if c.totalPins > 0: return
    # A blocking: worker holds this connection. Don't touch its h2 ref here
    # (h2Goaway materializes H2Conn(c.h2)) concurrently with the worker under
    # ORC's non-atomic refcounts. It stays counted (connCount > 0) so the loop
    # will not exit, and forceCloseAll closes it once the worker unpins.
  if c.h2 != nil:
    # RFC 9113 6.8 two-step drain: send the GOAWAY(2^31-1) notice so streams
    # already on the wire (and any racing new ones) still complete. An idle
    # connection has nothing in flight, so finalize immediately (GOAWAY notice +
    # real cutoff + close); a busy one keeps going and drainSweep finalizes it
    # once its streams drain.
    h2GoawayNotice(c)
    if h2ActiveStreams(c) == 0:
      h2Goaway(c)                         # final GOAWAY(lastStreamId), then close
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
    for i in 0 ..< loop.core.h3slots.len:
      let slot = addr loop.core.h3slots[i]
      # Skip a slot pinned by an h3 blocking: worker (see markDrain): touching
      # H3Conn(slot.conn) here would race the worker's non-atomic ORC refcount.
      if slot.totalPins == 0 and slot.conn != nil:
        h3Goaway(H3Conn(slot.conn))   # RFC 9114 GOAWAY
  let grace = max(0, loop.settings.shutdownGrace)
  loop.drainDeadline = loop.core.nowSec + int64(grace)

proc drainSweep(loop: Loop) =
  ## Close connections that finished their in-flight work this iteration.
  for fd in 0 ..< loop.core.conns.len:
    let c = addr loop.core.conns[fd]
    if c.state != csActive: continue
    if c.totalPins > 0: continue
      # A pinned connection is not "finished" (a blocking: worker is running),
      # so it never met the close conditions below anyway. Skipping it also
      # avoids materializing its h2 ref here (H2Conn(c.h2)) concurrently with
      # the worker, which under ORC's non-atomic refcounts would corrupt the
      # count. forceCloseAll (deferred) closes it once the worker unpins.
    if c.h2 != nil:
      # An h2 connection that has drained its in-flight streams: send the final
      # GOAWAY(lastStreamId) (the real cutoff, if only the notice went out) so a
      # client can retry any request above it, then close.
      let h2 = h2Conn(c)
      if h2ActiveStreams(c) == 0 and (h2.drainNoticeSent or h2.goingAway):
        if not h2.goingAway: h2Goaway(c)
        if c.pendingOut > 0: c.closeAfterFlush = true
        else: loop.closeConn(c)
    elif c.ws == nil and not c.awaitingResponse and c.pendingOut == 0:
      loop.closeConn(c)                   # h1 became idle after its response
  when not defined(plainHttp):
    for i in 0 ..< loop.core.h3slots.len:
      let slot = addr loop.core.h3slots[i]
      # Skip a slot pinned by an h3 blocking: worker: h3FreeSlot would defer
      # anyway, and this avoids materializing H3Conn(slot.conn) here while the
      # worker holds the same ref (non-atomic ORC refcount race).
      if slot.totalPins > 0: continue
      if slot.conn != nil:
        let h3c = H3Conn(slot.conn)
        # Final GOAWAY (once), after beginDrain's notice went out on a prior
        # iteration: completes the RFC 9114 5.2 two-step drain so the peer learns
        # the last-accepted stream id before the connection closes.
        h3Shutdown(h3c)
        if h3c.h3StreamCount == 0:
          # No in-flight request streams left: close cleanly. The shim flushes
          # the queued final GOAWAY, then emits CONNECTION_CLOSE and reaps the
          # connection, which fires on_conn_close -> the slot is freed. (Freeing
          # the slot here instead would set c->closed immediately and the GOAWAY
          # /CONNECTION_CLOSE would never reach the wire -- the old bug.)
          h3GracefulClose(h3c)

proc forceCloseAll(loop: Loop) =
  ## Grace expired: drop whatever is still open. A connection still pinned by a
  ## running `blocking:` worker is NOT force-freed here: closeConn / h3FreeSlot
  ## defer its teardown (unregister the fd, keep the slot) until the worker
  ## unpins, because the worker is still reading request state and, for h2/h3,
  ## the protocol object we would free. The run loop keeps spinning (still
  ## processing the outbox) until those pins clear, so we never free a slot or
  ## the loop itself under a worker. Idempotent, so re-calling each tick is fine.
  for fd in 0 ..< loop.core.conns.len:
    let c = addr loop.core.conns[fd]
    if c.state != csFree:
      loop.closeConn(c)
  when not defined(plainHttp):
    for i in 0 ..< loop.core.h3slots.len:
      loop.h3FreeSlot(i)

proc drainDone(loop: Loop): bool {.inline.} =
  loop.connCount == 0 and loop.activeH3Conns == 0

proc drainComplete(loop: Loop): bool =
  ## Can the drain loop exit? All connections must be gone AND the async adapter
  ## must have no pending operations. A `blocking:` worker's result is delivered
  ## via the outbox, which completes the awaiting future and *then* frees the
  ## connection; the future's own continuation is scheduled on the adapter's
  ## dispatcher and runs on a later pump. If we exited on connCount alone, that
  ## in-flight continuation (and the future + blocking box it holds) would be
  ## orphaned at teardown instead of released -- a shutdown-time leak. So keep
  ## pumping until the adapter drains (pumpCap < 0), bounded by a short deadline
  ## so a never-completing future can't wedge shutdown.
  ##
  ## `pendingBlockingResults` covers the earlier window too: a void async
  ## `req.blocking` body's `res.send` releases the connection pin one outbox
  ## message before its `omBlockingDone`, so `drainDone` (connection count) can
  ## reach 0 while the completion is still in flight. Waiting for it guarantees
  ## the worker's `onDone` runs -- completing the awaiting future -- before exit,
  ## instead of orphaning the future and its suspended continuation.
  if not loop.drainDone(): return false
  if loop.pumpCap < 0 and loop.core.pendingBlockingResults == 0: return true
  if loop.asyncDrainDeadline == 0:
    loop.asyncDrainDeadline = loop.core.nowSec + 3
    return false
  loop.core.nowSec >= loop.asyncDrainDeadline

proc run*(loop: Loop) =
  loop.core.threadId = getThreadId()
  loop.core.hooks.kick = kickImpl
  loop.core.hooks.flushHook = flushImpl
  loop.core.hooks.resumeBodyHook = resumeBodyImpl
  installWsHooks(addr loop.core)   # h2 WebSocket (RFC 8441) stream lookup
  when not defined(plainHttp):
    installH3WsHooks(addr loop.core)   # h3 WebSocket (RFC 9220) stream lookup
  loop.pumpCap = -1
  var keys: array[256, ReadyKey]
  while true:
    if loop.stopFlag[].load(moRelaxed) and not loop.draining:
      loop.tick()                     # refresh nowSec before arming the deadline
      loop.beginDrain()
    if loop.draining and loop.drainComplete():
      break
    var timeoutMs = 1000
    if loop.draining:
      timeoutMs = 100                 # check the grace deadline promptly
    if loop.pumpCap >= 0:
      # An adapter has pending async operations: bound the wait so
      # timer/IO completions from its dispatcher aren't starved.
      timeoutMs = min(timeoutMs, max(1, loop.pumpCap))
    if loop.bodyPausedConns > 0:
      # A streaming read is paused at the read-ahead high-water (recv loop stopped
      # pulling; fd still armed). The async consumer drains from its own queue on
      # the pump; its ack un-pauses the read. But between drained chunks the
      # dispatcher can briefly report no pending operations (pumpCap = -1), which
      # would let the selector block for the full 1s idle wait and stall the drain.
      # Cap the wait so the pump keeps cycling until the consumer catches up.
      timeoutMs = min(timeoutMs, 2)
    when not defined(plainHttp):
      if loop.udpFd >= 0:
        let qt = ngTimeoutMs()
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
        # Guard like the per-connection block below: a raise while applying a
        # worker response or accepting a connection must never take down the
        # whole loop thread (R11).
        try: loop.processOutbox()
        except Exception: discard
        continue
      if key.fd == loop.listenFd:
        try: loop.handleAccept()
        except Exception: discard
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
        if c.awaitingProxy:
          loop.handleProxyHeader(c)   # read the PROXY header before TLS/HTTP
          continue
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
      # Drive QUIC on datagrams, timer expiry, and every wakeup: the stack owns
      # its own retransmission/idle timers.
      if loop.udpFd >= 0:
        discard quicWork
        try: loop.h3Drive()
        except Exception: discard
    if loop.core.hooks.pumpHook != nil:
      # Pump at the end of the iteration so callbacks scheduled while
      # handling this batch (e.g. an await that completed immediately)
      # finish in the same pass instead of after a selector timeout.
      loop.pumpCap = loop.core.hooks.pumpHook()
    loop.tick()
    if loop.draining:
      loop.drainSweep()               # close connections that just finished
      if loop.drainComplete():
        break
      if loop.core.nowSec >= loop.drainDeadline:
        loop.forceCloseAll()          # grace expired: drop the rest
        if loop.drainComplete():
          break
        # Everything else is a connection still pinned by a running blocking:
        # worker; forceCloseAll deferred its teardown. Keep the loop alive and
        # processing the outbox until the workers finish and unpin, rather than
        # freeing the loop's memory under them (use-after-free). Nim has no safe
        # way to cancel a running thread, so a `blocking:` handler that never
        # returns cannot be reclaimed -- surface it once instead of hanging
        # silently, so the operator can see why shutdown is stuck.
        if not loop.warnedDrainStuck:
          loop.warnedDrainStuck = true
          var stuck = 0
          for fd in 0 ..< loop.core.conns.len:
            if loop.core.conns[fd].state != csFree and
                loop.core.conns[fd].totalPins > 0: inc stuck
          try: stderr.writeLine("vortex: graceful shutdown is waiting on " &
            $stuck & " connection(s) held by a still-running blocking: " &
            "handler; the loop cannot exit until they return (a handler that " &
            "never returns will block shutdown -- blocking: bodies must finish)")
          except IOError, OSError: discard
  when not defined(plainHttp):
    if loop.udpFd >= 0:
      for i in 0 ..< loop.core.h3slots.len:
        loop.core.h3slots[i].pins.reset()
        loop.h3FreeSlot(i)
      ngEngineFree()              # frees the shim engine (all conns + TLS ctx)
      discard posix.close(cint(loop.udpFd))
  loop.selector.close()
  loop.core.chunkPool.chunkPoolFree()    # free pooled sendFile buffers (workers joined)
  if loop.listenFd >= 0:                 # beginDrain may have closed it already
    discard posix.close(cint(loop.listenFd))
  if loop.core.hooks.teardownHook != nil:      # release the async adapter's dispatcher
    loop.core.hooks.teardownHook()

type LoopThreadArg* = tuple
  ## Plain-data bundle for starting a loop on its own thread; the Loop
  ## itself is constructed inside the thread (refs never cross threads).
  ## The outbox is created by the caller (see connection.newOutbox) and
  ## freed by the caller after workers and loops have stopped.
  settings: VortexConfig
  handler: RequestHandler
  stopFlag: ptr Atomic[bool]
  listenFd: SocketHandle
  pool: pointer
  outbox: ptr Outbox
  tls: pointer
  udpFd: SocketHandle
  streamRoute: StreamRouteCb
  quicReload: pointer
  alive: ptr Atomic[int]     ## shared live-thread counter; decremented when this
                             ## loop thread exits so a timed shutdown can detect a
                             ## loop wedged by a stuck worker (nil = not tracked)

proc runLoopThread*(arg: LoopThreadArg) {.thread, gcsafe.} =
  # An unhandled exception escaping a thread proc aborts the whole process.
  # newLoop can raise (fd exhaustion, a QUIC cert that changed since the probe),
  # and run() is defended per-connection but not absolutely; contain both so one
  # loop failing degrades the server instead of killing it. Close this loop's
  # listeners so its share of connections isn't blackholed by a dead listener.
  try:
    block:
      let loop = newLoop(arg.settings, arg.handler, arg.stopFlag, arg.listenFd,
                         arg.pool, arg.outbox, arg.tls, arg.udpFd,
                         arg.streamRoute, arg.quicReload)
      loop.run()
    # The Loop (and any async-dispatcher state) is now out of scope. Under ORC,
    # a cyclic object decref'd here is only queued in this thread's cycle-root
    # buffer; if the thread exits with it still queued, the process-exit
    # collection on the main thread walks this (now-gone) thread's buffer and
    # crashes. Force the collection here, on the owning thread, so nothing is
    # left for teardown to trip over.
    when defined(gcOrc): GC_fullCollect()
  except CatchableError, Defect:
    try: stderr.writeLine("vortex: event-loop thread exited on error: " &
                          getCurrentExceptionMsg())
    except IOError, OSError: discard
    if arg.listenFd != osInvalidSocket:
      discard posix.close(cint(arg.listenFd))
    if arg.udpFd != osInvalidSocket:
      discard posix.close(cint(arg.udpFd))
  # Mark this loop thread as exited last (both the clean and error paths), so a
  # timed shutdown (server.waitFor) knows every loop is truly gone before it
  # joins/frees -- and can detach instead of hang if run() never returned.
  if arg.alive != nil: discard arg.alive[].fetchSub(1, moAcquireRelease)
