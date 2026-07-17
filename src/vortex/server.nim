## Server lifecycle: N event-loop threads (each with its own SO_REUSEPORT
## listener; the kernel load-balances connections) plus a shared worker
## pool for `blocking:` code.

import std/[atomics, posix, cpuinfo, nativesockets, net]
import ./settings, ./request, ./eventloop, ./connection, ./workerpool
when not defined(plainHttp):
  import ./transport/tls
  import ./transport/quic

var stopRequested: Atomic[bool]

proc requestShutdown*() =
  ## Ask all event loops to stop after their current tick.
  stopRequested.store(true, moRelaxed)

proc installSignalHandlers() =
  proc onSignal(sig: cint) {.noconv.} =
    stopRequested.store(true, moRelaxed)
  signal(SIGINT, onSignal)
  signal(SIGTERM, onSignal)
  signal(SIGPIPE, SIG_IGN)

type
  Server* = object
    threads: seq[Thread[LoopThreadArg]]
    outboxes: seq[ptr Outbox]
    pool: ptr WorkerPool
    tls: pointer               ## ptr TlsConfig or nil
    quicReload: pointer        ## ptr CertReload: signals loops to reload h3 certs
    port*: Port                ## actual bound port (settings may say 0)

proc start*(handler: RequestHandler, settings = initSettings(),
            streamRoute: StreamRouteCb = nil): Server =
  ## Start loops and workers in the background; returns immediately.
  ## Use `close` (or `waitFor` after installing your own stop signal)
  ## to shut down. `streamRoute` (e.g. `router.streamPredicate`) opts requests
  ## into inbound streaming; nil keeps every request buffered.
  stopRequested.store(false, moRelaxed)
  var numLoops =
    if settings.numThreads > 0: settings.numThreads
    else: max(1, countProcessors())
  if not settings.reusePort:
    numLoops = 1               # per-thread listeners require SO_REUSEPORT
  let numWorkers =
    if settings.workerThreads > 0: settings.workerThreads
    else: numLoops * 2

  result.pool = createShared(WorkerPool)
  result.pool.start(numWorkers)

  when not defined(plainHttp):
    if settings.certFile.len > 0:
      let minVer = case settings.minTlsVersion
                   of tlsV12: TLS1_2_VERSION
                   of tlsV13: TLS1_3_VERSION
      result.tls = cast[pointer](
        newTlsConfig(settings.certFile, settings.keyFile, enableH2 = true,
                     minProtoVersion = minVer,
                     cipherList = settings.tlsCipherList,
                     cipherSuites = settings.tlsCipherSuites))
  else:
    if settings.certFile.len > 0:
      raise newException(CatchableError,
        "TLS requested but built with -d:plainHttp")

  var fds = newSeq[SocketHandle](numLoops)
  fds[0] = newListenSocket(settings)
  result.port = boundPort(fds[0])
  var cfg = settings
  cfg.port = result.port       # extra listeners bind the resolved port
  for i in 1 ..< numLoops:
    fds[i] = newListenSocket(cfg)

  var udpFds = newSeq[SocketHandle](numLoops)
  for i in 0 ..< numLoops:
    udpFds[i] = osInvalidSocket
  when not defined(plainHttp):
    if result.tls != nil and settings.http3:
      # Validate the QUIC cert/method once up front (raises on failure), then
      # discard the probe: each loop builds its own private ctx for in-place
      # hot-reload, and a valid udpFd is the loops' "h3 enabled" signal.
      freeTlsConfig(newQuicConfig(settings.certFile, settings.keyFile,
                                  cipherSuites = settings.tlsCipherSuites))
      result.quicReload = createShared(CertReload)
      initCertReload(cast[ptr CertReload](result.quicReload))
      for i in 0 ..< numLoops:
        udpFds[i] = newUdpSocket(cfg)

  result.threads = newSeq[Thread[LoopThreadArg]](numLoops)
  result.outboxes = newSeq[ptr Outbox](numLoops)
  for i in 0 ..< numLoops:
    result.outboxes[i] = newOutbox()
    createThread(result.threads[i], runLoopThread,
                 (settings: cfg, handler: handler,
                  stopFlag: addr stopRequested, listenFd: fds[i],
                  pool: cast[pointer](result.pool),
                  outbox: result.outboxes[i], tls: result.tls,
                  udpFd: udpFds[i],
                  streamRoute: streamRoute, quicReload: result.quicReload))

proc waitFor*(server: var Server) =
  ## Block until the loops exit (stop signal), then tear down workers.
  for t in server.threads.mitems:
    joinThread t
  server.threads.setLen(0)
  server.pool.shutdown()       # workers may still push; loops are gone but
                               # outbox events stay valid until freed below
  deallocShared server.pool
  server.pool = nil
  for ob in server.outboxes:
    freeOutbox ob
  server.outboxes.setLen(0)
  when not defined(plainHttp):
    if server.tls != nil:
      freeTlsConfig(cast[ptr TlsConfig](server.tls))
      server.tls = nil
    if server.quicReload != nil:
      deinitCertReload(cast[ptr CertReload](server.quicReload))
      deallocShared(server.quicReload)
      server.quicReload = nil

proc close*(server: var Server) =
  ## Stop and tear down.
  requestShutdown()
  server.waitFor()

proc reloadTls*(server: var Server, certFile = "", keyFile = ""): bool =
  ## Hot-reload the TLS certificate/key for new HTTPS (HTTP/1.1 and HTTP/2)
  ## connections, without a restart and without dropping in-flight ones. Pass
  ## new paths, or leave empty to re-read the originally configured files (e.g.
  ## after certbot renewed them in place). Returns false if TLS is not enabled,
  ## or the new cert/key is missing/invalid/mismatched -- in which case the
  ## running certificate is kept, so a bad renewal never takes the server down.
  ##
  ## Call from an ordinary thread (e.g. your own SIGHUP handling loop), not from
  ## inside a raw signal handler. Covers HTTP/1.1, HTTP/2, and (when enabled)
  ## HTTP/3: each h3 loop updates its own QUIC ctx in place on its next tick, so
  ## new h3 handshakes use the new certificate while in-flight ones keep theirs.
  when defined(plainHttp):
    false
  else:
    if server.tls == nil: return false
    let ok = reloadTlsConfig(cast[ptr TlsConfig](server.tls), certFile, keyFile)
    # Only signal the h3 loops when the TCP reload succeeded, so TCP and h3
    # never end up on different certificates and the returned bool applies to
    # both. A per-loop h3 apply failure (e.g. a transient bad read) is logged by
    # the loop; re-issue reloadTls to retry it.
    if ok and server.quicReload != nil:
      requestCertReload(cast[ptr CertReload](server.quicReload),
                        certFile, keyFile)
    ok

proc run*(handler: RequestHandler, settings = initSettings(),
          streamRoute: StreamRouteCb = nil) =
  ## Start serving; blocks until SIGINT/SIGTERM or `requestShutdown`.
  installSignalHandlers()
  var server = start(handler, settings, streamRoute)
  server.waitFor()
