## Server lifecycle: N event-loop threads (each with its own SO_REUSEPORT
## listener; the kernel load-balances connections) plus a shared worker
## pool for `blocking:` code.

import std/[atomics, cpuinfo]
when defined(nimdoc):
  # See eventloop.nim: `nim doc` (-d:nimdoc) flips net/nativesockets to winlean
  # types, colliding with std/posix. Resolve the two clashing names from posix
  # for doc builds; the real build (`else`) is unchanged.
  import std/nativesockets except SocketHandle, osInvalidSocket
  import std/posix
  const osInvalidSocket = SocketHandle(-1)
else:
  import std/[posix, nativesockets, net]
import ./settings, ./request, ./eventloop, ./connection, ./workerpool
when not defined(plainHttp):
  import ./transport/tls
  # CertReload lives in transport/tls; the per-loop ngtcp2 engine is built in
  # eventloop.newLoop.

# Each Server owns its own stop flag (shared memory, one per instance) so that
# stopping or starting one server never disturbs another in the same process.
# A small lock-free registry of the live flags lets a signal handler (and the
# no-arg requestShutdown) fan a stop out to every server without a lock or
# allocation, which a signal handler must avoid.
const maxRegisteredServers = 256
var serverFlags: array[maxRegisteredServers, Atomic[pointer]]  # ptr Atomic[bool]

proc registerServerFlag(flag: ptr Atomic[bool]) =
  for i in 0 ..< maxRegisteredServers:
    var expected: pointer = nil
    if serverFlags[i].compareExchange(expected, cast[pointer](flag)):
      return
  # Registry full (>256 live servers): the global/signal fan-out won't reach
  # this one, but close(server) still stops it via its own flag.

proc unregisterServerFlag(flag: ptr Atomic[bool]) =
  for i in 0 ..< maxRegisteredServers:
    var expected = cast[pointer](flag)
    if serverFlags[i].compareExchange(expected, pointer(nil)):
      return

proc requestShutdown*() =
  ## Ask every running server's event loops to stop after their current tick.
  ## Async-signal-safe (only atomic loads/stores, no lock or allocation).
  for i in 0 ..< maxRegisteredServers:
    let p = serverFlags[i].load(moRelaxed)
    if p != nil:
      cast[ptr Atomic[bool]](p)[].store(true, moRelaxed)

proc installSignalHandlers() =
  proc onSignal(sig: cint) {.noconv.} =
    requestShutdown()
  signal(SIGINT, onSignal)
  signal(SIGTERM, onSignal)
  signal(SIGPIPE, SIG_IGN)

type
  Server* = object
    threads: seq[Thread[LoopThreadArg]]
    outboxes: seq[ptr Outbox]
    pool: ptr WorkerPool
    stopFlag: ptr Atomic[bool]  ## this server's own stop signal (shared memory)
    tls: pointer               ## ptr TlsConfig or nil
    quicReload: pointer        ## ptr CertReload: signals loops to reload h3 certs
    port*: Port                ## actual bound port (settings may say 0)

proc requestShutdown*(server: var Server) =
  ## Ask just this server's event loops to stop after their current tick.
  if server.stopFlag != nil:
    server.stopFlag[].store(true, moRelaxed)

proc validateConfig(s: VortexConfig) =
  ## Reject nonsensical/dangerous configurations up front rather than failing
  ## silently at run time.
  let hasCert = s.certFile.len > 0 or s.certPem.len > 0
  let hasKey = s.keyFile.len > 0 or s.keyPem.len > 0
  if hasKey and not hasCert:
    raise newException(CatchableError,
      "a private key is set but no certificate: this would serve plaintext. " &
      "Set both (file or PEM) to enable TLS, or neither for plain HTTP.")
  if hasCert and not hasKey:
    raise newException(CatchableError, "a certificate is set but no private key.")
  if s.minTlsVersion == TlsVersion.V13 and s.maxTlsVersion == TlsVersion.V12:
    raise newException(CatchableError,
      "maxTlsVersion (TLS 1.2) is below minTlsVersion (TLS 1.3).")
  if s.maxHeaderSize < 0 or s.maxBodySize < 0 or s.maxWsMessageSize < 0 or
     s.headerTimeout < 0 or s.bodyTimeout < 0 or s.keepAliveTimeout < 0 or
     s.responseTimeout < 0 or s.shutdownGrace < 0 or s.maxConnections < 0 or
     s.numThreads < 0 or s.workerThreads < 0:
    raise newException(CatchableError, "settings must not be negative")

proc startServer(handler: RequestHandler, settings: VortexConfig,
                 streamRoute: StreamRouteCb = nil): Server =
  ## Internal: bind, start loops + workers in the background, return immediately.
  ## The public entry point is the `Vortex` object (`newVortex`, `serve`,
  ## `start`) at the bottom of this module.
  validateConfig(settings)
  signal(SIGPIPE, SIG_IGN)   # a mid-response client reset must not kill us
                             # (OpenSSL's raw write on Linux has no MSG_NOSIGNAL)
  result.stopFlag = createShared(Atomic[bool])   # zero-init == false
  registerServerFlag(result.stopFlag)
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
    if settings.hasTls:
      let minVer = case settings.minTlsVersion
                   of TlsVersion.None, TlsVersion.V12: TLS1_2_VERSION  # None: secure default floor
                   of TlsVersion.V13: TLS1_3_VERSION
      result.tls = cast[pointer](
        newTlsConfig(settings.certFile, settings.keyFile, enableH2 = true,
                     minProtoVersion = minVer,
                     cipherList = settings.tlsCipherList,
                     cipherSuites = settings.tlsCipherSuites,
                     certPem = settings.certPem, keyPem = settings.keyPem,
                     keyPassword = settings.keyPassword,
                     pkcs12File = settings.pkcs12File, pkcs12 = settings.pkcs12,
                     verify = tlsVerifyMode(settings.verifyClient),
                     clientCaFile = settings.clientCaFile,
                     clientCaPem = settings.clientCaPem,
                     sni = toSniCerts(settings),
                     maxProtoVersion = tlsMaxVer(settings.maxTlsVersion),
                     ocsp = ocspBytes(settings)))
  else:
    if settings.hasTls:
      raise newException(CatchableError,
        "TLS requested but built with -d:plainHttp")

  var fds = newSeq[SocketHandle](numLoops)
  var udpFds = newSeq[SocketHandle](numLoops)
  for i in 0 ..< numLoops:
    fds[i] = osInvalidSocket
    udpFds[i] = osInvalidSocket
  var madeThreads = 0
  # Anything past the worker pool can fail (a taken port, fd exhaustion, a cert
  # that changed since the probe, createThread). Unwind everything acquired so
  # far so a caught-and-retried start() does not leak threads, fds, or memory.
  try:
    fds[0] = newListenSocket(settings)
    result.port = boundPort(fds[0])
    var cfg = settings
    cfg.port = result.port     # extra listeners bind the resolved port
    for i in 1 ..< numLoops:
      fds[i] = newListenSocket(cfg)

    when not defined(plainHttp):
      if result.tls != nil and settings.http3:
        # The TCP TLS config above already validated the same cert/key, so no
        # separate QUIC probe is needed: each loop builds its own ngtcp2 engine
        # (which loads the cert) in newLoop, and a valid udpFd is the loops'
        # "h3 enabled" signal.
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
                    stopFlag: result.stopFlag, listenFd: fds[i],
                    pool: cast[pointer](result.pool),
                    outbox: result.outboxes[i], tls: result.tls,
                    udpFd: udpFds[i],
                    streamRoute: streamRoute, quicReload: result.quicReload))
      inc madeThreads
  except CatchableError:
    # Stop and join any loops already started (they own their listen/udp fds and
    # close them on exit), then free everything else and re-raise.
    result.stopFlag[].store(true, moRelaxed)
    for i in 0 ..< madeThreads: joinThread result.threads[i]
    for i in madeThreads ..< numLoops:      # fds of loops that never started
      if fds[i] != osInvalidSocket: discard posix.close(cint(fds[i]))
      if udpFds[i] != osInvalidSocket: discard posix.close(cint(udpFds[i]))
    for ob in result.outboxes:
      if ob != nil: freeOutbox ob
    result.outboxes.setLen(0)
    result.threads.setLen(0)
    result.pool.shutdown()
    deallocShared result.pool
    when not defined(plainHttp):
      if result.tls != nil: freeTlsConfig(cast[ptr TlsConfig](result.tls))
      if result.quicReload != nil:
        deinitCertReload(cast[ptr CertReload](result.quicReload))
        deallocShared result.quicReload
    unregisterServerFlag(result.stopFlag)
    deallocShared result.stopFlag
    raise

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
  if server.stopFlag != nil:
    unregisterServerFlag(server.stopFlag)
    deallocShared(server.stopFlag)
    server.stopFlag = nil

proc close*(server: var Server) =
  ## Stop and tear down. Stops only this server, not others in the process.
  server.requestShutdown()
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

# --- the Vortex object API --------------------------------------------------

type
  Vortex* = ref object
    ## A configured HTTP server. Build one with `newVortex`, tweak `config`,
    ## then `serve` (blocking) or `start` (non-blocking).
    handler: RequestHandler
    streamRoute: StreamRouteCb
    config*: VortexConfig     ## Mutable until `serve`/`start`, which copy it
                              ## into the loop threads; changing it after has no
                              ## effect (set everything before serving).
    server: Server
    started: bool

proc newVortex*(handler: RequestHandler, config = initVortexConfig(),
                streamRoute: StreamRouteCb = nil): Vortex =
  ## Create a server for `handler`. Pass a `config` to override defaults (or edit
  ## `vortex.config` before serving). `streamRoute` (e.g. `router.streamPredicate`)
  ## opts requests into inbound streaming; nil keeps every request buffered.
  Vortex(handler: handler, config: config, streamRoute: streamRoute)

proc start*(v: Vortex, port = -1, address = ""): Vortex {.discardable.} =
  ## Start serving in the background and return immediately (for embedding and
  ## tests). Read the resolved port from `v.port`, stop with `v.close`. `port`
  ## overrides `config.port` when >= 0 (0 = pick a free port); -1 keeps the
  ## configured port. Returns `v` for chaining: `newVortex(h).start(0)`.
  if port >= 0: v.config.port = Port(port)
  if address.len > 0: v.config.address = address
  v.server = startServer(v.handler, v.config, v.streamRoute)
  v.started = true
  v

proc serve*(v: Vortex, port = -1, address = "") =
  ## Start serving and block until SIGINT/SIGTERM or `requestShutdown`, then shut
  ## down gracefully. `port`/`address` override `config` as in `start`.
  installSignalHandlers()
  discard v.start(port, address)
  v.server.waitFor()

proc port*(v: Vortex): Port =
  ## The actual bound port (useful after `start(0)`); Port(0) before serving.
  ## `$v.port` gives the number for building URLs.
  v.server.port

proc requestShutdown*(v: Vortex) =
  ## Ask this server's loops to stop after their current tick (non-blocking).
  v.server.requestShutdown()

proc waitFor*(v: Vortex) =
  ## Block until the loops exit (after `requestShutdown` or a signal).
  v.server.waitFor()

proc close*(v: Vortex) =
  ## Stop and tear down this server (only this one, not others in the process).
  v.server.close()

proc stop*(v: Vortex) =
  ## Alias for `close`.
  v.server.close()

proc reloadTls*(v: Vortex, certFile = "", keyFile = ""): bool =
  ## Hot-reload the TLS cert/key for new connections without a restart (see the
  ## Server-level docs). Returns false if TLS is off or the new material is bad.
  v.server.reloadTls(certFile, keyFile)
