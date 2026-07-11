import std/net

type
  Settings* = object
    port*: Port
    address*: string          ## bind address, "" = all interfaces
    numThreads*: int          ## 0 = countProcessors()
    workerThreads*: int       ## worker pool size for `blocking:` (0 = numThreads * 2)
    listenBacklog*: int
    reusePort*: bool          ## SO_REUSEPORT per-thread listeners

    # Limits (bytes unless noted)
    maxHeaderSize*: int       ## request line + headers, 431 when exceeded
    maxHeaderCount*: int      ## 400 when exceeded
    maxBodySize*: int         ## 413 when exceeded
    initialBufferSize*: int   ## per-connection read/write buffer starting size

    # DoS budgets (0 disables the check)
    maxConnections*: int          ## live connections per loop thread
    maxConcurrentStreams*: int    ## open h2/h3 streams per connection
    maxResetStreams*: int         ## h2 peer resets before GOAWAY (rapid reset)
    maxControlFrames*: int        ## h2 PING/SETTINGS/etc. between stream progress

    # Timeouts (seconds, coarse; 0 disables)
    headerTimeout*: int       ## from first byte of a request to end of headers
    bodyTimeout*: int         ## from end of headers to end of body
    keepAliveTimeout*: int    ## idle time between requests
    shutdownGrace*: int       ## drain window on graceful shutdown

    serverHeader*: string     ## "" disables the Server header

    # TLS (both must be set to enable; PEM format)
    certFile*: string
    keyFile*: string
    http3*: bool              ## serve HTTP/3 over QUIC (requires certFile)

proc initSettings*(
    port = Port(8080),
    address = "",
    numThreads = 0,
    workerThreads = 0,
    listenBacklog = 1024,
    reusePort = true,
    maxHeaderSize = 16 * 1024,
    maxHeaderCount = 100,
    maxBodySize = 8 * 1024 * 1024,
    initialBufferSize = 8 * 1024,
    maxConnections = 65536,
    maxConcurrentStreams = 256,
    maxResetStreams = 512,
    maxControlFrames = 1000,
    headerTimeout = 10,
    bodyTimeout = 30,
    keepAliveTimeout = 60,
    shutdownGrace = 10,
    serverHeader = "vortex",
    certFile = "",
    keyFile = "",
    http3 = true
): Settings =
  Settings(
    port: port, address: address, numThreads: numThreads,
    workerThreads: workerThreads, listenBacklog: listenBacklog,
    reusePort: reusePort, maxHeaderSize: maxHeaderSize,
    maxHeaderCount: maxHeaderCount, maxBodySize: maxBodySize,
    initialBufferSize: initialBufferSize,
    maxConnections: maxConnections,
    maxConcurrentStreams: maxConcurrentStreams,
    maxResetStreams: maxResetStreams, maxControlFrames: maxControlFrames,
    headerTimeout: headerTimeout,
    bodyTimeout: bodyTimeout, keepAliveTimeout: keepAliveTimeout,
    shutdownGrace: shutdownGrace, serverHeader: serverHeader,
    certFile: certFile, keyFile: keyFile, http3: http3
  )
