import std/net

type
  TlsMinVersion* = enum
    tlsV12,   ## TLS 1.2 minimum (default; disallows the insecure 1.0/1.1)
    tlsV13    ## TLS 1.3 only

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
    maxWsMessageSize*: int    ## largest inbound WebSocket message (close 1009 over it)

    # DoS budgets (0 disables the check)
    maxConnections*: int          ## live connections per loop thread
    maxConcurrentStreams*: int    ## open h2/h3 streams per connection
    maxResetStreams*: int         ## h2 peer resets before GOAWAY (rapid reset)
    maxControlFrames*: int        ## h2 PING/SETTINGS/etc. between stream progress
    maxRequestsPerSocket*: int    ## HTTP/1 keep-alive requests before close

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
    minTlsVersion*: TlsMinVersion  ## lowest accepted TLS version (TCP; QUIC is always 1.3)
    tlsCipherList*: string    ## OpenSSL cipher list for TLS <= 1.2 ("" = default)
    tlsCipherSuites*: string  ## OpenSSL cipher suites for TLS 1.3 ("" = default)

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
    maxWsMessageSize = 1024 * 1024,
    maxConnections = 65536,
    maxConcurrentStreams = 256,
    maxResetStreams = 512,
    maxControlFrames = 1000,
    maxRequestsPerSocket = 0,
    headerTimeout = 10,
    bodyTimeout = 30,
    keepAliveTimeout = 60,
    shutdownGrace = 10,
    serverHeader = "vortex",
    certFile = "",
    keyFile = "",
    http3 = true,
    minTlsVersion = tlsV12,
    tlsCipherList = "",
    tlsCipherSuites = ""
): Settings =
  Settings(
    port: port, address: address, numThreads: numThreads,
    workerThreads: workerThreads, listenBacklog: listenBacklog,
    reusePort: reusePort, maxHeaderSize: maxHeaderSize,
    maxHeaderCount: maxHeaderCount, maxBodySize: maxBodySize,
    initialBufferSize: initialBufferSize,
    maxWsMessageSize: maxWsMessageSize,
    maxConnections: maxConnections,
    maxConcurrentStreams: maxConcurrentStreams,
    maxResetStreams: maxResetStreams, maxControlFrames: maxControlFrames,
    maxRequestsPerSocket: maxRequestsPerSocket,
    headerTimeout: headerTimeout,
    bodyTimeout: bodyTimeout, keepAliveTimeout: keepAliveTimeout,
    shutdownGrace: shutdownGrace, serverHeader: serverHeader,
    certFile: certFile, keyFile: keyFile, http3: http3,
    minTlsVersion: minTlsVersion, tlsCipherList: tlsCipherList,
    tlsCipherSuites: tlsCipherSuites
  )
