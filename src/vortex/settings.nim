import std/net

type
  TlsMinVersion* = enum
    tlsV12,   ## TLS 1.2 minimum (default; disallows the insecure 1.0/1.1)
    tlsV13    ## TLS 1.3 only

  ClientVerify* = enum
    cvNone,      ## no client certificate requested (default)
    cvOptional,  ## request a client cert; if presented it must verify (mTLS)
    cvRequire    ## require a valid client cert or refuse the handshake (mTLS)

  SniCertEntry* = object
    ## A per-hostname certificate for SNI. `host` selects it; the cert/key come
    ## from one source (files, in-memory PEM, or PKCS#12), like the defaults.
    host*: string
    certFile*, keyFile*: string
    certPem*, keyPem*: string
    pkcs12File*, pkcs12*: string
    keyPassword*: string

  Settings* = object
    port*: Port
    address*: string          ## bind address; "" = all interfaces, dual-stack
                              ## ("::" with IPv4-mapped, IPv4 fallback). Set an
                              ## explicit IPv4/IPv6 address to pin the family.
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
    wsCompression*: bool      ## negotiate permessage-deflate (only with -d:wsDeflate)

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
    responseTimeout*: int     ## end of request to first response byte (0 disables)
    auto100Continue*: bool    ## auto-send 100 Continue for Expect (false: app decides)
    securityHeaders*: bool    ## auto-add the OWASP baseline headers to responses
    wsPingInterval*: int      ## WebSocket idle before a keepalive ping (0 disables)
    wsPongTimeout*: int       ## close a WebSocket if no frame arrives this long after a ping
    shutdownGrace*: int       ## drain window on graceful shutdown

    serverHeader*: string     ## "" disables the Server header

    # TLS (a cert + key enables it; PEM format). Provide either files
    # (certFile/keyFile) or in-memory PEM (certPem/keyPem); keyPassword
    # decrypts an encrypted key.
    certFile*: string
    keyFile*: string
    certPem*: string          ## in-memory PEM cert chain (instead of certFile)
    keyPem*: string           ## in-memory PEM private key (instead of keyFile)
    keyPassword*: string      ## passphrase for an encrypted key/PKCS#12 ("" = none)
    pkcs12File*: string       ## PKCS#12 (.pfx) bundle file (cert + key + chain)
    pkcs12*: string           ## PKCS#12 bundle bytes (in-memory)
    verifyClient*: ClientVerify   ## mTLS: request/require a client certificate
    clientCaFile*: string     ## CA (PEM file) to verify client certs against
    clientCaPem*: string      ## CA (in-memory PEM) to verify client certs against
    sni*: seq[SniCertEntry]   ## additional certs selected by SNI hostname
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
    wsCompression = true,
    maxConnections = 65536,
    maxConcurrentStreams = 256,
    maxResetStreams = 512,
    maxControlFrames = 1000,
    maxRequestsPerSocket = 0,
    headerTimeout = 10,
    bodyTimeout = 30,
    keepAliveTimeout = 60,
    responseTimeout = 0,
    auto100Continue = true,
    securityHeaders = false,
    wsPingInterval = 30,
    wsPongTimeout = 10,
    shutdownGrace = 10,
    serverHeader = "vortex",
    certFile = "",
    keyFile = "",
    certPem = "",
    keyPem = "",
    keyPassword = "",
    pkcs12File = "",
    pkcs12 = "",
    verifyClient = cvNone,
    clientCaFile = "",
    clientCaPem = "",
    sni: seq[SniCertEntry] = @[],
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
    maxWsMessageSize: maxWsMessageSize, wsCompression: wsCompression,
    maxConnections: maxConnections,
    maxConcurrentStreams: maxConcurrentStreams,
    maxResetStreams: maxResetStreams, maxControlFrames: maxControlFrames,
    maxRequestsPerSocket: maxRequestsPerSocket,
    headerTimeout: headerTimeout,
    bodyTimeout: bodyTimeout, keepAliveTimeout: keepAliveTimeout,
    responseTimeout: responseTimeout, auto100Continue: auto100Continue,
    securityHeaders: securityHeaders,
    wsPingInterval: wsPingInterval, wsPongTimeout: wsPongTimeout,
    shutdownGrace: shutdownGrace, serverHeader: serverHeader,
    certFile: certFile, keyFile: keyFile, certPem: certPem, keyPem: keyPem,
    keyPassword: keyPassword, pkcs12File: pkcs12File, pkcs12: pkcs12,
    verifyClient: verifyClient, clientCaFile: clientCaFile,
    clientCaPem: clientCaPem, sni: sni, http3: http3,
    minTlsVersion: minTlsVersion, tlsCipherList: tlsCipherList,
    tlsCipherSuites: tlsCipherSuites
  )

proc hasTls*(s: Settings): bool =
  ## True when TLS material is configured (files, in-memory PEM, or PKCS#12).
  s.certFile.len > 0 or s.certPem.len > 0 or
    s.pkcs12File.len > 0 or s.pkcs12.len > 0
