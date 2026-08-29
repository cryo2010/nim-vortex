import std/net

type
  TlsVersion* {.pure.} = enum
    ## Shared by minTlsVersion and maxTlsVersion. `None` means "unset": as a
    ## minimum it applies the secure default (TLS 1.2 -- never 1.0/1.1); as a
    ## maximum it means no cap (up to the newest supported).
    None,   ## unset (min: default TLS 1.2 floor; max: no cap)
    V12,    ## TLS 1.2
    V13     ## TLS 1.3

  ClientVerify* {.pure.} = enum
    None,      ## no client certificate requested (default)
    Optional,  ## request a client cert; if presented it must verify (mTLS)
    Require    ## require a valid client cert or refuse the handshake (mTLS)

  ProxyProtocol* {.pure.} = enum
    ## HAProxy PROXY protocol on the listener, for recovering the real client
    ## address behind an L4 / TLS-passthrough load balancer (feeds
    ## req.remoteAddress). Only honored from a trusted peer (trustedProxies).
    Disabled,  ## never read a PROXY header (default)
    Optional,  ## from a trusted peer, consume a PROXY header if present;
               ## otherwise treat the bytes as normal traffic
    Require    ## require a valid PROXY header from a trusted peer; drop
               ## the connection otherwise

  SniCertEntry* = object
    ## A per-hostname certificate for SNI. `host` selects it; the cert/key come
    ## from one source (files, in-memory PEM, or PKCS#12), like the defaults.
    host*: string
    certFile*, keyFile*: string
    certPem*, keyPem*: string
    pkcs12File*, pkcs12*: string
    keyPassword*: string

  VortexConfig* = object
    port*: Port
    address*: string          ## bind address; "" = all interfaces, dual-stack
                              ## ("::" with IPv4-mapped, IPv4 fallback). Set an
                              ## explicit IPv4/IPv6 address to pin the family.
    numThreads*: int          ## 0 = countProcessors()
    workerThreads*: int       ## worker pool size for `blocking:` (0 = numThreads * 2)
    listenBacklog*: int
    reusePort*: bool          ## SO_REUSEPORT per-thread listeners
    proxyProtocol*: ProxyProtocol  ## accept a HAProxy PROXY header (see enum)
    trustedProxies*: seq[string]   ## IPs/CIDRs allowed to send a PROXY header;
                                   ## empty trusts any direct peer (safe only when
                                   ## the listener is not publicly reachable)

    # Limits (bytes unless noted)
    maxHeaderSize*: int       ## request line + headers, 431 when exceeded
    maxHeaderCount*: int      ## 400 when exceeded
    maxBodySize*: int         ## 413 when exceeded
    initialBufferSize*: int   ## per-connection read/write buffer starting size
    maxWsMessageSize*: int    ## largest inbound WebSocket message (close 1009 over it)
    wsCompression*: bool      ## negotiate permessage-deflate (only with -d:wsDeflate)
    compress*: bool           ## gzip/brotli eligible responses (needs -d:httpGzip/httpBrotli)
    decompressRequest*: bool  ## transparently decode a gzip/br/zstd request body
                              ## into req.body, bounded by maxBodySize (needs
                              ## -d:httpGzip/httpBrotli/httpZstd); over the cap -> 413

    # DoS budgets (0 disables the check)
    maxConnections*: int          ## live connections per loop thread
    maxConcurrentStreams*: int    ## open h2/h3 streams per connection
    maxResetStreams*: int         ## h2 peer resets before GOAWAY (rapid reset)
    maxControlFrames*: int        ## h2 PING/SETTINGS/etc. between stream progress
    maxRequestsPerSocket*: int    ## HTTP/1 keep-alive requests before close
    h2StreamWindow*: int          ## h2 receive window advertised per stream
                                  ## (SETTINGS_INITIAL_WINDOW_SIZE): the upload
                                  ## flow-control window and the cap on one
                                  ## stream's un-consumed streaming-body buffer.
                                  ## Larger = higher upload throughput on
                                  ## higher-latency links (bandwidth-delay
                                  ## product); the 64 KiB HTTP/2 default throttles
                                  ## it. (h3 uses QUIC transport-parameter flow
                                  ## control, set separately by the ngtcp2 shim.)
    h2ConnWindow*: int            ## h2 per-connection receive window: the cap on
                                  ## total un-consumed streaming-body buffer
                                  ## across all streams (bounds memory regardless
                                  ## of stream count). Should be >= h2StreamWindow.

    # Timeouts (seconds, coarse; 0 disables)
    headerTimeout*: int       ## from first byte of a request to end of headers
    bodyTimeout*: int         ## from end of headers to end of body
    keepAliveTimeout*: int    ## idle time between requests
    responseTimeout*: int     ## end of request to first response byte (0 disables)
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
    minTlsVersion*: TlsVersion  ## lowest accepted TLS version (TCP; QUIC is always 1.3)
    maxTlsVersion*: TlsVersion  ## highest accepted TLS version (TCP; default = no cap)
    ocspFile*: string         ## DER OCSP response to staple (file; default cert)
    ocspResponse*: string     ## DER OCSP response to staple (in-memory bytes)
    tlsCipherList*: string    ## OpenSSL cipher list for TLS <= 1.2 ("" = default)
    tlsCipherSuites*: string  ## OpenSSL cipher suites for TLS 1.3 ("" = default)

proc initVortexConfig*(
    port = Port(8080),
    address = "",
    numThreads = 0,
    workerThreads = 0,
    listenBacklog = 1024,
    reusePort = true,
    proxyProtocol = ProxyProtocol.Disabled,
    trustedProxies: seq[string] = @[],
    maxHeaderSize = 16 * 1024,
    maxHeaderCount = 100,
    maxBodySize = 8 * 1024 * 1024,
    initialBufferSize = 8 * 1024,
    maxWsMessageSize = 1024 * 1024,
    wsCompression = true,
    compress = false,
    decompressRequest = false,
    maxConnections = 65536,
    maxConcurrentStreams = 256,
    maxResetStreams = 512,
    maxControlFrames = 1000,
    maxRequestsPerSocket = 0,
    h2StreamWindow = 1024 * 1024,
    h2ConnWindow = 1024 * 1024,
    headerTimeout = 10,
    bodyTimeout = 30,
    keepAliveTimeout = 60,
    responseTimeout = 0,
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
    verifyClient = ClientVerify.None,
    clientCaFile = "",
    clientCaPem = "",
    sni: seq[SniCertEntry] = @[],
    maxTlsVersion = TlsVersion.None,
    ocspFile = "",
    ocspResponse = "",
    http3 = true,
    minTlsVersion = TlsVersion.V12,
    tlsCipherList = "",
    tlsCipherSuites = ""
): VortexConfig =
  VortexConfig(
    port: port, address: address, numThreads: numThreads,
    workerThreads: workerThreads, listenBacklog: listenBacklog,
    reusePort: reusePort, proxyProtocol: proxyProtocol,
    trustedProxies: trustedProxies, maxHeaderSize: maxHeaderSize,
    maxHeaderCount: maxHeaderCount, maxBodySize: maxBodySize,
    initialBufferSize: initialBufferSize,
    maxWsMessageSize: maxWsMessageSize, wsCompression: wsCompression,
    compress: compress, decompressRequest: decompressRequest,
    maxConnections: maxConnections,
    maxConcurrentStreams: maxConcurrentStreams,
    maxResetStreams: maxResetStreams, maxControlFrames: maxControlFrames,
    maxRequestsPerSocket: maxRequestsPerSocket,
    h2StreamWindow: h2StreamWindow, h2ConnWindow: h2ConnWindow,
    headerTimeout: headerTimeout,
    bodyTimeout: bodyTimeout, keepAliveTimeout: keepAliveTimeout,
    responseTimeout: responseTimeout,
    securityHeaders: securityHeaders,
    wsPingInterval: wsPingInterval, wsPongTimeout: wsPongTimeout,
    shutdownGrace: shutdownGrace, serverHeader: serverHeader,
    certFile: certFile, keyFile: keyFile, certPem: certPem, keyPem: keyPem,
    keyPassword: keyPassword, pkcs12File: pkcs12File, pkcs12: pkcs12,
    verifyClient: verifyClient, clientCaFile: clientCaFile,
    clientCaPem: clientCaPem, sni: sni, maxTlsVersion: maxTlsVersion,
    ocspFile: ocspFile, ocspResponse: ocspResponse, http3: http3,
    minTlsVersion: minTlsVersion, tlsCipherList: tlsCipherList,
    tlsCipherSuites: tlsCipherSuites
  )

proc hasTls*(s: VortexConfig): bool =
  ## True when TLS material is configured (files, in-memory PEM, or PKCS#12).
  s.certFile.len > 0 or s.certPem.len > 0 or
    s.pkcs12File.len > 0 or s.pkcs12.len > 0
