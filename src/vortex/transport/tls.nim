## Minimal OpenSSL (>= 3.x) bindings for the TLS transport: nonblocking
## SSL-on-fd with WANT_READ/WANT_WRITE plumbing and ALPN selection.
## Hand-rolled FFI: we need ~20 symbols, not a wrapper dependency.
##
## Build with -d:plainHttp to exclude TLS (and the libssl runtime
## requirement) entirely.

const sslLibName {.strdefine.} =
  when defined(macosx):
    "(/opt/homebrew/opt/openssl@3/lib/|/usr/local/opt/openssl@3/lib/|)libssl.3.dylib"
  else:
    "libssl.so(.3|)"
const cryptoLibName {.strdefine.} =
  when defined(macosx):
    "(/opt/homebrew/opt/openssl@3/lib/|/usr/local/opt/openssl@3/lib/|)libcrypto.3.dylib"
  else:
    "libcrypto.so(.3|)"

type
  SslCtxPtr* = pointer
  SslPtr* = pointer

const
  SSL_FILETYPE_PEM = cint(1)
  SSL_ERROR_WANT_READ = cint(2)
  SSL_ERROR_WANT_WRITE = cint(3)
  SSL_ERROR_SYSCALL = cint(5)
  SSL_ERROR_ZERO_RETURN = cint(6)
  SSL_CTRL_MODE = cint(33)
  SSL_CTRL_SET_MIN_PROTO_VERSION = cint(123)
  SSL_MODE_ENABLE_PARTIAL_WRITE = clong(1)
  SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER = clong(2)

const
  # OpenSSL protocol version numbers (for set_min_proto_version).
  TLS1_2_VERSION* = clong(0x0303)
  TLS1_3_VERSION* = clong(0x0304)
  SSL_TLSEXT_ERR_OK = cint(0)
  SSL_TLSEXT_ERR_NOACK = cint(3)
  OPENSSL_NPN_NEGOTIATED = cint(1)

{.push importc, cdecl, dynlib: sslLibName.}
proc TLS_server_method(): pointer
proc SSL_CTX_new(m: pointer): SslCtxPtr
proc SSL_CTX_free(ctx: SslCtxPtr)
proc SSL_CTX_use_certificate_chain_file(ctx: SslCtxPtr, file: cstring): cint
proc SSL_CTX_use_PrivateKey_file(ctx: SslCtxPtr, file: cstring,
                                 typ: cint): cint
proc SSL_CTX_check_private_key(ctx: SslCtxPtr): cint
proc SSL_CTX_ctrl(ctx: SslCtxPtr, cmd: cint, larg: clong,
                  parg: pointer): clong
proc SSL_CTX_set_cipher_list(ctx: SslCtxPtr, str: cstring): cint
proc SSL_CTX_set_ciphersuites(ctx: SslCtxPtr, str: cstring): cint
proc SSL_CTX_set_alpn_select_cb(ctx: SslCtxPtr,
    cb: proc (ssl: SslPtr, outProto: ptr ptr uint8, outLen: ptr uint8,
              inProtos: ptr uint8, inLen: cuint, arg: pointer): cint {.cdecl.},
    arg: pointer)
proc SSL_select_next_proto(outp: ptr ptr uint8, outLen: ptr uint8,
                           server: ptr uint8, serverLen: cuint,
                           client: ptr uint8, clientLen: cuint): cint
proc SSL_new(ctx: SslCtxPtr): SslPtr
proc SSL_free(ssl: SslPtr)
proc SSL_set_fd(ssl: SslPtr, fd: cint): cint
proc SSL_set_accept_state(ssl: SslPtr)
proc SSL_do_handshake(ssl: SslPtr): cint
proc SSL_read(ssl: SslPtr, buf: pointer, num: cint): cint
proc SSL_write(ssl: SslPtr, buf: pointer, num: cint): cint
proc SSL_get_error(ssl: SslPtr, ret: cint): cint
proc SSL_shutdown(ssl: SslPtr): cint
proc SSL_get0_alpn_selected(ssl: SslPtr, data: ptr ptr uint8, len: ptr cuint)
proc SSL_pending(ssl: SslPtr): cint
{.pop.}

{.push importc, cdecl, dynlib: cryptoLibName.}
proc ERR_clear_error()
proc ERR_get_error(): culong
proc ERR_error_string(e: culong, buf: cstring): cstring
{.pop.}

type
  TlsConfig* = object
    ## One per server; SSL_CTX is thread-safe for SSL_new. Lives in shared
    ## memory so loop threads can use it via pointer.
    ctx*: SslCtxPtr          ## active SSL_CTX; loop threads load it atomically
                             ## so a certificate hot-reload can swap it in
    retired: SslCtxPtr       ## the ctx displaced by the previous reload, freed
                             ## at the next one (grace for in-flight SSL_new)
    protos: string           ## ALPN preference list, wire format
    meth: pointer            ## method the ctx was built with (rebuild on reload)
    certFile, keyFile: string
    minProtoVersion: clong
    cipherList, cipherSuites: string

  TlsIo* = enum
    tlsOk, tlsWantRead, tlsWantWrite, tlsClosed, tlsError

proc lastErrorMsg(): string =
  let e = ERR_get_error()
  if e == 0: return "unknown TLS error"
  $ERR_error_string(e, nil)

proc alpnSelect(ssl: SslPtr, outProto: ptr ptr uint8, outLen: ptr uint8,
                inProtos: ptr uint8, inLen: cuint,
                arg: pointer): cint {.cdecl.} =
  let cfg = cast[ptr TlsConfig](arg)
  var chosen: ptr uint8
  var chosenLen: uint8
  let r = SSL_select_next_proto(addr chosen, addr chosenLen,
      cast[ptr uint8](unsafeAddr cfg.protos[0]), cuint(cfg.protos.len),
      inProtos, inLen)
  if r == OPENSSL_NPN_NEGOTIATED:
    outProto[] = chosen
    outLen[] = chosenLen
    SSL_TLSEXT_ERR_OK
  else:
    SSL_TLSEXT_ERR_NOACK      # no overlap: proceed without ALPN (=> h1)

proc buildTlsCtx(meth: pointer, certFile, keyFile: string,
                 minProtoVersion: clong, cipherList, cipherSuites: string):
                 SslCtxPtr =
  ## Build a fully-configured SSL_CTX (min version, ciphers, cert/key). Raises
  ## on any failure, freeing the partial ctx. The ALPN callback is set by the
  ## caller, which owns the stable arg pointer. Shared by initial config and
  ## certificate hot-reload.
  let ctx = SSL_CTX_new(meth)
  if ctx == nil:
    raise newException(CatchableError, "SSL_CTX_new failed: " & lastErrorMsg())
  if minProtoVersion != 0:
    if SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION,
                    minProtoVersion, nil) != 1:
      SSL_CTX_free(ctx)
      raise newException(CatchableError,
        "cannot set minimum TLS version: " & lastErrorMsg())
  if cipherList.len > 0 and SSL_CTX_set_cipher_list(ctx, cipherList) != 1:
    SSL_CTX_free(ctx)
    raise newException(CatchableError,
      "invalid TLS cipher list: " & lastErrorMsg())
  if cipherSuites.len > 0 and SSL_CTX_set_ciphersuites(ctx, cipherSuites) != 1:
    SSL_CTX_free(ctx)
    raise newException(CatchableError,
      "invalid TLS 1.3 cipher suites: " & lastErrorMsg())
  if SSL_CTX_use_certificate_chain_file(ctx, certFile.cstring) != 1:
    SSL_CTX_free(ctx)
    raise newException(CatchableError,
      "cannot load certificate '" & certFile & "': " & lastErrorMsg())
  if SSL_CTX_use_PrivateKey_file(ctx, keyFile.cstring, SSL_FILETYPE_PEM) != 1:
    SSL_CTX_free(ctx)
    raise newException(CatchableError,
      "cannot load private key '" & keyFile & "': " & lastErrorMsg())
  if SSL_CTX_check_private_key(ctx) != 1:
    SSL_CTX_free(ctx)
    raise newException(CatchableError,
      "certificate/key mismatch: " & lastErrorMsg())
  # Partial writes with a moving buffer match our flushOut retry pattern.
  discard SSL_CTX_ctrl(ctx, SSL_CTRL_MODE,
      SSL_MODE_ENABLE_PARTIAL_WRITE or SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER,
      nil)
  ctx

proc newTlsConfigWith*(meth: pointer, certFile, keyFile: string,
                       protos: string, minProtoVersion: clong = 0,
                       cipherList = "", cipherSuites = ""): ptr TlsConfig =
  let ctx = buildTlsCtx(meth, certFile, keyFile, minProtoVersion,
                        cipherList, cipherSuites)
  result = createShared(TlsConfig)
  result.ctx = ctx
  result.protos = protos
  result.meth = meth
  result.certFile = certFile
  result.keyFile = keyFile
  result.minProtoVersion = minProtoVersion
  result.cipherList = cipherList
  result.cipherSuites = cipherSuites
  SSL_CTX_set_alpn_select_cb(ctx, alpnSelect, result)

proc reloadTlsConfig*(cfg: ptr TlsConfig, certFile = "", keyFile = ""): bool =
  ## Rebuild the SSL_CTX from `certFile`/`keyFile` (or, when empty, the paths
  ## most recently loaded -- initially the configured ones -- e.g. after an
  ## in-place renewal) and atomically install it, so subsequent TLS handshakes
  ## present the new certificate while in-flight connections keep the old one.
  ## Returns false and leaves the running ctx untouched if the new material is
  ## missing/invalid/mismatched.
  ##
  ## Lock-free and safe: loop threads read `cfg.ctx` with an atomic load in
  ## `newTlsSession`; the displaced ctx is not freed now but retired and freed
  ## at the *next* reload. That gives any thread mid-`SSL_new` an effectively
  ## unbounded grace window (reloads are seconds/hours apart, SSL_new is
  ## microseconds), while capping retained ctxs at one. Call from a normal
  ## thread, not a raw signal handler.
  let cf = if certFile.len > 0: certFile else: cfg.certFile
  let kf = if keyFile.len > 0: keyFile else: cfg.keyFile
  var newCtx: SslCtxPtr
  try:
    newCtx = buildTlsCtx(cfg.meth, cf, kf, cfg.minProtoVersion,
                         cfg.cipherList, cfg.cipherSuites)
  except CatchableError:
    return false
  SSL_CTX_set_alpn_select_cb(newCtx, alpnSelect, cfg)
  cfg.certFile = cf
  cfg.keyFile = kf
  let old = atomicExchangeN(addr cfg.ctx, newCtx, ATOMIC_ACQ_REL)
  if cfg.retired != nil: SSL_CTX_free(cfg.retired)  # unreferenced since last reload
  cfg.retired = old
  true

proc newTlsConfig*(certFile, keyFile: string, enableH2 = false,
                   minProtoVersion: clong = 0,
                   cipherList = "", cipherSuites = ""): ptr TlsConfig =
  newTlsConfigWith(TLS_server_method(), certFile, keyFile,
    (if enableH2: "\x02h2\x08http/1.1" else: "\x08http/1.1"),
    minProtoVersion, cipherList, cipherSuites)

proc freeTlsConfig*(cfg: ptr TlsConfig) =
  SSL_CTX_free(cfg.ctx)
  if cfg.retired != nil: SSL_CTX_free(cfg.retired)
  cfg.protos = ""
  cfg.certFile = ""
  cfg.keyFile = ""
  cfg.cipherList = ""
  cfg.cipherSuites = ""
  deallocShared(cfg)

proc newTlsSession*(cfg: ptr TlsConfig, fd: cint): SslPtr =
  # Atomic load: a concurrent certificate hot-reload may swap cfg.ctx.
  let ctx = atomicLoadN(addr cfg.ctx, ATOMIC_ACQUIRE)
  result = SSL_new(ctx)
  if result == nil: return nil
  if SSL_set_fd(result, fd) != 1:
    SSL_free(result)
    return nil
  SSL_set_accept_state(result)

proc freeTlsSession*(ssl: SslPtr) =
  SSL_free(ssl)

proc classify(ssl: SslPtr, ret: cint): TlsIo =
  case SSL_get_error(ssl, ret)
  of SSL_ERROR_WANT_READ: tlsWantRead
  of SSL_ERROR_WANT_WRITE: tlsWantWrite
  of SSL_ERROR_ZERO_RETURN: tlsClosed
  of SSL_ERROR_SYSCALL:
    if ret == 0: tlsClosed else: tlsError
  else: tlsError

proc tlsHandshake*(ssl: SslPtr): TlsIo =
  ERR_clear_error()
  let r = SSL_do_handshake(ssl)
  if r == 1: tlsOk else: classify(ssl, r)

proc tlsRead*(ssl: SslPtr, buf: pointer, len: int): (int, TlsIo) =
  ERR_clear_error()
  let n = SSL_read(ssl, buf, cint(len))
  if n > 0: (int(n), tlsOk) else: (0, classify(ssl, n))

proc tlsWrite*(ssl: SslPtr, buf: pointer, len: int): (int, TlsIo) =
  ERR_clear_error()
  let n = SSL_write(ssl, buf, cint(len))
  if n > 0: (int(n), tlsOk) else: (0, classify(ssl, n))

proc tlsPending*(ssl: SslPtr): bool =
  SSL_pending(ssl) > 0

proc tlsShutdown*(ssl: SslPtr) =
  ## Best-effort close_notify; never blocks (fd is nonblocking).
  ERR_clear_error()
  discard SSL_shutdown(ssl)

proc tlsSelectedAlpn*(ssl: SslPtr): string =
  var data: ptr uint8
  var len: cuint
  SSL_get0_alpn_selected(ssl, addr data, addr len)
  if data == nil or len == 0: return ""
  result = newString(int(len))
  copyMem(addr result[0], data, int(len))
