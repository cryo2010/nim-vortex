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
  SSL_MODE_ENABLE_PARTIAL_WRITE = clong(1)
  SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER = clong(2)
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
    ctx*: SslCtxPtr
    protos: string          ## ALPN preference list, wire format

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

proc newTlsConfigWith*(meth: pointer, certFile, keyFile: string,
                       protos: string): ptr TlsConfig =
  let ctx = SSL_CTX_new(meth)
  if ctx == nil:
    raise newException(CatchableError, "SSL_CTX_new failed: " & lastErrorMsg())
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
  result = createShared(TlsConfig)
  result.ctx = ctx
  result.protos = protos
  SSL_CTX_set_alpn_select_cb(ctx, alpnSelect, result)

proc newTlsConfig*(certFile, keyFile: string,
                   enableH2 = false): ptr TlsConfig =
  newTlsConfigWith(TLS_server_method(), certFile, keyFile,
    if enableH2: "\x02h2\x08http/1.1" else: "\x08http/1.1")

proc freeTlsConfig*(cfg: ptr TlsConfig) =
  SSL_CTX_free(cfg.ctx)
  cfg.protos = ""
  deallocShared(cfg)

proc newTlsSession*(cfg: ptr TlsConfig, fd: cint): SslPtr =
  result = SSL_new(cfg.ctx)
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
