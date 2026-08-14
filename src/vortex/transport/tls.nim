## Minimal OpenSSL (>= 3.x) bindings for the TLS transport: nonblocking
## SSL-on-fd with WANT_READ/WANT_WRITE plumbing and ALPN selection.
## Hand-rolled FFI: we need ~20 symbols, not a wrapper dependency.
##
## Build with -d:plainHttp to exclude TLS (and the libssl runtime
## requirement) entirely.

import std/[locks, monotimes, times]

const
  ctxRetireSlots = 4     ## displaced SSL_CTXs kept during their grace window
  ctxGraceSec = 5        ## free a retired ctx only this long after it was
                         ## displaced (a thread mid-SSL_new keeps it valid)

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
  # Public client-verification modes (map settings.ClientVerify -> these).
  TlsVerifyNone* = cint(0)
  TlsVerifyOptional* = cint(1)          ## SSL_VERIFY_PEER
  TlsVerifyRequire* = cint(3)           ## PEER | FAIL_IF_NO_PEER_CERT

const
  SSL_FILETYPE_PEM = cint(1)
  SSL_ERROR_WANT_READ = cint(2)
  SSL_ERROR_WANT_WRITE = cint(3)
  SSL_ERROR_SYSCALL = cint(5)
  SSL_ERROR_ZERO_RETURN = cint(6)
  SSL_CTRL_MODE = cint(33)
  SSL_CTRL_EXTRA_CHAIN_CERT = cint(14)     # append a cert to the chain (add0)
  SSL_CTRL_CHAIN_CERT = cint(89)           # add0/add1 a chain cert
  SSL_CTRL_CLEAR_CHAIN_CERTS = cint(88)    # drop the built chain (for in-place reload)
  SSL_CTRL_SET_MIN_PROTO_VERSION = cint(123)
  SSL_CTRL_SET_MAX_PROTO_VERSION = cint(124)
  SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB = cint(63)
  SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG = cint(64)
  SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP = cint(71)
  SSL_VERIFY_NONE = cint(0)
  SSL_VERIFY_PEER = cint(1)
  SSL_VERIFY_FAIL_IF_NO_PEER_CERT = cint(2)
  SSL_CTRL_SET_TLSEXT_SERVERNAME_CB = cint(53)
  SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG = cint(54)
  TLSEXT_NAMETYPE_host_name = cint(0)
  X509_V_OK = clong(0)
  SSL_MODE_ENABLE_PARTIAL_WRITE = clong(1)
  SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER = clong(2)

const
  # OpenSSL protocol version numbers (for set_min_proto_version).
  TLS1_2_VERSION* = clong(0x0303)
  TLS1_3_VERSION* = clong(0x0304)
  SSL_TLSEXT_ERR_OK = cint(0)
  SSL_TLSEXT_ERR_NOACK = cint(3)
  OPENSSL_NPN_NEGOTIATED = cint(1)

type
  PemPasswordCb = proc (buf: cstring, size: cint, rwflag: cint,
                        u: pointer): cint {.cdecl.}
    ## OpenSSL pem_password_cb: fill `buf` (up to `size`) with the passphrase
    ## for an encrypted key, return its length.

{.push importc, cdecl, dynlib: sslLibName.}
proc TLS_server_method(): pointer
proc SSL_CTX_new(m: pointer): SslCtxPtr
proc SSL_CTX_free(ctx: SslCtxPtr)
proc SSL_CTX_use_certificate_chain_file(ctx: SslCtxPtr, file: cstring): cint
proc SSL_CTX_use_certificate(ctx: SslCtxPtr, x: pointer): cint   # up-refs x
proc SSL_CTX_use_PrivateKey(ctx: SslCtxPtr, pkey: pointer): cint # up-refs pkey
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
proc SSL_CTX_get0_certificate(ctx: SslCtxPtr): pointer   # X509* (borrowed)
proc SSL_CTX_set_verify(ctx: SslCtxPtr, mode: cint, cb: pointer)
proc SSL_CTX_load_verify_locations(ctx: SslCtxPtr, caFile, caPath: cstring): cint
proc SSL_CTX_get_cert_store(ctx: SslCtxPtr): pointer     # X509_STORE* (borrowed)
proc SSL_get1_peer_certificate(ssl: SslPtr): pointer     # X509* (owned; free it)
proc SSL_get_verify_result(ssl: SslPtr): clong
proc SSL_get_servername(ssl: SslPtr, typ: cint): cstring
proc SSL_set_SSL_CTX(ssl: SslPtr, ctx: SslCtxPtr): SslCtxPtr
proc SSL_CTX_callback_ctrl(ctx: SslCtxPtr, cmd: cint, fp: pointer): clong
proc SSL_ctrl(ssl: SslPtr, cmd: cint, larg: clong, parg: pointer): clong
{.pop.}

{.push importc, cdecl, dynlib: cryptoLibName.}
proc ERR_clear_error()
proc ERR_get_error(): culong
proc ERR_error_string(e: culong, buf: cstring): cstring
proc X509_get_subject_name(x: pointer): pointer          # X509_NAME* (borrowed)
proc X509_NAME_oneline(name: pointer, buf: cstring, size: cint): cstring
proc BIO_new_mem_buf(buf: pointer, len: cint): pointer   # read-only mem BIO
proc BIO_free(bio: pointer): cint
proc PEM_read_bio_X509(bio: pointer, x: ptr pointer,
                       cb: PemPasswordCb, u: pointer): pointer
proc PEM_read_bio_PrivateKey(bio: pointer, x: ptr pointer,
                             cb: PemPasswordCb, u: pointer): pointer
proc X509_free(x: pointer)
proc EVP_PKEY_free(pkey: pointer)
proc X509_STORE_add_cert(store, x: pointer): cint        # up-refs x
proc d2i_PKCS12_bio(bio: pointer, p12: ptr pointer): pointer
proc PKCS12_parse(p12: pointer, pass: cstring,
                  pkey, cert, ca: ptr pointer): cint
proc PKCS12_free(p12: pointer)
proc OPENSSL_sk_num(st: pointer): cint
proc OPENSSL_sk_value(st: pointer, i: cint): pointer
proc OPENSSL_sk_pop_free(st: pointer, freefn: proc (p: pointer) {.cdecl.})
proc CRYPTO_malloc(num: csize_t, file: cstring, line: cint): pointer
{.pop.}

proc passwdCb(buf: cstring, size: cint, rwflag: cint,
              u: pointer): cint {.cdecl.} =
  ## Copy the NUL-terminated passphrase at `u` into `buf` (bounded by `size`).
  if u == nil: return 0
  let src = cast[cstring](u)
  var n = 0
  while n < int(size) and src[n] != '\0': inc n
  if n > 0: copyMem(buf, u, n)
  cint(n)

proc loadCertChainMem(ctx: SslCtxPtr, pem: string): bool =
  ## Load a PEM certificate chain (leaf first, then intermediates) from memory.
  let bio = BIO_new_mem_buf(unsafeAddr pem[0], cint(pem.len))
  if bio == nil: return false
  defer: discard BIO_free(bio)
  let leaf = PEM_read_bio_X509(bio, nil, nil, nil)
  if leaf == nil: return false
  let used = SSL_CTX_use_certificate(ctx, leaf) == 1   # up-refs leaf
  X509_free(leaf)
  if not used: return false
  while true:
    let extra = PEM_read_bio_X509(bio, nil, nil, nil)
    if extra == nil:
      ERR_clear_error()          # expected: end of PEM data
      break
    # SSL_CTX_add_extra_chain_cert takes ownership; do not free on success.
    if SSL_CTX_ctrl(ctx, SSL_CTRL_EXTRA_CHAIN_CERT, 0, extra) != 1:
      X509_free(extra)
      return false
  true

proc loadKeyMem(ctx: SslCtxPtr, pem, password: string): bool =
  ## Load a PEM private key from memory, decrypting with `password` if set.
  if pem.len == 0: return false
  let bio = BIO_new_mem_buf(unsafeAddr pem[0], cint(pem.len))
  if bio == nil: return false
  defer: discard BIO_free(bio)
  # Always pass our own callback (never nil). If it were nil, OpenSSL falls back
  # to its built-in PEM_def_callback, which prompts for a passphrase on the
  # controlling tty (blocking) whenever the key is encrypted. With no password
  # the callback yields an empty passphrase, so an encrypted key fails to load
  # cleanly instead of prompting; an unencrypted key never consults it.
  let ud = if password.len > 0: cast[pointer](password.cstring) else: nil
  let pkey = PEM_read_bio_PrivateKey(bio, nil, passwdCb, ud)
  if pkey == nil:
    ERR_clear_error()
    return false
  result = SSL_CTX_use_PrivateKey(ctx, pkey) == 1      # up-refs pkey
  EVP_PKEY_free(pkey)

type
  TlsMaterial* = object
    ## Where a cert + private key come from. Provide one source: a PKCS#12
    ## bundle (file or bytes), in-memory PEM (certPem/keyPem), or PEM files
    ## (certFile/keyFile). keyPassword decrypts an encrypted PEM key or the p12.
    certFile*, keyFile*: string
    certPem*, keyPem*: string
    pkcs12File*, pkcs12*: string
    keyPassword*: string

  SniCert* = object
    ## A per-hostname certificate for SNI: `host` selects `material`.
    host*: string
    material*: TlsMaterial

  TlsConfig* = object
    ## One per server; SSL_CTX is thread-safe for SSL_new. Lives in shared
    ## memory so loop threads can use it via pointer.
    ctx*: SslCtxPtr          ## active SSL_CTX; loop threads load it atomically
                             ## so a certificate hot-reload can swap it in
    retired: array[ctxRetireSlots, SslCtxPtr]   ## displaced ctxs pending free
    retiredAt: array[ctxRetireSlots, MonoTime]  ## when each was displaced
    protos: string           ## ALPN preference list, wire format
    meth: pointer            ## method the ctx was built with (rebuild on reload)
    material: TlsMaterial    ## the default cert/key source (reloaded in place)
    verify: cint             ## client-cert verification mode (SSL_VERIFY_*)
    clientCaFile, clientCaPem: string   ## CA to verify client certs (mTLS)
    minProtoVersion, maxProtoVersion: clong
    cipherList, cipherSuites: string
    ocsp: string             ## DER OCSP response to staple (immutable; "" = off)
    sniHosts: seq[string]              ## per-host SNI: hostnames...
    sniCtx: seq[SslCtxPtr]             ## ...and their ctxs (parallel to sniHosts)

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

proc cstrEq(cs: cstring, s: string): bool =
  ## Compare a NUL-terminated C string to a Nim string without allocating (the
  ## SNI callback runs on a loop thread; avoid ORC ops on the shared config).
  var i = 0
  while i < s.len:
    if cs[i] == '\0' or cs[i] != s[i]: return false
    inc i
  cs[i] == '\0'

proc wildMatch(name: cstring, pat: string): bool =
  ## `*.example.com` matches exactly one leading label: `foo.example.com` yes,
  ## `example.com` no, `a.b.example.com` no. No allocation (loop-thread cb).
  if pat.len < 3 or pat[0] != '*' or pat[1] != '.': return false
  var dot = 0
  while name[dot] != '\0' and name[dot] != '.': inc dot
  if dot == 0 or name[dot] != '.': return false     # need a label then a dot
  var i = dot                                        # name[dot..] == pat[1..]
  var j = 1                                          # (both include the dot)
  while j < pat.len:
    if name[i] == '\0' or name[i] != pat[j]: return false
    inc i; inc j
  name[i] == '\0'

proc servernameCb(ssl: SslPtr, al: ptr cint, arg: pointer): cint {.cdecl.} =
  ## SNI: switch the connection to the ctx whose host matches the requested
  ## server name (exact match preferred over a wildcard); fall through to the
  ## default ctx when none matches.
  let cfg = cast[ptr TlsConfig](arg)
  let name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name)
  if name != nil:
    var idx = -1
    for i in 0 ..< cfg.sniHosts.len:
      if cstrEq(name, cfg.sniHosts[i]): idx = i; break
    if idx < 0:
      for i in 0 ..< cfg.sniHosts.len:
        if wildMatch(name, cfg.sniHosts[i]): idx = i; break
    if idx >= 0: discard SSL_set_SSL_CTX(ssl, cfg.sniCtx[idx])
  SSL_TLSEXT_ERR_OK

proc statusCb(ssl: SslPtr, arg: pointer): cint {.cdecl.} =
  ## OCSP stapling: hand the client a copy of the configured DER OCSP response
  ## (OpenSSL frees the copy after sending). NOACK when none is set.
  let cfg = cast[ptr TlsConfig](arg)
  if cfg == nil or cfg.ocsp.len == 0: return SSL_TLSEXT_ERR_NOACK
  let n = cfg.ocsp.len
  let buf = CRYPTO_malloc(csize_t(n), nil, 0)
  if buf == nil: return SSL_TLSEXT_ERR_NOACK
  copyMem(buf, unsafeAddr cfg.ocsp[0], n)
  discard SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_STATUS_REQ_OCSP_RESP, clong(n), buf)
  SSL_TLSEXT_ERR_OK

proc loadPkcs12(ctx: SslCtxPtr, data, password: string): bool =
  ## Load cert + key (+ any bundled CA chain) from PKCS#12 (.pfx/.p12) bytes.
  if data.len == 0: return false
  let bio = BIO_new_mem_buf(unsafeAddr data[0], cint(data.len))
  if bio == nil: return false
  defer: discard BIO_free(bio)
  let p12 = d2i_PKCS12_bio(bio, nil)
  if p12 == nil: return false
  defer: PKCS12_free(p12)
  var pkey, cert, ca: pointer
  if PKCS12_parse(p12, password.cstring, addr pkey, addr cert, addr ca) != 1:
    return false
  result = cert != nil and pkey != nil and
           SSL_CTX_use_certificate(ctx, cert) == 1 and
           SSL_CTX_use_PrivateKey(ctx, pkey) == 1
  if result and ca != nil:
    for i in 0 ..< OPENSSL_sk_num(ca):
      # add1 (up-ref) so the whole stack is freed uniformly below
      if SSL_CTX_ctrl(ctx, SSL_CTRL_CHAIN_CERT, 1, OPENSSL_sk_value(ca, i)) != 1:
        result = false
        break
  if cert != nil: X509_free(cert)
  if pkey != nil: EVP_PKEY_free(pkey)
  if ca != nil: OPENSSL_sk_pop_free(ca, X509_free)

proc loadCaMem(ctx: SslCtxPtr, pem: string): bool =
  ## Add PEM CA cert(s) from memory to the ctx trust store (client verification).
  let store = SSL_CTX_get_cert_store(ctx)
  if store == nil or pem.len == 0: return false
  let bio = BIO_new_mem_buf(unsafeAddr pem[0], cint(pem.len))
  if bio == nil: return false
  defer: discard BIO_free(bio)
  var added = 0
  while true:
    let x = PEM_read_bio_X509(bio, nil, nil, nil)
    if x == nil:
      ERR_clear_error()
      break
    let ok = X509_STORE_add_cert(store, x) == 1     # up-refs x
    X509_free(x)
    if not ok: return false
    inc added
  added > 0

proc applyClientVerify(ctx: SslCtxPtr, verify: cint,
                       caFile, caPem: string): bool =
  ## Configure mTLS: load the client-cert CA (if any) and set the verify mode.
  if verify == SSL_VERIFY_NONE: return true
  if caPem.len > 0:
    if not loadCaMem(ctx, caPem): return false
  elif caFile.len > 0:
    if SSL_CTX_load_verify_locations(ctx, caFile.cstring, nil) != 1: return false
  SSL_CTX_set_verify(ctx, verify, nil)   # nil cb: OpenSSL's default chain check
  true

proc loadCertKey(ctx: SslCtxPtr, m: TlsMaterial): bool =
  ## Load the server cert + key from a PKCS#12 bundle, in-memory PEM, or files.
  if m.pkcs12.len > 0 or m.pkcs12File.len > 0:
    let data = if m.pkcs12.len > 0: m.pkcs12
               else:
                 try: readFile(m.pkcs12File)
                 except CatchableError: return false
    return loadPkcs12(ctx, data, m.keyPassword)
  let certOk = if m.certPem.len > 0: loadCertChainMem(ctx, m.certPem)
               else: SSL_CTX_use_certificate_chain_file(ctx, m.certFile.cstring) == 1
  if not certOk: return false
  # Both the in-memory and file key paths go through loadKeyMem, which passes an
  # explicit passphrase callback to PEM_read_bio_PrivateKey. Reading keyFile into
  # memory here (rather than SSL_CTX_use_PrivateKey_file) keeps that single path:
  # the file loader routes through OpenSSL 3's decoder machinery, whose legacy
  # default-passwd-cb bridge can still fire OpenSSL's interactive tty prompt for
  # an encrypted key even when a callback is registered.
  if m.keyPem.len > 0:
    loadKeyMem(ctx, m.keyPem, m.keyPassword)
  else:
    let keyData = try: readFile(m.keyFile)
                  except CatchableError: return false
    loadKeyMem(ctx, keyData, m.keyPassword)

proc buildTlsCtx(meth: pointer, m: TlsMaterial, verify: cint,
                 clientCaFile, clientCaPem: string,
                 minProtoVersion, maxProtoVersion: clong,
                 cipherList, cipherSuites: string): SslCtxPtr =
  ## Build a fully-configured SSL_CTX: min version, ciphers, the cert/key from
  ## `m` (PKCS#12, in-memory PEM, or files), and client-cert verification
  ## (mTLS). Raises on any failure, freeing the partial ctx. The ALPN callback
  ## is set by the caller, which owns the stable arg pointer. Shared by initial
  ## config and certificate hot-reload.
  let ctx = SSL_CTX_new(meth)
  if ctx == nil:
    raise newException(CatchableError, "SSL_CTX_new failed: " & lastErrorMsg())
  if minProtoVersion != 0:
    if SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION,
                    minProtoVersion, nil) != 1:
      SSL_CTX_free(ctx)
      raise newException(CatchableError,
        "cannot set minimum TLS version: " & lastErrorMsg())
  if maxProtoVersion != 0:
    if SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION,
                    maxProtoVersion, nil) != 1:
      SSL_CTX_free(ctx)
      raise newException(CatchableError,
        "cannot set maximum TLS version: " & lastErrorMsg())
  if cipherList.len > 0 and SSL_CTX_set_cipher_list(ctx, cipherList) != 1:
    SSL_CTX_free(ctx)
    raise newException(CatchableError,
      "invalid TLS cipher list: " & lastErrorMsg())
  if cipherSuites.len > 0 and SSL_CTX_set_ciphersuites(ctx, cipherSuites) != 1:
    SSL_CTX_free(ctx)
    raise newException(CatchableError,
      "invalid TLS 1.3 cipher suites: " & lastErrorMsg())
  if not loadCertKey(ctx, m):
    SSL_CTX_free(ctx)
    raise newException(CatchableError,
      "cannot load TLS certificate/key: " & lastErrorMsg())
  if SSL_CTX_check_private_key(ctx) != 1:
    SSL_CTX_free(ctx)
    raise newException(CatchableError,
      "certificate/key mismatch: " & lastErrorMsg())
  if not applyClientVerify(ctx, verify, clientCaFile, clientCaPem):
    SSL_CTX_free(ctx)
    raise newException(CatchableError,
      "cannot configure client verification / load client CA: " & lastErrorMsg())
  # Partial writes with a moving buffer match our flushOut retry pattern.
  discard SSL_CTX_ctrl(ctx, SSL_CTRL_MODE,
      SSL_MODE_ENABLE_PARTIAL_WRITE or SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER,
      nil)
  ctx

proc newTlsConfigWith*(meth: pointer, m: TlsMaterial, protos: string,
                       minProtoVersion: clong = 0, cipherList = "",
                       cipherSuites = "", verify: cint = 0,
                       clientCaFile = "", clientCaPem = "",
                       sni: openArray[SniCert] = [], maxProtoVersion: clong = 0,
                       ocsp = ""): ptr TlsConfig =
  let ctx = buildTlsCtx(meth, m, verify, clientCaFile, clientCaPem,
                        minProtoVersion, maxProtoVersion, cipherList, cipherSuites)
  result = createShared(TlsConfig)
  result.ctx = ctx
  result.protos = protos
  result.meth = meth
  result.material = m
  result.verify = verify
  result.clientCaFile = clientCaFile
  result.clientCaPem = clientCaPem
  result.minProtoVersion = minProtoVersion
  result.maxProtoVersion = maxProtoVersion
  result.cipherList = cipherList
  result.cipherSuites = cipherSuites
  result.ocsp = ocsp
  SSL_CTX_set_alpn_select_cb(ctx, alpnSelect, result)
  if ocsp.len > 0:   # OCSP stapling for the default cert
    discard SSL_CTX_callback_ctrl(ctx, SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB,
                                  cast[pointer](statusCb))
    discard SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG, 0, result)
  # SNI: one ctx per host, selected by the servername callback on the default.
  for sc in sni:
    let hctx = buildTlsCtx(meth, sc.material, verify, clientCaFile, clientCaPem,
                           minProtoVersion, maxProtoVersion, cipherList,
                           cipherSuites)
    SSL_CTX_set_alpn_select_cb(hctx, alpnSelect, result)
    result.sniHosts.add sc.host
    result.sniCtx.add hctx
  if sni.len > 0:
    discard SSL_CTX_callback_ctrl(ctx, SSL_CTRL_SET_TLSEXT_SERVERNAME_CB,
                                  cast[pointer](servernameCb))
    discard SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG, 0, result)

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
  # Explicit file paths override any stored in-memory/PKCS#12 material; empty
  # means "reuse what was last loaded" (files, PEM, or p12).
  var m = cfg.material
  if certFile.len > 0:
    m.certFile = certFile; m.certPem = ""; m.pkcs12File = ""; m.pkcs12 = ""
  if keyFile.len > 0:
    m.keyFile = keyFile; m.keyPem = ""
  var newCtx: SslCtxPtr
  try:
    newCtx = buildTlsCtx(cfg.meth, m, cfg.verify, cfg.clientCaFile,
                         cfg.clientCaPem, cfg.minProtoVersion,
                         cfg.maxProtoVersion, cfg.cipherList, cfg.cipherSuites)
  except CatchableError:
    return false
  SSL_CTX_set_alpn_select_cb(newCtx, alpnSelect, cfg)
  if cfg.ocsp.len > 0:   # re-attach OCSP stapling to the rebuilt ctx
    discard SSL_CTX_callback_ctrl(newCtx, SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB,
                                  cast[pointer](statusCb))
    discard SSL_CTX_ctrl(newCtx, SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG, 0, cfg)
  cfg.material = m
  let old = atomicExchangeN(addr cfg.ctx, newCtx, ATOMIC_ACQ_REL)
  # Retire `old` with a time-based grace rather than freeing the previous
  # retirement outright: freeing at the *next* reload alone is unsafe if two
  # reloads land within a thread's load->SSL_new window (the ctx it loaded could
  # be freed before it up-refs). Free only ctxs displaced at least ctxGraceSec
  # ago; keep the rest in a small fixed ring.
  let now = getMonoTime()
  for i in 0 ..< ctxRetireSlots:
    if cfg.retired[i] != nil and (now - cfg.retiredAt[i]).inSeconds >= ctxGraceSec:
      SSL_CTX_free(cfg.retired[i]); cfg.retired[i] = nil
  var placed = false
  for i in 0 ..< ctxRetireSlots:
    if cfg.retired[i] == nil:
      cfg.retired[i] = old; cfg.retiredAt[i] = now; placed = true; break
  if not placed:
    # Ring full (many reloads within the grace window): evict the oldest.
    var oldest = 0
    for i in 1 ..< ctxRetireSlots:
      if cfg.retiredAt[i] < cfg.retiredAt[oldest]: oldest = i
    SSL_CTX_free(cfg.retired[oldest])
    cfg.retired[oldest] = old; cfg.retiredAt[oldest] = now
  true

# --- QUIC (HTTP/3) certificate reload ---------------------------------------
#
# The h3 stack (ngtcp2 + nghttp3) owns a per-loop TLS context that the atomic
# pointer swap the TCP path uses would not reach, so each loop thread reloads its
# own engine *in place* on its own thread (eventloop.applyQuicReload ->
# ngReloadCert). New handshakes present the new cert; in-flight connections keep
# theirs.
#
# The main thread signals a reload through this plain-memory struct (fixed
# buffers, never GC strings, so it is safe to read from the loop threads).

const certPathMax = 4096            # PATH_MAX on Linux; macOS is 1024

type
  CertReload* = object
    ## Main-thread -> loop-thread signal for a QUIC certificate reload. A Lock
    ## makes the {generation, paths} update atomic as a unit, so a loop can
    ## never read a path spliced from two overlapping reloads. Paths are fixed
    ## buffers (never GC strings), so they are safe to read from the loop
    ## threads without ORC refcount races.
    lock: Lock
    gen: int
    certPath: array[certPathMax, char]
    keyPath: array[certPathMax, char]

proc initCertReload*(r: ptr CertReload) = initLock(r.lock)
proc deinitCertReload*(r: ptr CertReload) = deinitLock(r.lock)

proc setPath(dst: var array[certPathMax, char], s: string) =
  let n = min(s.len, certPathMax - 1)   # over-length paths truncate -> the
  for i in 0 ..< n: dst[i] = s[i]        # reload then fails validation and is
  dst[n] = '\0'                          # reported (not silently applied)

proc getPath(src: array[certPathMax, char]): string =
  var n = 0
  while n < certPathMax and src[n] != '\0': inc n
  result = newString(n)
  for i in 0 ..< n: result[i] = src[i]

proc requestCertReload*(r: ptr CertReload, certFile, keyFile: string) =
  ## Main thread: publish the paths for a QUIC certificate reload and bump the
  ## generation, as one locked update. Empty paths mean "re-read the configured
  ## ones".
  acquire(r.lock)
  setPath(r.certPath, certFile)
  setPath(r.keyPath, keyFile)
  inc r.gen
  release(r.lock)

proc pendingCertReload*(r: ptr CertReload, seen: int,
                        certFile, keyFile: var string): int =
  ## Loop thread: returns the current reload generation. When it differs from
  ## `seen`, fills `certFile`/`keyFile` with the requested paths (a consistent
  ## snapshot under the lock). The caller advances its own `seen` once it has
  ## acted on the result.
  acquire(r.lock)
  result = r.gen
  if result != seen:
    certFile = getPath(r.certPath)
    keyFile = getPath(r.keyPath)
  release(r.lock)


proc ctxCertSubject*(cfg: ptr TlsConfig): string =
  ## The subject line of the certificate currently installed on `cfg.ctx`, for
  ## tests/introspection: proves an in-place reload actually reached the ctx.
  ## "" if no certificate is set.
  let x = SSL_CTX_get0_certificate(cfg.ctx)
  if x == nil: return ""
  var buf = newString(512)
  let s = X509_NAME_oneline(X509_get_subject_name(x), buf.cstring, 512)
  if s == nil: return ""
  $s

proc newTlsConfig*(certFile, keyFile: string, enableH2 = false,
                   minProtoVersion: clong = 0, cipherList = "", cipherSuites = "",
                   certPem = "", keyPem = "", keyPassword = "",
                   pkcs12File = "", pkcs12 = "", verify: cint = 0,
                   clientCaFile = "", clientCaPem = "",
                   sni: openArray[SniCert] = [], maxProtoVersion: clong = 0,
                   ocsp = ""): ptr TlsConfig =
  let m = TlsMaterial(certFile: certFile, keyFile: keyFile, certPem: certPem,
                      keyPem: keyPem, pkcs12File: pkcs12File, pkcs12: pkcs12,
                      keyPassword: keyPassword)
  newTlsConfigWith(TLS_server_method(), m,
    (if enableH2: "\x02h2\x08http/1.1" else: "\x08http/1.1"),
    minProtoVersion, cipherList, cipherSuites, verify, clientCaFile,
    clientCaPem, sni, maxProtoVersion, ocsp)

proc peerCertSubject*(ssl: SslPtr): string =
  ## Subject DN of the peer's (client's) certificate, "" if none was presented.
  ## In SSL_VERIFY_PEER mode OpenSSL has already verified any presented cert
  ## during the handshake, so a non-empty result is a verified client cert.
  if ssl == nil: return ""
  let x = SSL_get1_peer_certificate(ssl)
  if x == nil: return ""
  defer: X509_free(x)
  var buf = newString(512)
  let s = X509_NAME_oneline(X509_get_subject_name(x), buf.cstring, 512)
  if s == nil: "" else: $s

proc freeTlsConfig*(cfg: ptr TlsConfig) =
  SSL_CTX_free(cfg.ctx)
  for i in 0 ..< ctxRetireSlots:
    if cfg.retired[i] != nil: SSL_CTX_free(cfg.retired[i])
  for c in cfg.sniCtx: SSL_CTX_free(c)
  cfg.sniCtx = @[]
  cfg.sniHosts = @[]
  cfg.protos = ""
  cfg.material = TlsMaterial()
  cfg.clientCaFile = ""
  cfg.clientCaPem = ""
  cfg.cipherList = ""
  cfg.cipherSuites = ""
  cfg.ocsp = ""
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
