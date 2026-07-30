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
  SSL_FILETYPE_PEM = cint(1)
  SSL_ERROR_WANT_READ = cint(2)
  SSL_ERROR_WANT_WRITE = cint(3)
  SSL_ERROR_SYSCALL = cint(5)
  SSL_ERROR_ZERO_RETURN = cint(6)
  SSL_CTRL_MODE = cint(33)
  SSL_CTRL_EXTRA_CHAIN_CERT = cint(14)     # append a cert to the chain (add0)
  SSL_CTRL_CLEAR_CHAIN_CERTS = cint(88)    # drop the built chain (for in-place reload)
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
proc SSL_CTX_use_PrivateKey_file(ctx: SslCtxPtr, file: cstring,
                                 typ: cint): cint
proc SSL_CTX_use_certificate(ctx: SslCtxPtr, x: pointer): cint   # up-refs x
proc SSL_CTX_use_PrivateKey(ctx: SslCtxPtr, pkey: pointer): cint # up-refs pkey
proc SSL_CTX_set_default_passwd_cb(ctx: SslCtxPtr, cb: PemPasswordCb)
proc SSL_CTX_set_default_passwd_cb_userdata(ctx: SslCtxPtr, u: pointer)
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
  let bio = BIO_new_mem_buf(unsafeAddr pem[0], cint(pem.len))
  if bio == nil: return false
  defer: discard BIO_free(bio)
  let cb = if password.len > 0: passwdCb else: nil
  let ud = if password.len > 0: cast[pointer](password.cstring) else: nil
  let pkey = PEM_read_bio_PrivateKey(bio, nil, cb, ud)
  if pkey == nil: return false
  result = SSL_CTX_use_PrivateKey(ctx, pkey) == 1      # up-refs pkey
  EVP_PKEY_free(pkey)

type
  TlsConfig* = object
    ## One per server; SSL_CTX is thread-safe for SSL_new. Lives in shared
    ## memory so loop threads can use it via pointer.
    ctx*: SslCtxPtr          ## active SSL_CTX; loop threads load it atomically
                             ## so a certificate hot-reload can swap it in
    retired: array[ctxRetireSlots, SslCtxPtr]   ## displaced ctxs pending free
    retiredAt: array[ctxRetireSlots, MonoTime]  ## when each was displaced
    protos: string           ## ALPN preference list, wire format
    meth: pointer            ## method the ctx was built with (rebuild on reload)
    certFile, keyFile: string
    certPem, keyPem, keyPassword: string   ## in-memory material / passphrase
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

proc buildTlsCtx(meth: pointer, certFile, keyFile, certPem, keyPem,
                 keyPassword: string, minProtoVersion: clong,
                 cipherList, cipherSuites: string): SslCtxPtr =
  ## Build a fully-configured SSL_CTX (min version, ciphers, cert/key). The cert
  ## and key each come from memory (certPem/keyPem) when set, otherwise from a
  ## file (certFile/keyFile); keyPassword decrypts an encrypted key. Raises on
  ## any failure, freeing the partial ctx. The ALPN callback is set by the
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
  # Passphrase for an encrypted key: used by both the file and memory loaders.
  if keyPassword.len > 0:
    SSL_CTX_set_default_passwd_cb(ctx, passwdCb)
    SSL_CTX_set_default_passwd_cb_userdata(ctx, keyPassword.cstring)
  let certOk = if certPem.len > 0: loadCertChainMem(ctx, certPem)
               else: SSL_CTX_use_certificate_chain_file(ctx, certFile.cstring) == 1
  if not certOk:
    SSL_CTX_free(ctx)
    raise newException(CatchableError,
      "cannot load certificate " &
      (if certPem.len > 0: "(in-memory)" else: "'" & certFile & "'") &
      ": " & lastErrorMsg())
  let keyOk = if keyPem.len > 0: loadKeyMem(ctx, keyPem, keyPassword)
              else: SSL_CTX_use_PrivateKey_file(ctx, keyFile.cstring,
                                                SSL_FILETYPE_PEM) == 1
  if not keyOk:
    SSL_CTX_free(ctx)
    raise newException(CatchableError,
      "cannot load private key " &
      (if keyPem.len > 0: "(in-memory)" else: "'" & keyFile & "'") &
      ": " & lastErrorMsg())
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
                       cipherList = "", cipherSuites = "",
                       certPem = "", keyPem = "", keyPassword = ""): ptr TlsConfig =
  let ctx = buildTlsCtx(meth, certFile, keyFile, certPem, keyPem, keyPassword,
                        minProtoVersion, cipherList, cipherSuites)
  result = createShared(TlsConfig)
  result.ctx = ctx
  result.protos = protos
  result.meth = meth
  result.certFile = certFile
  result.keyFile = keyFile
  result.certPem = certPem
  result.keyPem = keyPem
  result.keyPassword = keyPassword
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
  # Explicit file paths override any stored in-memory material; empty means
  # "reuse what was last loaded" (files or PEM).
  let cf = if certFile.len > 0: certFile else: cfg.certFile
  let kf = if keyFile.len > 0: keyFile else: cfg.keyFile
  let cp = if certFile.len > 0: "" else: cfg.certPem
  let kp = if keyFile.len > 0: "" else: cfg.keyPem
  var newCtx: SslCtxPtr
  try:
    newCtx = buildTlsCtx(cfg.meth, cf, kf, cp, kp, cfg.keyPassword,
                         cfg.minProtoVersion, cfg.cipherList, cfg.cipherSuites)
  except CatchableError:
    return false
  SSL_CTX_set_alpn_select_cb(newCtx, alpnSelect, cfg)
  cfg.certFile = cf
  cfg.keyFile = kf
  cfg.certPem = cp
  cfg.keyPem = kp
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
# A QUIC listener binds its SSL_CTX at creation, so the atomic pointer swap the
# TCP path uses would not reach it. Instead each loop thread owns a private QUIC
# ctx and updates it *in place* on its own thread (so no handshake on that
# listener interleaves the update, and no other thread touches the ctx). New
# connections read the ctx's current cert at accept time -- the same mechanism
# as SSL_new on the TCP side -- while in-flight connections keep theirs.
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

proc reloadQuicCert*(cfg: ptr TlsConfig, certFile, keyFile: string): bool =
  ## In-place certificate update on a per-loop QUIC ctx, called on the owning
  ## loop thread (so no handshake on that listener interleaves the two apply
  ## calls, and no other thread touches the ctx). Validates the new material in
  ## a throwaway ctx first, then applies cert+key to the live ctx. Returns false
  ## on bad material.
  ##
  ## Caveat: the probe and the apply each read the files, so a *concurrent*
  ## replacement of the files between the two (a renewal racing this call) can
  ## get past the probe and then fail the apply, briefly leaving the live ctx
  ## with a mismatched cert/key. The caller reports the false result, and a
  ## subsequent reload (retried against stable files) restores a consistent
  ## ctx. New connections read the ctx's current cert at accept time (the same
  ## mechanism as SSL_new on TCP); in-flight connections keep theirs.
  let cf = if certFile.len > 0: certFile else: cfg.certFile
  let kf = if keyFile.len > 0: keyFile else: cfg.keyFile
  let cp = if certFile.len > 0: "" else: cfg.certPem
  let kp = if keyFile.len > 0: "" else: cfg.keyPem
  try:
    SSL_CTX_free(buildTlsCtx(cfg.meth, cf, kf, cp, kp, cfg.keyPassword,
                             cfg.minProtoVersion, cfg.cipherList,
                             cfg.cipherSuites))  # probe only
  except CatchableError:
    return false
  if cfg.keyPassword.len > 0:
    SSL_CTX_set_default_passwd_cb(cfg.ctx, passwdCb)
    SSL_CTX_set_default_passwd_cb_userdata(cfg.ctx, cfg.keyPassword.cstring)
  if cp.len > 0:
    discard SSL_CTX_ctrl(cfg.ctx, SSL_CTRL_CLEAR_CHAIN_CERTS, 0, nil)  # replace
    if not loadCertChainMem(cfg.ctx, cp): return false
  elif SSL_CTX_use_certificate_chain_file(cfg.ctx, cf.cstring) != 1:
    return false
  if kp.len > 0:
    if not loadKeyMem(cfg.ctx, kp, cfg.keyPassword): return false
  elif SSL_CTX_use_PrivateKey_file(cfg.ctx, kf.cstring, SSL_FILETYPE_PEM) != 1:
    return false
  if SSL_CTX_check_private_key(cfg.ctx) != 1: return false
  cfg.certFile = cf
  cfg.keyFile = kf
  cfg.certPem = cp
  cfg.keyPem = kp
  true

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
                   minProtoVersion: clong = 0,
                   cipherList = "", cipherSuites = "",
                   certPem = "", keyPem = "", keyPassword = ""): ptr TlsConfig =
  newTlsConfigWith(TLS_server_method(), certFile, keyFile,
    (if enableH2: "\x02h2\x08http/1.1" else: "\x08http/1.1"),
    minProtoVersion, cipherList, cipherSuites, certPem, keyPem, keyPassword)

proc freeTlsConfig*(cfg: ptr TlsConfig) =
  SSL_CTX_free(cfg.ctx)
  for i in 0 ..< ctxRetireSlots:
    if cfg.retired[i] != nil: SSL_CTX_free(cfg.retired[i])
  cfg.protos = ""
  cfg.certFile = ""
  cfg.keyFile = ""
  cfg.certPem = ""
  cfg.keyPem = ""
  cfg.keyPassword = ""
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
