## OpenSSL (>= 3.5) server-side QUIC bindings for HTTP/3. We own the UDP
## socket; OpenSSL owns the QUIC transport (handshake, loss recovery,
## congestion control). Event integration: SSL_handle_events on the
## listener each loop pass, with SSL_get_event_timeout feeding the
## selector timeout.

import std/[posix, dynlib, tables]
import ./tls
export tls.TlsIo, tls.tlsRead, tls.tlsWrite, tls.freeTlsSession,
       tls.tlsSelectedAlpn, tls.TlsConfig, tls.freeTlsConfig, tls.SslPtr

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

const
  SSL_STREAM_FLAG_UNI = 1'u64
  SSL_DEFAULT_STREAM_MODE_NONE = 0'u32
  SSL_INCOMING_STREAM_POLICY_ACCEPT = cint(1)
  SSL_STREAM_TYPE_BIDI* = cint(3)
  SSL_ACCEPT_CONNECTION_NO_BLOCK = 1'u64

{.push importc, cdecl, dynlib: sslLibName.}
proc OSSL_QUIC_server_method(): pointer
proc SSL_new_listener(ctx: pointer, flags: uint64): SslPtr
proc SSL_set_fd(ssl: SslPtr, fd: cint): cint
proc SSL_set_blocking_mode(ssl: SslPtr, blocking: cint): cint
proc SSL_listen(ssl: SslPtr, flags: uint64): cint
proc SSL_accept_connection(ssl: SslPtr, flags: uint64): SslPtr
proc SSL_accept_stream(ssl: SslPtr, flags: uint64): SslPtr
proc SSL_new_stream(ssl: SslPtr, flags: uint64): SslPtr
proc SSL_get_stream_id(ssl: SslPtr): uint64
proc SSL_get_stream_type(ssl: SslPtr): cint
proc SSL_set_default_stream_mode(ssl: SslPtr, mode: uint32): cint
proc SSL_set_incoming_stream_policy(ssl: SslPtr, policy: cint,
                                    aec: uint64): cint
proc SSL_handle_events(ssl: SslPtr): cint
proc SSL_get_event_timeout(ssl: SslPtr, tv: ptr Timeval,
                           isInfinite: ptr cint): cint
proc SSL_stream_conclude(ssl: SslPtr, flags: uint64): cint
proc SSL_get_shutdown(ssl: SslPtr): cint
{.pop.}

type
  SslShutdownExArgs = object
    quicErrorCode: uint64
    quicReason: cstring
  SslStreamResetArgs = object
    quicErrorCode: uint64

proc SSL_shutdown_ex(ssl: SslPtr, flags: uint64, args: ptr SslShutdownExArgs,
                     argsLen: csize_t): cint
  {.importc: "SSL_shutdown_ex", cdecl, dynlib: sslLibName.}
proc SSL_stream_reset(ssl: SslPtr, args: ptr SslStreamResetArgs,
                      argsLen: csize_t): cint
  {.importc: "SSL_stream_reset", cdecl, dynlib: sslLibName.}

const SSL_SHUTDOWN_FLAG_IMMEDIATE = 0x01'u64

proc SSL_free_q(ssl: SslPtr)
  {.importc: "SSL_free", cdecl, dynlib: sslLibName.}

# --- QUIC peer-address capture -------------------------------------------
# OpenSSL exposes no usable getter for a QUIC *server* connection's peer
# address: the address is stored on the channel but walled behind an
# addressed_mode flag that is only ever set client-side. So we capture it
# ourselves. A filter BIO wraps the UDP datagram BIO and taps every inbound
# datagram, recording its source IP keyed by the QUIC Destination Connection
# ID from the packet header (which, for client->server traffic, is our own
# local CID). At accept we read the connection's local CID and look it up.

const
  BIO_TYPE_DESCRIPTOR = 0x0100
  BIO_TYPE_SOURCE_SINK = 0x0400
  BIO_NOCLOSE = 0x00
  BIO_CTRL_PUSH = 6
  BIO_CTRL_POP = 7
  BIO_CTRL_DUP = 12
  quicMaxConnIdLen = 20

type
  BioMsg = object          ## mirrors OpenSSL's BIO_MSG
    data: pointer
    dataLen: csize_t
    peer, local: pointer   ## BIO_ADDR*
    flags: uint64
  QuicConnId = object      ## mirrors OpenSSL's QUIC_CONN_ID
    idLen: uint8
    id: array[quicMaxConnIdLen, uint8]

{.push importc, cdecl, dynlib: cryptoLibName.}
proc BIO_ADDR_hostname_string(ap: pointer, numeric: cint): cstring
proc CRYPTO_free(p: pointer, file: cstring, line: cint)
proc BIO_new_dgram(fd: cint, closeFlag: cint): pointer
proc BIO_new(m: pointer): pointer
proc BIO_free(b: pointer): cint
proc BIO_set_data(b, p: pointer)
proc BIO_get_data(b: pointer): pointer
proc BIO_set_init(b: pointer, i: cint)
proc BIO_get_new_index(): cint
proc BIO_meth_new(typ: cint, name: cstring): pointer
proc BIO_meth_set_create(m, f: pointer): cint
proc BIO_meth_set_destroy(m, f: pointer): cint
proc BIO_meth_set_ctrl(m, f: pointer): cint
proc BIO_meth_set_sendmmsg(m, f: pointer): cint
proc BIO_meth_set_recvmmsg(m, f: pointer): cint
proc BIO_recvmmsg(b, msg: pointer, stride, num: csize_t, flags: uint64,
                  processed: ptr csize_t): cint
proc BIO_sendmmsg(b, msg: pointer, stride, num: csize_t, flags: uint64,
                  processed: ptr csize_t): cint
proc BIO_ctrl(b: pointer, cmd: cint, larg: clong, parg: pointer): clong
{.pop.}

proc SSL_set_bio(ssl: SslPtr, rbio, wbio: pointer)
  {.importc, cdecl, dynlib: sslLibName.}

# The internal ossl_* symbols map a connection SSL to its channel and read the
# channel's local CID. Both are diagnostic getters (no address state); resolved
# at runtime and nil-guarded so a future OpenSSL that drops them degrades to ""
# rather than failing to link or crashing.
type
  GetChannelFn = proc(ssl: SslPtr): pointer {.cdecl, gcsafe, raises: [].}
  GetLocalCidFn = proc(ch: pointer, cid: ptr QuicConnId) {.cdecl, gcsafe,
                                                           raises: [].}
var
  qcGetChannel {.threadvar.}: GetChannelFn
  qcGetLocalCid {.threadvar.}: GetLocalCidFn
  qcResolved {.threadvar.}: bool
  qcPeers {.threadvar.}: Table[string, string]  ## DCID bytes -> peer IP
  tapMeth {.threadvar.}: pointer                ## cached filter BIO_METHOD

proc ensureResolved() =
  if qcResolved: return
  qcResolved = true
  # dlopen(NULL) does not expose libssl's internal symbols on macOS, so load
  # the library explicitly (same candidates as sslLibName) and read from it.
  const cands =
    when defined(macosx):
      ["/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib",
       "/opt/homebrew/opt/openssl/lib/libssl.3.dylib",
       "/usr/local/opt/openssl@3/lib/libssl.3.dylib",
       "libssl.3.dylib"]
    else:
      ["libssl.so.3", "libssl.so"]
  for c in cands:
    let h = loadLib(c)
    if h == nil: continue
    qcGetChannel = cast[GetChannelFn](h.symAddr("ossl_quic_conn_get_channel"))
    qcGetLocalCid = cast[GetLocalCidFn](
      h.symAddr("ossl_quic_channel_get_diag_local_cid"))
    if qcGetChannel != nil and qcGetLocalCid != nil: break

proc recordPeer(m: ptr BioMsg) {.raises: [].} =
  ## Tap a received datagram: record its source IP under the packet's DCID.
  if m.peer == nil or m.data == nil or m.dataLen < 6: return
  let d = cast[ptr UncheckedArray[byte]](m.data)
  if (d[0] and 0x80'u8) == 0: return   # short header: DCID length not encoded
  let dcidLen = int(d[5])              # long header: version(4) then DCID len
  if dcidLen == 0 or dcidLen > quicMaxConnIdLen or int(m.dataLen) < 6 + dcidLen:
    return
  let cs = BIO_ADDR_hostname_string(m.peer, 1)   # numeric literal, no DNS
  if cs == nil: return
  var key = newString(dcidLen)
  copyMem(addr key[0], addr d[6], dcidLen)
  if qcPeers.len >= 4096: qcPeers.clear()   # bound memory (entries are transient)
  qcPeers[key] = $cs
  CRYPTO_free(cs, nil, 0)

proc tapCreate(b: pointer): cint {.cdecl.} =
  BIO_set_init(b, 1)
  1

proc tapDestroy(b: pointer): cint {.cdecl.} =
  if b != nil:
    let raw = BIO_get_data(b)
    if raw != nil: discard BIO_free(raw)
  1

proc tapCtrl(b: pointer, cmd: cint, larg: clong, parg: pointer): clong {.cdecl.} =
  let raw = BIO_get_data(b)
  if raw == nil: return 0
  case cmd
  of BIO_CTRL_PUSH, BIO_CTRL_POP, BIO_CTRL_DUP: 0   # filter-only, don't forward
  else: BIO_ctrl(raw, cmd, larg, parg)

proc tapSend(b, msg: pointer, stride, num: csize_t, flags: uint64,
             processed: ptr csize_t): cint {.cdecl.} =
  let raw = BIO_get_data(b)
  if raw == nil: return 0
  BIO_sendmmsg(raw, msg, stride, num, flags, processed)

proc tapRecv(b, msg: pointer, stride, num: csize_t, flags: uint64,
             processed: ptr csize_t): cint {.cdecl, raises: [].} =
  let raw = BIO_get_data(b)
  if raw == nil: return 0
  result = BIO_recvmmsg(raw, msg, stride, num, flags, processed)
  if result != 1 or processed == nil: return
  for i in 0 ..< int(processed[]):
    let m = cast[ptr BioMsg](cast[uint](msg) + uint(i) * uint(stride))
    # Only long-header packets (high bit set) carry a parseable DCID. Short
    # header 1-RTT data packets -- the steady-state bulk -- skip the call
    # entirely; the DCID is captured from the handshake's long-header packets.
    if m.data != nil and m.dataLen >= 6 and
        (cast[ptr UncheckedArray[byte]](m.data)[0] and 0x80'u8) != 0:
      recordPeer(m)

proc tapMethod(): pointer =
  if tapMeth != nil: return tapMeth
  let m = BIO_meth_new(BIO_get_new_index() or BIO_TYPE_SOURCE_SINK or
                       BIO_TYPE_DESCRIPTOR, "vortex-quic-tap")
  if m == nil: return nil
  discard BIO_meth_set_create(m, cast[pointer](tapCreate))
  discard BIO_meth_set_destroy(m, cast[pointer](tapDestroy))
  discard BIO_meth_set_ctrl(m, cast[pointer](tapCtrl))
  discard BIO_meth_set_sendmmsg(m, cast[pointer](tapSend))
  discard BIO_meth_set_recvmmsg(m, cast[pointer](tapRecv))
  tapMeth = m
  m

proc newTapBio(fd: cint): pointer =
  ## A filter BIO over the UDP datagram BIO that taps inbound peer addresses.
  let raw = BIO_new_dgram(fd, BIO_NOCLOSE)   # the loop owns and closes the fd
  if raw == nil: return nil
  let m = tapMethod()
  if m == nil: (discard BIO_free(raw); return nil)
  result = BIO_new(m)
  if result == nil: (discard BIO_free(raw); return nil)
  BIO_set_data(result, raw)
  BIO_set_init(result, 1)

proc quicPeerAddr*(conn: SslPtr): string =
  ## Numeric peer IP (no port) of an accepted QUIC server connection, captured
  ## by the datagram tap and keyed by our local CID. "" if unavailable.
  if conn == nil: return ""
  ensureResolved()
  if qcGetChannel == nil or qcGetLocalCid == nil: return ""
  let ch = qcGetChannel(conn)
  if ch == nil: return ""
  var cid: QuicConnId
  qcGetLocalCid(ch, addr cid)
  if cid.idLen == 0 or int(cid.idLen) > quicMaxConnIdLen: return ""
  var key = newString(int(cid.idLen))
  copyMem(addr key[0], addr cid.id[0], int(cid.idLen))
  if qcPeers.hasKey(key):
    result = qcPeers[key]
    qcPeers.del(key)   # consumed once, at accept

proc newQuicConfig*(certFile, keyFile: string, cipherSuites = "",
                    certPem = "", keyPem = "", keyPassword = ""): ptr TlsConfig =
  ## SSL_CTX for the QUIC server; ALPN offers h3 only. QUIC mandates
  ## TLS 1.3, so only the 1.3 cipher suites are configurable.
  newTlsConfigWith(OSSL_QUIC_server_method(), certFile, keyFile, "\x02h3",
                   cipherSuites = cipherSuites, certPem = certPem,
                   keyPem = keyPem, keyPassword = keyPassword)

proc newQuicListener*(cfg: ptr TlsConfig, udpFd: cint): SslPtr =
  result = SSL_new_listener(cfg.ctx, 0)
  if result == nil: return nil
  # Attach the datagram tap instead of SSL_set_fd so we can record peer
  # addresses (SSL_set_bio consumes one reference; rbio and wbio are the same).
  let bio = newTapBio(udpFd)
  if bio == nil:
    SSL_free_q(result)
    return nil
  SSL_set_bio(result, bio, bio)
  if SSL_set_blocking_mode(result, 0) != 1 or SSL_listen(result, 0) != 1:
    SSL_free_q(result)
    return nil

proc quicAcceptConnection*(listener: SslPtr): SslPtr =
  result = SSL_accept_connection(listener, SSL_ACCEPT_CONNECTION_NO_BLOCK)
  if result != nil:
    discard SSL_set_blocking_mode(result, 0)
    discard SSL_set_default_stream_mode(result, SSL_DEFAULT_STREAM_MODE_NONE)
    discard SSL_set_incoming_stream_policy(
      result, SSL_INCOMING_STREAM_POLICY_ACCEPT, 0)

proc quicAcceptStream*(conn: SslPtr): SslPtr =
  SSL_accept_stream(conn, 0)      # nonblocking mode: nil when none pending

proc quicNewUniStream*(conn: SslPtr): SslPtr =
  SSL_new_stream(conn, SSL_STREAM_FLAG_UNI)

proc quicStreamId*(ssl: SslPtr): uint64 =
  SSL_get_stream_id(ssl)

proc quicStreamIsBidi*(ssl: SslPtr): bool =
  SSL_get_stream_type(ssl) == SSL_STREAM_TYPE_BIDI

proc quicHandleEvents*(ssl: SslPtr) =
  discard SSL_handle_events(ssl)

proc quicEventTimeoutMs*(ssl: SslPtr): int =
  ## Milliseconds until OpenSSL needs another SSL_handle_events call;
  ## -1 when no timer is pending.
  var tv: Timeval
  var inf: cint
  if SSL_get_event_timeout(ssl, addr tv, addr inf) != 1 or inf != 0:
    return -1
  int(tv.tv_sec) * 1000 + int(tv.tv_usec) div 1000

proc quicConclude*(ssl: SslPtr) =
  ## Send FIN on a stream (response complete).
  discard SSL_stream_conclude(ssl, 0)

proc quicCloseConn*(conn: SslPtr, errorCode: uint64) =
  ## Close the QUIC connection with an application (HTTP/3) error code,
  ## emitting CONNECTION_CLOSE. Immediate: does not wait to flush streams.
  ## Used for HTTP/3 connection errors (RFC 9114 8).
  var args = SslShutdownExArgs(quicErrorCode: errorCode, quicReason: nil)
  discard SSL_shutdown_ex(conn, SSL_SHUTDOWN_FLAG_IMMEDIATE, addr args,
                          csize_t(sizeof(args)))
  discard SSL_handle_events(conn)   # flush the CONNECTION_CLOSE to the wire

proc quicResetStream*(ssl: SslPtr, errorCode: uint64) =
  ## Abort a stream with RESET_STREAM carrying an application error code
  ## (RFC 9114 stream error, e.g. a malformed request -> H3_MESSAGE_ERROR).
  var args = SslStreamResetArgs(quicErrorCode: errorCode)
  discard SSL_stream_reset(ssl, addr args, csize_t(sizeof(args)))

proc quicConnDead*(conn: SslPtr): bool =
  SSL_get_shutdown(conn) != 0

proc quicFree*(ssl: SslPtr) =
  SSL_free_q(ssl)
