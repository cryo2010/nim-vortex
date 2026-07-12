## OpenSSL (>= 3.5) server-side QUIC bindings for HTTP/3. We own the UDP
## socket; OpenSSL owns the QUIC transport (handshake, loss recovery,
## congestion control). Event integration: SSL_handle_events on the
## listener each loop pass, with SSL_get_event_timeout feeding the
## selector timeout.

import std/posix
import ./tls
export tls.TlsIo, tls.tlsRead, tls.tlsWrite, tls.freeTlsSession,
       tls.tlsSelectedAlpn, tls.TlsConfig, tls.freeTlsConfig, tls.SslPtr

const sslLibName {.strdefine.} =
  when defined(macosx):
    "(/opt/homebrew/opt/openssl@3/lib/|/usr/local/opt/openssl@3/lib/|)libssl.3.dylib"
  else:
    "libssl.so(.3|)"

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

proc newQuicConfig*(certFile, keyFile: string,
                    cipherSuites = ""): ptr TlsConfig =
  ## SSL_CTX for the QUIC server; ALPN offers h3 only. QUIC mandates
  ## TLS 1.3, so only the 1.3 cipher suites are configurable.
  newTlsConfigWith(OSSL_QUIC_server_method(), certFile, keyFile, "\x02h3",
                   cipherSuites = cipherSuites)

proc newQuicListener*(cfg: ptr TlsConfig, udpFd: cint): SslPtr =
  result = SSL_new_listener(cfg.ctx, 0)
  if result == nil: return nil
  if SSL_set_fd(result, udpFd) != 1 or
      SSL_set_blocking_mode(result, 0) != 1 or
      SSL_listen(result, 0) != 1:
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
