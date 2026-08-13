# Standalone HTTP/3 smoke server driving the vq_ngtcp2 shim directly (no vortex
# event loop yet). Validates the ngtcp2/nghttp3 handshake and a fixed 200 over a
# real UDP socket, and exercises the Nim<->shim struct/callback ABI. Built and
# run against the h2load HTTP/3 client by ngtcp2_smoke.sh. Phase 3 milestone;
# the real integration lives in eventloop.nim (Phase 4).
#
#   nim cpp --mm:orc --threads:on -d:release --passC:-std=c++20 \
#     --passL:"-lngtcp2 -lngtcp2_crypto_ossl -lnghttp3 -lssl -lcrypto" smoke_server.nim

import std/[posix, monotimes]

{.passC: "-std=c++20 -I.".}
{.passL: "-lngtcp2 -lngtcp2_crypto_ossl -lnghttp3 -lssl -lcrypto".}
{.compile: "vq_ngtcp2.cpp".}

type
  VqEngine {.importc, header: "vq_ngtcp2.h", incompleteStruct.} = object
  VqConn {.importc, header: "vq_ngtcp2.h", incompleteStruct.} = object

  VqHeader {.importc, header: "vq_ngtcp2.h", bycopy.} = object
    name: cstring
    name_len: csize_t
    value: cstring
    value_len: csize_t

  OnAccept = proc(user: pointer, conn: ptr VqConn, peerIp: cstring): pointer {.cdecl.}
  OnHeaders = proc(user, connUd: pointer, sid: int64, hdrs: ptr VqHeader, n: csize_t) {.cdecl.}
  OnBody = proc(user, connUd: pointer, sid: int64, data: ptr uint8, len: csize_t) {.cdecl.}
  OnStream = proc(user, connUd: pointer, sid: int64) {.cdecl.}
  OnStreamClose = proc(user, connUd: pointer, sid: int64, appErr: uint64) {.cdecl.}
  OnConnClose = proc(user, connUd: pointer) {.cdecl.}
  OnSend = proc(user: pointer, conn: ptr VqConn, data: ptr uint8, len: csize_t,
                peer: pointer, peerLen: csize_t): cint {.cdecl.}

  VqCallbacks {.importc, header: "vq_ngtcp2.h", bycopy.} = object
    on_accept: OnAccept
    on_headers: OnHeaders
    on_body: OnBody
    on_stream_end: OnStream
    on_stream_close: OnStreamClose
    on_stream_writable: OnStream
    on_conn_close: OnConnClose
    on_send: OnSend

  VqConfig {.importc, header: "vq_ngtcp2.h", bycopy.} = object
    user: pointer
    cb: VqCallbacks
    cert_file: cstring
    key_file: cstring
    cert_pem: cstring
    key_pem: cstring
    key_password: cstring
    max_body: uint64
    max_concurrent_streams: uint64
    max_field_section_size: cint

{.push header: "vq_ngtcp2.h", cdecl.}
proc vqEngineNew(cfg: ptr VqConfig): ptr VqEngine {.importc: "vq_engine_new".}
proc vqEngineRecv(e: ptr VqEngine, pkt: ptr uint8, len: csize_t, peer: pointer,
  peerLen: csize_t, local: pointer, localLen: csize_t, nowNs: uint64) {.importc: "vq_engine_recv".}
proc vqEnginePump(e: ptr VqEngine, nowNs: uint64) {.importc: "vq_engine_pump".}
proc vqEngineNextExpiry(e: ptr VqEngine, nowNs: uint64): uint64 {.importc: "vq_engine_next_expiry_ns".}
proc vqEngineHandleExpiry(e: ptr VqEngine, nowNs: uint64) {.importc: "vq_engine_handle_expiry".}
proc vqSubmitResponse(conn: ptr VqConn, sid: int64, status: cint, hdrs: ptr VqHeader,
  n: csize_t, body: ptr uint8, bodyLen: csize_t, fin: cint) {.importc: "vq_submit_response".}
{.pop.}

var
  gFd: SocketHandle
  gEngine: ptr VqEngine

proc nowNs(): uint64 = getMonoTime().ticks.uint64

proc htons16(x: uint16): uint16 = (x shl 8) or (x shr 8)   # little-endian hosts

proc hdr(n, v: string): VqHeader =
  VqHeader(name: n.cstring, name_len: n.len.csize_t,
           value: v.cstring, value_len: v.len.csize_t)

proc onAccept(user: pointer, conn: ptr VqConn, peerIp: cstring): pointer {.cdecl.} =
  cast[pointer](conn)   # use the VqConn* itself as the per-conn handle (smoke)

proc onHeaders(user, connUd: pointer, sid: int64, hdrs: ptr VqHeader, n: csize_t) {.cdecl.} =
  discard            # a real backend dispatches here; smoke waits for stream end

proc onBody(user, connUd: pointer, sid: int64, data: ptr uint8, len: csize_t) {.cdecl.} =
  discard

proc onStreamEnd(user, connUd: pointer, sid: int64) {.cdecl.} =
  # Fixed 200 "ok" for every request.
  var hs = [hdr(":status", "200"), hdr("content-type", "text/plain")]
  const body = "ok"
  vqSubmitResponse(cast[ptr VqConn](connUd), sid, 200, addr hs[0], hs.len.csize_t,
                   cast[ptr uint8](cstring(body)), body.len.csize_t, 1)

proc onStreamClose(user, connUd: pointer, sid: int64, appErr: uint64) {.cdecl.} = discard
proc onStreamWritable(user, connUd: pointer, sid: int64) {.cdecl.} = discard
proc onConnClose(user, connUd: pointer) {.cdecl.} = discard

proc onSend(user: pointer, conn: ptr VqConn, data: ptr uint8, len: csize_t,
            peer: pointer, peerLen: csize_t): cint {.cdecl.} =
  discard sendto(gFd, data, int(len), cint(0), cast[ptr SockAddr](peer),
                 SockLen(peerLen))
  0

proc main() =
  gFd = socket(AF_INET, SOCK_DGRAM, 0)
  if cint(gFd) < 0: quit "socket failed"
  var one: cint = 1
  discard setsockopt(gFd, SOL_SOCKET, SO_REUSEADDR, addr one, SockLen(sizeof(one)))
  var sa: Sockaddr_in
  sa.sin_family = TSa_Family(AF_INET)
  sa.sin_port = InPort(htons16(4433))
  sa.sin_addr.s_addr = InAddrScalar(0)   # INADDR_ANY
  if bindSocket(gFd, cast[ptr SockAddr](addr sa), SockLen(sizeof(sa))) < 0:
    quit "bind failed"
  var local: Sockaddr_in
  var locLen = SockLen(sizeof(local))
  discard getsockname(gFd, cast[ptr SockAddr](addr local), addr locLen)
  discard fcntl(cint(gFd), F_SETFL, fcntl(cint(gFd), F_GETFL, 0) or O_NONBLOCK)

  var cfg: VqConfig
  cfg.cb = VqCallbacks(on_accept: onAccept, on_headers: onHeaders, on_body: onBody,
    on_stream_end: onStreamEnd, on_stream_close: onStreamClose,
    on_stream_writable: onStreamWritable, on_conn_close: onConnClose, on_send: onSend)
  cfg.cert_file = "cert.pem"
  cfg.key_file = "key.pem"
  cfg.max_concurrent_streams = 100
  cfg.max_field_section_size = 128 * 1024
  gEngine = vqEngineNew(addr cfg)
  if gEngine == nil: quit "vq_engine_new failed (cert/key?)"
  stderr.writeLine "listening"   # ngtcp2_smoke.sh waits for this

  var buf: array[2048, uint8]
  var pfd = TPollfd(fd: cint(gFd), events: POLLIN)
  while true:
    let now = nowNs()
    let exp = vqEngineNextExpiry(gEngine, now)
    var timeoutMs: cint = 1000
    if exp != high(uint64):
      timeoutMs = (if exp <= now: 0.cint else: cint((exp - now) div 1_000_000) + 1)
    discard poll(addr pfd, Tnfds(1), timeoutMs)
    while true:
      var peer: Sockaddr_storage
      var plen = SockLen(sizeof(peer))
      let n = recvfrom(gFd, addr buf[0], buf.len, cint(0),
                       cast[ptr SockAddr](addr peer), addr plen)
      if n <= 0: break
      vqEngineRecv(gEngine, addr buf[0], n.csize_t, addr peer, plen.csize_t,
                   addr local, locLen.csize_t, nowNs())
    vqEngineHandleExpiry(gEngine, nowNs())
    vqEnginePump(gEngine, nowNs())

main()
