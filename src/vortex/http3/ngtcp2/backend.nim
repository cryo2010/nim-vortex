## HTTP/3 backend over ngtcp2 (QUIC) + nghttp3, via the vq_ngtcp2 C++ shim.
## The HTTP/3 implementation for vortex: request.nim and eventloop.nim import it
## as `h3codec`. nghttp3 does the framing/QPACK; this module holds per-request
## state and translates request/response calls to the shim. Loop-thread only
## (one engine per thread). Building HTTP/3 (any non -d:plainHttp build) links
## ngtcp2 + nghttp3 (see the passL below).

import std/[tables, strutils, uri, json, os, monotimes]
import ../../connection
import ../../websocket/codec as wscodec

# The shim is a C++ TU compiled by g++ (via {.compile.} on a .cpp), while the
# rest of vortex stays on the C backend -- so no -std on passC (it would reach
# Nim's generated .c files). -lstdc++ links the C++ runtime the shim needs.
{.passC: "-I" & currentSourcePath().parentDir.}
{.passL: "-lngtcp2 -lngtcp2_crypto_ossl -lnghttp3 -lssl -lcrypto -lstdc++".}
{.compile: "vq_ngtcp2.cpp".}

# --- shim ABI ---------------------------------------------------------------
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
proc vqEngineFree(e: ptr VqEngine) {.importc: "vq_engine_free".}
proc vqEngineReloadCert(e: ptr VqEngine, certPem, keyPem: cstring): cint {.importc: "vq_engine_reload_cert".}
proc vqEngineRecv(e: ptr VqEngine, pkt: ptr uint8, len: csize_t, peer: pointer,
  peerLen: csize_t, local: pointer, localLen: csize_t, nowNs: uint64) {.importc: "vq_engine_recv".}
proc vqEnginePump(e: ptr VqEngine, nowNs: uint64) {.importc: "vq_engine_pump".}
proc vqEngineNextExpiry(e: ptr VqEngine, nowNs: uint64): uint64 {.importc: "vq_engine_next_expiry_ns".}
proc vqEngineHandleExpiry(e: ptr VqEngine, nowNs: uint64) {.importc: "vq_engine_handle_expiry".}
proc vqSubmitResponse(conn: ptr VqConn, sid: int64, status: cint, hdrs: ptr VqHeader,
  n: csize_t, body: ptr uint8, bodyLen: csize_t, fin: cint) {.importc: "vq_submit_response".}
proc vqSubmitHead(conn: ptr VqConn, sid: int64, status: cint, hdrs: ptr VqHeader, n: csize_t) {.importc: "vq_submit_head".}
proc vqStreamWrite(conn: ptr VqConn, sid: int64, data: ptr uint8, len: csize_t): csize_t {.importc: "vq_stream_write".}
proc vqStreamFinish(conn: ptr VqConn, sid: int64) {.importc: "vq_stream_finish".}
proc vqStreamBacklog(conn: ptr VqConn, sid: int64): csize_t {.importc: "vq_stream_backlog".}
proc vqStreamReset(conn: ptr VqConn, sid: int64, appErr: uint64) {.importc: "vq_stream_reset".}
proc vqStreamConsume(conn: ptr VqConn, sid: int64, n: csize_t) {.importc: "vq_stream_consume".}
proc vqConnGoaway(conn: ptr VqConn) {.importc: "vq_conn_goaway".}
proc vqConnClose(conn: ptr VqConn, appErr: uint64) {.importc: "vq_conn_close".}
{.pop.}

# --- H3 state (codec-compatible surface) ------------------------------------
type
  H3Stream* = object
    id*: uint64
    headers*: seq[(string, string)]
    body*: string
    headersDone*: bool
    responded*: bool
    isHead*: bool
    streaming*: bool
    streamingReq*: bool
    isWsConnect*: bool
    ws*: RootRef
    respComp*: RootRef
    respEnc*: string
    pathParams*: PathParams
    urlCached*: bool
    queryCached*: bool
    jsonCached*: bool
    cachedUrl*: Uri
    cachedQuery*: Table[string, string]
    cachedJson*: JsonNode
    onBodyCb*: BodyCb
    onRespDrain*: RespDrainCb
    dispatched: bool
    finSeen: bool
    bodyManualAck: bool

  H3Conn* = ref object of RootObj
    core*: ptr LoopCore
    ssl*: pointer            ## always nil: the shim owns the TLS handle; kept
                             ## for the H3Conn shape request.nim expects
    remoteAddr*: string
    slot*: int
    vq: ptr VqConn
    streams*: Table[uint64, H3Stream]
    closing: bool
    lastStreamId: uint64
    goneAway: bool

# One engine + core + UDP fd per loop thread.
var
  gEngine {.threadvar.}: ptr VqEngine
  gCore {.threadvar.}: ptr LoopCore
  gUdpFd {.threadvar.}: cint
  gLocalSa {.threadvar.}: array[128, byte]   # bound local sockaddr (for the QUIC path)
  gLocalLen {.threadvar.}: cuint
  gReady {.threadvar.}: seq[tuple[slot: int, gen: uint32, sid: uint64]]

proc nowNs(): uint64 = getMonoTime().ticks.uint64

proc h3ConnOf*(core: ptr LoopCore, fd: int32, gen: uint32): H3Conn =
  ## Resolve an h3 Request handle (fd = -(slot+2)); nil if gone.
  let idx = int(-fd) - 2
  if idx < 0 or idx >= core.h3slots.len: return nil
  if core.h3slots[idx].gen != gen or core.h3slots[idx].conn == nil: return nil
  H3Conn(core.h3slots[idx].conn)

proc h3StreamPtr*(conn: H3Conn, sid: uint64): ptr H3Stream =
  if sid in conn.streams: addr conn.streams[sid] else: nil

proc h3StreamAlive*(conn: H3Conn, sid: uint64): bool = sid in conn.streams
proc h3StreamCount*(conn: H3Conn): int = conn.streams.len

# --- header validation (RFC 9114 pseudo-header rules; pure) -----------------
type H3HeaderKind* = enum h3hInvalid, h3hRequest, h3hWebSocket

proc classifyH3Headers*(headers: openArray[(string, string)]): H3HeaderKind =
  ## Validate the pseudo-header set and classify it as a normal request, an
  ## RFC 9220 Extended CONNECT websocket, or invalid. Pure (no live connection),
  ## so it is unit-testable. nghttp3 also enforces its own checks on the wire.
  var meth, path, scheme, protocol: string
  var seenMethod, seenPath, seenScheme, seenAuthority, seenProtocol = false
  var hasHost = false
  var pseudoDone = false
  for (name, val) in headers:
    if name.len == 0: return h3hInvalid
    if name[0] == ':':
      if pseudoDone: return h3hInvalid
      case name
      of ":method":
        if seenMethod: return h3hInvalid
        seenMethod = true; meth = val
      of ":path":
        if seenPath: return h3hInvalid
        seenPath = true; path = val
      of ":scheme":
        if seenScheme: return h3hInvalid
        seenScheme = true; scheme = val
      of ":authority":
        if seenAuthority: return h3hInvalid
        seenAuthority = true
      of ":protocol":
        if seenProtocol: return h3hInvalid
        seenProtocol = true; protocol = val
      else: return h3hInvalid
    else:
      pseudoDone = true
      for ch in name:
        if ch in 'A'..'Z': return h3hInvalid
      if name == "host": hasHost = true
  if meth == "CONNECT" and protocol == "websocket":
    if path.len == 0 or scheme.len == 0 or not seenAuthority: return h3hInvalid
    return h3hWebSocket
  if seenProtocol: return h3hInvalid
  if meth.len == 0 or path.len == 0 or scheme.len == 0: return h3hInvalid
  if (scheme == "http" or scheme == "https") and not seenAuthority and
      not hasHost: return h3hInvalid
  h3hRequest

# --- shim callbacks (all loop-thread) ---------------------------------------
proc cbAccept(user: pointer, conn: ptr VqConn, peerIp: cstring): pointer {.cdecl.} =
  let core = cast[ptr LoopCore](user)
  var idx = -1
  for i in 0 ..< core.h3slots.len:
    if core.h3slots[i].conn == nil and core.h3slots[i].pinned == 0:
      idx = i; break
  if idx < 0:
    core.h3slots.add H3SlotEntry()
    idx = core.h3slots.len - 1
  let h3c = H3Conn(core: core, vq: conn, slot: idx,
                   remoteAddr: (if peerIp != nil: $peerIp else: ""))
  core.h3slots[idx].conn = h3c
  cast[pointer](h3c)

proc toStr(p: cstring, n: csize_t): string =
  result = newString(int(n))
  if n > 0: copyMem(addr result[0], p, int(n))

proc cbHeaders(user, connUd: pointer, sid: int64, hdrs: ptr VqHeader, n: csize_t) {.cdecl.} =
  let h3c = cast[H3Conn](connUd)
  let usid = uint64(sid)
  if usid notin h3c.streams:
    h3c.streams[usid] = H3Stream(id: usid)
  template st: H3Stream = h3c.streams[usid]
  let arr = cast[ptr UncheckedArray[VqHeader]](hdrs)
  for i in 0 ..< int(n):
    st.headers.add (toStr(arr[i].name, arr[i].name_len),
                    toStr(arr[i].value, arr[i].value_len))
  case classifyH3Headers(st.headers)
  of h3hInvalid:
    vqStreamReset(h3c.vq, sid, 0x0105)   # H3_MESSAGE_ERROR
    h3c.streams.del(usid)
    return
  of h3hWebSocket: st.isWsConnect = true
  of h3hRequest: discard
  for (name, val) in st.headers:
    if name == ":method": st.isHead = val == "HEAD"
  st.headersDone = true
  if usid > h3c.lastStreamId: h3c.lastStreamId = usid
  # Streaming route or ws-connect dispatch on headers; body flows via onBody.
  if not st.isWsConnect and hasStreamRoute(h3c.core) and
      callStreamRoute(h3c.core, int32(-(h3c.slot + 2)),
                      h3c.core.h3slots[h3c.slot].gen, uint32(sid)):
    st.streamingReq = true
  if (st.isWsConnect or st.streamingReq) and not st.dispatched:
    st.dispatched = true
    gReady.add (h3c.slot, h3c.core.h3slots[h3c.slot].gen, usid)

proc deliverBody(h3c: H3Conn, usid: uint64, last: bool) =
  if usid notin h3c.streams: return
  template st: H3Stream = h3c.streams[usid]
  if st.onBodyCb == nil: return
  if st.body.len > 0 or last:
    let cb = st.onBodyCb
    var buf: string
    swap(buf, st.body)
    cb(buf.toOpenArray(0, buf.len - 1), last)

proc cbBody(user, connUd: pointer, sid: int64, data: ptr uint8, len: csize_t) {.cdecl.} =
  let h3c = cast[H3Conn](connUd)
  let usid = uint64(sid)
  if usid notin h3c.streams: return
  template st: H3Stream = h3c.streams[usid]
  if st.ws != nil:
    # RFC 9220 tunnel: DATA payload is WebSocket framing.
    let arr = cast[ptr UncheckedArray[char]](data)
    wsFeed(h3c.core, nil, WsConn(st.ws), arr.toOpenArray(0, int(len) - 1))
    return
  let old = st.body.len
  st.body.setLen(old + int(len))
  if len > 0: copyMem(addr st.body[old], data, int(len))
  if st.streamingReq: deliverBody(h3c, usid, false)

proc cbStreamEnd(user, connUd: pointer, sid: int64) {.cdecl.} =
  let h3c = cast[H3Conn](connUd)
  let usid = uint64(sid)
  if usid notin h3c.streams: return
  template st: H3Stream = h3c.streams[usid]
  st.finSeen = true
  if st.ws != nil:
    wsPeerClosed(h3c.core, nil, WsConn(st.ws))
  elif st.streamingReq:
    deliverBody(h3c, usid, true)
  elif not st.dispatched and st.headersDone:
    st.dispatched = true
    gReady.add (h3c.slot, h3c.core.h3slots[h3c.slot].gen, usid)

proc cbStreamClose(user, connUd: pointer, sid: int64, appErr: uint64) {.cdecl.} =
  let h3c = cast[H3Conn](connUd)
  let usid = uint64(sid)
  if usid in h3c.streams:
    template st: H3Stream = h3c.streams[usid]
    if st.ws != nil:
      wsStreamClosed(h3c.core, nil, WsConn(st.ws))
      st.ws = nil
    if st.onBodyCb != nil:
      let cb = st.onBodyCb
      st.onBodyCb = nil
      var empty: string
      try: cb(toOpenArray(empty, 0, -1), true)
      except CatchableError: discard
    h3c.streams.del(usid)

proc cbStreamWritable(user, connUd: pointer, sid: int64) {.cdecl.} =
  let h3c = cast[H3Conn](connUd)
  let usid = uint64(sid)
  if usid in h3c.streams:
    template st: H3Stream = h3c.streams[usid]
    if st.onRespDrain != nil and vqStreamBacklog(h3c.vq, sid) == 0:
      st.onRespDrain(h3c.core, int32(-(h3c.slot + 2)),
                     h3c.core.h3slots[h3c.slot].gen, uint32(usid))

proc cbConnClose(user, connUd: pointer) {.cdecl.} =
  let h3c = cast[H3Conn](connUd)
  if h3c != nil:
    # The shim frees the VqConn immediately after this returns, so drop our
    # dangling pointer to it now: h3Free and the response procs must not touch
    # a freed VqConn (use-after-free otherwise).
    h3c.vq = nil
    if h3c.slot >= 0 and h3c.slot < h3c.core.h3slots.len:
      h3c.core.h3slots[h3c.slot].closeReq = true

proc sendtoUdp(fd: cint, data: pointer, len: csize_t, flags: cint, peer: pointer,
               peerLen: cuint): int {.importc: "sendto", header: "<sys/socket.h>".}
proc recvfromUdp(fd: cint, buf: pointer, n: csize_t, flags: cint, peer: pointer,
                 peerLen: ptr cuint): int {.importc: "recvfrom", header: "<sys/socket.h>".}
proc getsocknameC(fd: cint, a: pointer, l: ptr cuint): cint {.importc: "getsockname", header: "<sys/socket.h>".}

proc cbSend(user: pointer, conn: ptr VqConn, data: ptr uint8, len: csize_t,
            peer: pointer, peerLen: csize_t): cint {.cdecl.} =
  discard sendtoUdp(gUdpFd, data, len, cint(0), peer, cuint(peerLen))
  0

# --- transport drive (called by eventloop's ngtcp2 h3Drive branch) ----------
proc ngSetup*(core: ptr LoopCore, udpFd: cint, certFile, keyFile: string,
              maxBody, maxStreams, maxFieldSection: int): bool =
  gCore = core
  gUdpFd = udpFd
  var cfg: VqConfig
  cfg.user = core
  cfg.cb = VqCallbacks(on_accept: cbAccept, on_headers: cbHeaders, on_body: cbBody,
    on_stream_end: cbStreamEnd, on_stream_close: cbStreamClose,
    on_stream_writable: cbStreamWritable, on_conn_close: cbConnClose, on_send: cbSend)
  cfg.cert_file = certFile.cstring
  cfg.key_file = keyFile.cstring
  cfg.max_body = uint64(maxBody)
  cfg.max_concurrent_streams = uint64(maxStreams)
  cfg.max_field_section_size = cint(maxFieldSection)
  gEngine = vqEngineNew(addr cfg)
  if gEngine == nil: return false
  gLocalLen = cuint(sizeof(gLocalSa))
  discard getsocknameC(udpFd, addr gLocalSa[0], addr gLocalLen)
  true

proc ngReceive*() =
  ## Drain all pending datagrams from the loop's (nonblocking) UDP socket into
  ## the engine; the shim's callbacks populate connections and the ready list.
  var buf: array[2048, uint8]
  var peer: array[128, byte]
  while true:
    var plen = cuint(sizeof(peer))
    let n = recvfromUdp(gUdpFd, addr buf[0], csize_t(buf.len), cint(0),
                        addr peer[0], addr plen)
    if n <= 0: break
    vqEngineRecv(gEngine, addr buf[0], csize_t(n), addr peer[0], csize_t(plen),
                 addr gLocalSa[0], csize_t(gLocalLen), nowNs())

proc ngPump*() = vqEnginePump(gEngine, nowNs())
proc ngHandleExpiry*() = vqEngineHandleExpiry(gEngine, nowNs())
proc ngTimeoutMs*(): int =
  let now = nowNs()
  let e = vqEngineNextExpiry(gEngine, now)
  if e == high(uint64): -1
  elif e <= now: 0
  else: int((e - now) div 1_000_000) + 1
proc ngReloadCert*(certPem, keyPem: string): bool =
  gEngine != nil and vqEngineReloadCert(gEngine, certPem.cstring, keyPem.cstring) == 0
proc ngTakeReady*(): seq[tuple[slot: int, gen: uint32, sid: uint64]] =
  result = gReady
  gReady.setLen(0)
proc ngEngineFree*() =
  if gEngine != nil: vqEngineFree(gEngine); gEngine = nil

# --- response emission (codec-compatible) -----------------------------------
proc toVq(hdrs: seq[(string, string)]): seq[VqHeader] =
  result = newSeq[VqHeader](hdrs.len)
  for i, (n, v) in hdrs:
    result[i] = VqHeader(name: n.cstring, name_len: csize_t(n.len),
                         value: v.cstring, value_len: csize_t(v.len))

proc buildRespHeaders(core: ptr LoopCore, code: int, contentType: string,
                      extra: openArray[(string, string)], bodyLen: int,
                      isHead, bodiless: bool): seq[(string, string)] =
  result.add (":status", $code)
  if core.serverHeader.len > 0: result.add ("server", core.serverHeader)
  result.add ("date", core.dateStr)
  if contentType.len > 0 and not bodiless: result.add ("content-type", contentType)
  if not bodiless: result.add ("content-length", $bodyLen)
  for (name, val) in extra: result.add (name.toLowerAscii, val)

proc h3Respond*(core: ptr LoopCore, conn: H3Conn, sid: uint64, code: int,
                contentType: string, extraHeaders: openArray[(string, string)],
                body: openArray[char]) =
  if conn.vq == nil or sid notin conn.streams or conn.streams[sid].responded: return
  template st: H3Stream = conn.streams[sid]
  st.responded = true
  let bodiless = code in 100 .. 199 or code == 204 or code == 304
  let hdrs = buildRespHeaders(core, code, contentType, extraHeaders, body.len,
                              st.isHead, bodiless)
  var nv = toVq(hdrs)
  let sendBody = body.len > 0 and not st.isHead and not bodiless
  vqSubmitResponse(conn.vq, int64(sid), cint(code), addr nv[0], csize_t(nv.len),
    (if sendBody: cast[ptr uint8](unsafeAddr body[0]) else: nil),
    (if sendBody: csize_t(body.len) else: 0), 1)

proc h3SendHead*(core: ptr LoopCore, conn: H3Conn, sid: uint64, code: int,
                 contentType: string, extraHeaders: openArray[(string, string)]) =
  if conn.vq == nil or sid notin conn.streams or conn.streams[sid].responded: return
  template st: H3Stream = conn.streams[sid]
  st.responded = true
  st.streaming = not st.isHead
  var hdrs: seq[(string, string)]
  hdrs.add (":status", $code)
  if core.serverHeader.len > 0: hdrs.add ("server", core.serverHeader)
  hdrs.add ("date", core.dateStr)
  if contentType.len > 0: hdrs.add ("content-type", contentType)
  for (name, val) in extraHeaders: hdrs.add (name.toLowerAscii, val)
  var nv = toVq(hdrs)
  vqSubmitHead(conn.vq, int64(sid), cint(code), addr nv[0], csize_t(nv.len))
  if st.isHead: vqStreamFinish(conn.vq, int64(sid))

proc h3StreamWrite*(conn: H3Conn, sid: uint64, data: openArray[char]): int =
  if conn.vq == nil or sid notin conn.streams or not conn.streams[sid].streaming: return 0
  if data.len > 0:
    return int(vqStreamWrite(conn.vq, int64(sid),
                             cast[ptr uint8](unsafeAddr data[0]), csize_t(data.len)))
  int(vqStreamBacklog(conn.vq, int64(sid)))

proc h3StreamFinish*(conn: H3Conn, sid: uint64) =
  if conn.vq == nil or sid notin conn.streams or not conn.streams[sid].streaming: return
  conn.streams[sid].streaming = false
  conn.streams[sid].onRespDrain = nil
  vqStreamFinish(conn.vq, int64(sid))

proc h3StreamBacklog*(conn: H3Conn, sid: uint64): int =
  if conn.vq == nil or sid notin conn.streams: return 0
  int(vqStreamBacklog(conn.vq, int64(sid)))

proc h3StreamAbort*(conn: H3Conn, sid: uint64) =
  if conn.vq == nil or sid notin conn.streams or not conn.streams[sid].streaming: return
  conn.streams[sid].streaming = false
  conn.streams[sid].onRespDrain = nil
  vqStreamReset(conn.vq, int64(sid), 0x0102)   # H3_INTERNAL_ERROR

proc h3RespComp*(conn: H3Conn, sid: uint64): RootRef =
  if sid in conn.streams: conn.streams[sid].respComp else: nil
proc h3RespEnc*(conn: H3Conn, sid: uint64): string =
  if sid in conn.streams: conn.streams[sid].respEnc else: ""
proc h3SetRespComp*(conn: H3Conn, sid: uint64, comp: RootRef, enc: string) =
  if sid in conn.streams:
    conn.streams[sid].respComp = comp
    conn.streams[sid].respEnc = enc

proc h3SetOnBody*(conn: H3Conn, sid: uint64, cb: BodyCb, manualAck = false) =
  if sid notin conn.streams: return
  conn.streams[sid].onBodyCb = cb
  conn.streams[sid].bodyManualAck = manualAck
  deliverBody(conn, sid, conn.streams[sid].finSeen)

proc h3AckBody*(conn: H3Conn, sid: uint64, n: int) =
  ## Flow control is handled inside the shim/ngtcp2 on receive; nothing to do
  ## here yet (a future refinement can gate extend_max_stream_offset on acks).
  discard

proc h3Goaway*(conn: H3Conn) =
  if conn.vq == nil or conn.goneAway: return
  conn.goneAway = true
  vqConnGoaway(conn.vq)

proc h3Free*(conn: H3Conn) =
  var empty: string
  for sid, st in conn.streams.mpairs:
    if st.ws != nil:                  # onClose(1006) for any open ws stream
      wsStreamClosed(conn.core, nil, WsConn(st.ws))
      st.ws = nil
    if st.onBodyCb != nil:
      let cb = st.onBodyCb
      st.onBodyCb = nil
      try: cb(toOpenArray(empty, 0, -1), true)
      except CatchableError: discard
  conn.streams.clear()
  if conn.vq != nil:
    vqConnClose(conn.vq, 0)
    conn.vq = nil

# --- WebSocket over HTTP/3 (RFC 9220 Extended CONNECT) ----------------------
proc wsFlushH3ng(core: ptr LoopCore, c: ptr Connection, w: WsConn) {.nimcall, gcsafe.} =
  ## WsConn.flush for HTTP/3: push produced frames as DATA (nghttp3 serves them),
  ## then finalize on close or fire onDrain when the backlog empties.
  let conn = H3Conn(w.h3conn)
  let sid = uint64(w.stream)
  if conn == nil or conn.vq == nil or sid notin conn.streams:
    w.outBuf.setLen 0
    return
  if w.outBuf.len > 0:
    discard vqStreamWrite(conn.vq, int64(sid),
                          cast[ptr uint8](addr w.outBuf[0]), csize_t(w.outBuf.len))
    w.outBuf.setLen 0
  let backlog = int(vqStreamBacklog(conn.vq, int64(sid)))
  w.h2Pending = backlog
  if backlog == 0:
    if w.wantClose:
      wsStreamClosed(core, nil, w)
      if sid in conn.streams: conn.streams[sid].ws = nil
      vqStreamFinish(conn.vq, int64(sid))
    elif w.backedUp:
      w.backedUp = false
      if w.onDrain != nil:
        w.onDrain(WebSocket(core: core, fd: w.fd, gen: w.gen, stream: w.stream))
  else:
    w.backedUp = true

proc h3WsAccept*(core: ptr LoopCore, conn: H3Conn, sid: uint64, fd: int32,
                 gen: uint32, maxMessage: int, extensionsOffer, protocolsOffer: string,
                 serverProtocols: openArray[string]): bool =
  ## Accept an Extended CONNECT WebSocket: 200 headers (no FIN, stream stays
  ## open) and attach a WsConn whose frames tunnel through h3 DATA.
  if sid notin conn.streams: return false
  template st: H3Stream = conn.streams[sid]
  if not st.isWsConnect or st.responded or st.ws != nil: return false
  st.responded = true
  let (w, proto, ext) = wsSetup(core, fd, gen, maxMessage, uint32(sid),
                                extensionsOffer, protocolsOffer, serverProtocols)
  w.flush = wsFlushH3ng
  w.h3conn = conn
  st.ws = w
  var hdrs: seq[(string, string)] = @[(":status", "200")]
  if core.serverHeader.len > 0: hdrs.add ("server", core.serverHeader)
  hdrs.add ("date", core.dateStr)
  if proto.len > 0: hdrs.add ("sec-websocket-protocol", proto)
  if ext.len > 0: hdrs.add ("sec-websocket-extensions", ext)
  var nv = toVq(hdrs)
  vqSubmitHead(conn.vq, int64(sid), cint(200), addr nv[0], csize_t(nv.len))
  true

proc h3WsResume*(core: ptr LoopCore, conn: H3Conn, sid: uint64) =
  if sid in conn.streams and conn.streams[sid].ws != nil:
    wsResume(core, nil, WsConn(conn.streams[sid].ws))

proc h3WsLookup(corep: pointer, fd: int32, gen: uint32,
                stream: uint32): RootRef {.nimcall, gcsafe.} =
  let core = cast[ptr LoopCore](corep)
  let conn = h3ConnOf(core, fd, gen)
  if conn != nil and uint64(stream) in conn.streams:
    return conn.streams[uint64(stream)].ws
  nil

proc installH3WsHooks*(core: ptr LoopCore) =
  core.wsH3Lookup = h3WsLookup
