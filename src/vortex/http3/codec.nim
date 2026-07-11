## HTTP/3 connection state machine (RFC 9114) over OpenSSL QUIC streams.
## Loop-thread only; workers respond through the protocol-neutral outbox.
## One request per client-initiated bidirectional stream: HEADERS frame
## (QPACK, capacity-0) then DATA frames, FIN completes the request.

import std/[tables, strutils, uri]
import ./frames, ./qpack
import ../connection
import ../transport/quic

type
  H3Stream* = object
    ssl*: SslPtr
    id*: uint64
    rbuf: string              ## accumulated stream bytes
    frameType: uint64
    frameLen: int
    frameHdrDone: bool
    headers*: seq[(string, string)]
    body*: string
    headersDone*: bool
    urlCached*: bool                 ## lazy per-request caches
    queryCached*: bool
    cachedUrl*: Uri
    cachedQuery*: Table[string, string]
    pathParams*: PathParams          ## written by the router at match time
    finSeen: bool
    dispatched: bool
    responded*: bool
    isHead*: bool
    failed: bool
    outBuf: string
    outPos: int
    concludeAfterFlush: bool

  H3Conn* = ref object of RootObj
    ssl*: SslPtr
    slot*: int
    streams*: Table[uint64, H3Stream]
    unis: seq[SslPtr]         ## peer's unidirectional streams (drained)
    ctrl: SslPtr              ## our control stream
    ctrlBuf: string
    ctrlPos: int
    maxBody: int
    maxConcurrentStreams: int
    scratch: string

proc h3ConnOf*(core: ptr LoopCore, fd: int32, gen: uint32): H3Conn =
  ## Resolve an h3 Request handle (fd = -(slot+2)); nil if gone.
  let idx = int(-fd) - 2
  if idx < 0 or idx >= core.h3slots.len: return nil
  if core.h3slots[idx].gen != gen or core.h3slots[idx].conn == nil:
    return nil
  H3Conn(core.h3slots[idx].conn)

proc newH3Conn*(ssl: SslPtr, slot: int, maxBody,
                maxConcurrentStreams: int): H3Conn =
  result = H3Conn(ssl: ssl, slot: slot, maxBody: maxBody,
                  maxConcurrentStreams: maxConcurrentStreams)
  result.scratch = newString(4096)
  # Our control stream: stream type + SETTINGS (QPACK capacity 0).
  result.ctrl = quicNewUniStream(ssl)
  if result.ctrl != nil:
    result.ctrlBuf.addVarint h3sControl
    var payload = ""
    payload.addVarint h3SetQpackMaxTableCapacity
    payload.addVarint 0
    payload.addVarint h3SetQpackBlockedStreams
    payload.addVarint 0
    result.ctrlBuf.addFrame(h3fSettings, payload)

proc flushCtrl(conn: H3Conn) =
  while conn.ctrlPos < conn.ctrlBuf.len and conn.ctrl != nil:
    let (n, st) = tlsWrite(conn.ctrl, addr conn.ctrlBuf[conn.ctrlPos],
                           conn.ctrlBuf.len - conn.ctrlPos)
    if st == tlsOk: conn.ctrlPos += n
    else: break

proc flushStream(conn: H3Conn, sid: uint64): bool =
  ## True when the stream is finished and was removed.
  template st: H3Stream = conn.streams[sid]
  while st.outPos < st.outBuf.len:
    let (n, ioSt) = tlsWrite(st.ssl, addr st.outBuf[st.outPos],
                             st.outBuf.len - st.outPos)
    if ioSt == tlsOk:
      st.outPos += n
    elif ioSt == tlsWantWrite or ioSt == tlsWantRead:
      return false
    else:
      quicFree(st.ssl)
      conn.streams.del(sid)
      return true
  if st.concludeAfterFlush:
    quicConclude(st.ssl)
    quicFree(st.ssl)
    conn.streams.del(sid)
    return true
  false

proc h3Respond*(core: ptr LoopCore, conn: H3Conn, sid: uint64, code: int,
                contentType: string,
                extraHeaders: openArray[(string, string)],
                body: openArray[char]) =
  if sid notin conn.streams: return
  if conn.streams[sid].responded: return
  conn.streams[sid].responded = true
  let skipBody = conn.streams[sid].isHead
  # RFC 9110 8.6: 1xx, 204, and 304 responses carry no representation, so
  # they must not advertise content-length (or content-type). Distinct
  # from HEAD (skipBody), which keeps the length a GET would have sent.
  let bodiless = code in 100 .. 199 or code == 204 or code == 304
  var fs = ""
  addPrefix(fs)
  qpack.encodeStatus(fs, code)
  if core.serverHeader.len > 0:
    qpack.encodeHeader(fs, "server", core.serverHeader)
  qpack.encodeHeader(fs, "date", core.dateStr)
  if contentType.len > 0 and not bodiless:
    qpack.encodeHeader(fs, "content-type", contentType)
  if not bodiless:
    qpack.encodeHeader(fs, "content-length", $body.len)
  for (name, val) in extraHeaders:
    qpack.encodeHeader(fs, name.toLowerAscii, val)
  template st: H3Stream = conn.streams[sid]
  st.outBuf.addFrame(h3fHeaders, fs)
  if body.len > 0 and not skipBody and not bodiless:
    st.outBuf.addFrame(h3fData, body)
  st.concludeAfterFlush = true
  discard conn.flushStream(sid)

proc failStream(conn: H3Conn, sid: uint64) =
  template st: H3Stream = conn.streams[sid]
  st.failed = true
  if not st.responded and st.headersDone:
    discard    # handled by caller responding 400/413
  quicFree(st.ssl)
  conn.streams.del(sid)

proc validateHeaders(st: var H3Stream): bool =
  var meth, path, scheme: string
  var pseudoDone = false
  for (name, val) in st.headers:
    if name.len == 0: return false
    if name[0] == ':':
      if pseudoDone: return false
      case name
      of ":method": meth = val
      of ":path": path = val
      of ":scheme": scheme = val
      of ":authority": discard
      else: return false
    else:
      pseudoDone = true
      for ch in name:
        if ch in 'A'..'Z': return false
  if meth.len == 0 or path.len == 0 or scheme.len == 0: return false
  st.isHead = meth == "HEAD"
  true

proc parseStreamFrames(conn: H3Conn, sid: uint64,
                       ready: var seq[uint64]): bool =
  ## Consume complete frames from the stream buffer. False on failure
  ## (stream already cleaned up).
  template st: H3Stream = conn.streams[sid]
  var pos = 0
  while true:
    if not st.frameHdrDone:
      var p = pos
      var typ, length: uint64
      if getVarint(st.rbuf, p, st.rbuf.len, typ) != viOk: break
      if getVarint(st.rbuf, p, st.rbuf.len, length) != viOk: break
      if length > uint64(conn.maxBody):
        conn.failStream(sid)
        return false
      st.frameType = typ
      st.frameLen = int(length)
      st.frameHdrDone = true
      pos = p
    if st.rbuf.len - pos < st.frameLen: break
    case st.frameType
    of h3fHeaders:
      if not st.headersDone:
        try:
          decodeFieldSection(st.rbuf, pos, pos + st.frameLen, st.headers)
        except QpackError:
          conn.failStream(sid)
          return false
        if not validateHeaders(st):
          conn.failStream(sid)
          return false
        st.headersDone = true
      # else: trailers (discarded)
    of h3fData:
      if not st.headersDone:
        conn.failStream(sid)
        return false
      if st.body.len + st.frameLen > conn.maxBody:
        conn.failStream(sid)
        return false
      let old = st.body.len
      st.body.setLen(old + st.frameLen)
      if st.frameLen > 0:
        copyMem(addr st.body[old], addr st.rbuf[pos], st.frameLen)
    of h3fPushPromise, h3fCancelPush, h3fSettings, h3fGoaway:
      # Not valid on request streams (SETTINGS/GOAWAY are control-only).
      conn.failStream(sid)
      return false
    else:
      discard                      # unknown frames are skipped
    pos += st.frameLen
    st.frameHdrDone = false
    st.frameLen = 0
  if pos > 0:
    if pos >= st.rbuf.len: st.rbuf.setLen(0)
    else: st.rbuf = st.rbuf.substr(pos)
  if st.finSeen and st.headersDone and not st.dispatched and
      not st.frameHdrDone:
    st.dispatched = true
    ready.add sid
  true

proc pumpRequestStream(conn: H3Conn, sid: uint64, ready: var seq[uint64]) =
  template st: H3Stream = conn.streams[sid]
  if st.outBuf.len > st.outPos or st.concludeAfterFlush:
    if conn.flushStream(sid): return
  var readSome = false
  while true:
    let (n, ioSt) = tlsRead(st.ssl, addr conn.scratch[0], conn.scratch.len)
    case ioSt
    of tlsOk:
      let old = st.rbuf.len
      if old + n > conn.maxBody + 4096:
        conn.failStream(sid)
        return
      st.rbuf.setLen(old + n)
      copyMem(addr st.rbuf[old], addr conn.scratch[0], n)
      readSome = true
    of tlsClosed:
      st.finSeen = true
      break
    of tlsWantRead, tlsWantWrite:
      break
    of tlsError:
      conn.failStream(sid)
      return
  if readSome or st.finSeen:
    discard conn.parseStreamFrames(sid, ready)

proc h3Pump*(conn: H3Conn, ready: var seq[uint64]) =
  ## Accept new streams and advance all existing ones; appends request
  ## streams that became ready for dispatch.
  conn.flushCtrl()
  while true:
    let s = quicAcceptStream(conn.ssl)
    if s == nil: break
    if quicStreamIsBidi(s):
      # Concurrent-stream cap: refuse (conclude + free) rather than admit
      # unbounded request streams on one QUIC connection.
      if conn.maxConcurrentStreams > 0 and
          conn.streams.len >= conn.maxConcurrentStreams:
        quicConclude(s)
        quicFree(s)
      else:
        conn.streams[quicStreamId(s)] = H3Stream(ssl: s, id: quicStreamId(s))
    else:
      conn.unis.add s
  # Drain peer uni streams (control/QPACK); contents are ignored in
  # capacity-0 mode but must be read to release flow control.
  for u in conn.unis:
    while true:
      let (_, ioSt) = tlsRead(u, addr conn.scratch[0], conn.scratch.len)
      if ioSt != tlsOk: break
  var sids: seq[uint64]
  for sid in conn.streams.keys: sids.add sid
  for sid in sids:
    if sid in conn.streams:
      conn.pumpRequestStream(sid, ready)

proc h3Free*(conn: H3Conn) =
  for sid, st in conn.streams:
    quicFree(st.ssl)
  conn.streams.clear()
  for u in conn.unis:
    quicFree(u)
  conn.unis.setLen(0)
  if conn.ctrl != nil:
    quicFree(conn.ctrl)
    conn.ctrl = nil
  quicFree(conn.ssl)
  conn.ssl = nil

proc h3StreamAlive*(conn: H3Conn, sid: uint64): bool =
  sid in conn.streams

proc h3StreamPtr*(conn: H3Conn, sid: uint64): ptr H3Stream =
  if sid in conn.streams: addr conn.streams[sid] else: nil
