## HTTP/3 connection state machine (RFC 9114) over OpenSSL QUIC streams.
## Loop-thread only; workers respond through the protocol-neutral outbox.
## One request per client-initiated bidirectional stream: HEADERS frame
## (QPACK, capacity-0) then DATA frames, FIN completes the request.

import std/[tables, strutils, uri]
import ./frames, ./qpack
import ../connection
import ../transport/quic
import ../websocket/codec as wscodec

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
    streaming*: bool                 ## res.sendHead opened a streamed body
    respBackedUp: bool               ## flush hit QUIC backpressure; onDrain due
    onRespDrain*: RespDrainCb        ## streamed-response drain callback
    streamingReq*: bool              ## router.stream route: dispatch on headers
    onBodyCb*: BodyCb                ## inbound streaming sink (req.onBody)
    bodyManualAck: bool              ## consumer acks via req.ackBody
    bodyOutstanding: int             ## delivered-but-unacked bytes (manualAck)
    readPaused: bool                 ## backpressure: stop draining the stream
    isWsConnect*: bool               ## RFC 9220 Extended CONNECT websocket
    ws*: RootRef                     ## WsConn when this stream is a WebSocket

  H3UniStream = object
    ## A peer-initiated unidirectional stream (control / QPACK encoder /
    ## decoder). We parse enough to enforce the RFC 9114/9204 error cases.
    ssl: SslPtr
    buf: string
    typ: int64                ## -1 until the stream-type varint is read
    settingsSeen: bool        ## control stream: SETTINGS received
    frameType: uint64         ## control stream frame-parse state
    frameLen: int
    frameHdrDone: bool
    finSeen: bool

  H3Conn* = ref object of RootObj
    core*: ptr LoopCore       ## owning loop core (for WebSocket callbacks)
    ssl*: SslPtr
    slot*: int
    streams*: Table[uint64, H3Stream]
    unis: seq[H3UniStream]    ## peer's unidirectional streams
    ctrl: SslPtr              ## our control stream
    ctrlBuf: string
    ctrlPos: int
    maxBody: int
    maxConcurrentStreams: int
    scratch: string
    closing: bool
    lastStreamId: uint64      ## highest request stream id accepted (for GOAWAY)
    goneAway: bool            ## GOAWAY sent
    qpackDec: QpackDynTable   ## decoder dynamic table (peer's request headers)
    qpackDecStream: SslPtr    ## our QPACK decoder stream (acks to the peer)
    decBuf: string            ## decoder-stream output
    decPos: int

proc h3ConnOf*(core: ptr LoopCore, fd: int32, gen: uint32): H3Conn =
  ## Resolve an h3 Request handle (fd = -(slot+2)); nil if gone.
  let idx = int(-fd) - 2
  if idx < 0 or idx >= core.h3slots.len: return nil
  if core.h3slots[idx].gen != gen or core.h3slots[idx].conn == nil:
    return nil
  H3Conn(core.h3slots[idx].conn)

const qpackDecoderMaxCapacity = 4096
  ## Advertised SETTINGS_QPACK_MAX_TABLE_CAPACITY: the peer's encoder may use a
  ## dynamic table up to this size for the request headers it sends us.

proc newH3Conn*(core: ptr LoopCore, ssl: SslPtr, slot: int, maxBody,
                maxConcurrentStreams: int): H3Conn =
  result = H3Conn(core: core, ssl: ssl, slot: slot, maxBody: maxBody,
                  maxConcurrentStreams: maxConcurrentStreams)
  result.scratch = newString(4096)
  # Our control stream: stream type + SETTINGS. We advertise a QPACK dynamic
  # table so peers can compress request headers; BLOCKED_STREAMS stays 0 so the
  # encoder never references an unacknowledged entry (no stream blocking).
  result.ctrl = quicNewUniStream(ssl)
  if result.ctrl != nil:
    result.ctrlBuf.addVarint h3sControl
    var payload = ""
    payload.addVarint h3SetQpackMaxTableCapacity
    payload.addVarint uint64(qpackDecoderMaxCapacity)
    payload.addVarint h3SetQpackBlockedStreams
    payload.addVarint 0
    payload.addVarint h3SetEnableConnectProtocol   # RFC 9220 WebSockets
    payload.addVarint 1
    result.ctrlBuf.addFrame(h3fSettings, payload)
  # Our QPACK decoder stream: acknowledgments back to the peer's encoder.
  result.qpackDecStream = quicNewUniStream(ssl)
  if result.qpackDecStream != nil:
    result.decBuf.addVarint h3sQpackDecoder

proc flushCtrl(conn: H3Conn) =
  while conn.ctrlPos < conn.ctrlBuf.len and conn.ctrl != nil:
    let (n, st) = tlsWrite(conn.ctrl, addr conn.ctrlBuf[conn.ctrlPos],
                           conn.ctrlBuf.len - conn.ctrlPos)
    if st == tlsOk: conn.ctrlPos += n
    else: break

proc flushDecStream(conn: H3Conn) =
  while conn.decPos < conn.decBuf.len and conn.qpackDecStream != nil:
    let (n, st) = tlsWrite(conn.qpackDecStream, addr conn.decBuf[conn.decPos],
                           conn.decBuf.len - conn.decPos)
    if st == tlsOk: conn.decPos += n
    else: break
  if conn.decPos > 0 and conn.decPos == conn.decBuf.len:   # fully sent: compact
    conn.decBuf.setLen(0)
    conn.decPos = 0

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

# --- streaming responses (res.sendHead / write / finish over HTTP/3) --------

proc h3StreamDrained(conn: H3Conn, sid: uint64) =
  ## Fire a streamed response's onDrain once its QUIC-backpressured backlog
  ## empties. Called after every flush of a streaming stream.
  if sid notin conn.streams: return
  template st: H3Stream = conn.streams[sid]
  if not st.streaming: return
  if st.outBuf.len - st.outPos == 0:
    st.outBuf.setLen 0
    st.outPos = 0
    if st.respBackedUp:
      st.respBackedUp = false
      if st.onRespDrain != nil:
        st.onRespDrain(conn.core, 0, 0, uint32(sid))   # handle captured in cb
  else:
    st.respBackedUp = true

proc h3SendHead*(core: ptr LoopCore, conn: H3Conn, sid: uint64, code: int,
                 contentType: string,
                 extraHeaders: openArray[(string, string)]) =
  ## Send a streamed response's HEADERS (no content-length, no FIN) and open
  ## the body. Subsequent bytes flow via h3StreamWrite/h3StreamFinish.
  if sid notin conn.streams or conn.streams[sid].responded: return
  template st: H3Stream = conn.streams[sid]
  st.responded = true
  st.streaming = true
  var fs = ""
  addPrefix(fs)
  qpack.encodeStatus(fs, code)
  if core.serverHeader.len > 0:
    qpack.encodeHeader(fs, "server", core.serverHeader)
  qpack.encodeHeader(fs, "date", core.dateStr)
  if contentType.len > 0:
    qpack.encodeHeader(fs, "content-type", contentType)
  for (name, val) in extraHeaders:
    qpack.encodeHeader(fs, name.toLowerAscii, val)
  st.outBuf.addFrame(h3fHeaders, fs)
  if st.isHead:
    st.streaming = false
    st.concludeAfterFlush = true       # HEAD: headers only, FIN
  discard conn.flushStream(sid)

proc h3StreamWrite*(conn: H3Conn, sid: uint64, data: openArray[char]): int =
  ## Append a body chunk (an h3 DATA frame) to a streamed response and flush.
  ## Returns the unsent backlog for backpressure.
  if sid notin conn.streams or not conn.streams[sid].streaming: return 0
  template st: H3Stream = conn.streams[sid]
  if data.len > 0:
    st.outBuf.addFrame(h3fData, data)
  if conn.flushStream(sid): return 0    # stream finished/removed
  conn.h3StreamDrained(sid)
  if sid notin conn.streams: return 0
  st.outBuf.len - st.outPos

proc h3StreamFinish*(conn: H3Conn, sid: uint64) =
  ## Terminate a streamed response: FIN the QUIC stream once the backlog drains.
  if sid notin conn.streams or not conn.streams[sid].streaming: return
  template st: H3Stream = conn.streams[sid]
  st.streaming = false
  st.onRespDrain = nil
  st.concludeAfterFlush = true
  discard conn.flushStream(sid)

proc h3StreamBacklog*(conn: H3Conn, sid: uint64): int =
  ## Unsent bytes queued on a streamed response (for res.bufferedAmount).
  if sid notin conn.streams: return 0
  conn.streams[sid].outBuf.len - conn.streams[sid].outPos

# --- inbound streaming (req.onBody) -----------------------------------------

const h3BackpressureHigh = 256 * 1024
  ## manualAck streaming: pause draining the QUIC stream once this many
  ## delivered-but-unacked bytes are outstanding, so OpenSSL stops extending
  ## the peer's stream flow-control window until the consumer catches up.

proc h3DeliverBody(conn: H3Conn, sid: uint64, last: bool) =
  ## Hand buffered request-body bytes to a streaming stream's onBody and clear
  ## the buffer (bounded memory). No-op until the handler registers onBody. The
  ## callback may res.send (deleting this stream), so move the buffer out and
  ## touch nothing on the stream afterwards. Under manualAck, track outstanding
  ## bytes and pause reads past the high-water mark (req.ackBody resumes).
  if sid notin conn.streams: return
  template st: H3Stream = conn.streams[sid]
  if st.onBodyCb == nil: return
  if st.body.len > 0 or last:
    let cb = st.onBodyCb
    let manual = st.bodyManualAck
    var buf: string
    swap(buf, st.body)
    cb(buf.toOpenArray(0, buf.len - 1), last)
    if manual and buf.len > 0 and sid in conn.streams:
      conn.streams[sid].bodyOutstanding += buf.len
      if conn.streams[sid].bodyOutstanding > h3BackpressureHigh:
        conn.streams[sid].readPaused = true

proc h3SetOnBody*(conn: H3Conn, sid: uint64, cb: BodyCb, manualAck = false) =
  ## request.onBody for HTTP/3: store the sink and flush whatever body already
  ## arrived before the handler ran (last=true if the peer already sent FIN).
  if sid notin conn.streams: return
  conn.streams[sid].onBodyCb = cb
  conn.streams[sid].bodyManualAck = manualAck
  h3DeliverBody(conn, sid, conn.streams[sid].finSeen)

proc h3ConnError(conn: H3Conn, code: uint64) =
  ## Raise an HTTP/3 connection error (RFC 9114 8): close the QUIC connection
  ## with `code` as the application error code (a CONNECTION_CLOSE). The loop
  ## frees the slot on its next pass.
  if conn.closing: return
  conn.closing = true
  quicCloseConn(conn.ssl, code)

proc failStream(conn: H3Conn, sid: uint64) =
  template st: H3Stream = conn.streams[sid]
  st.failed = true
  if not st.responded and st.headersDone:
    discard    # handled by caller responding 400/413
  if st.ws != nil:                    # a WebSocket was aborted: onClose (1006)
    wsStreamClosed(conn.core, nil, WsConn(st.ws))
    st.ws = nil
  quicFree(st.ssl)
  conn.streams.del(sid)

proc h3StreamError(conn: H3Conn, sid: uint64, code: uint64) =
  ## Raise an HTTP/3 stream error (RFC 9114, e.g. a malformed request ->
  ## H3_MESSAGE_ERROR): RESET_STREAM with the error code and drop the stream,
  ## leaving the rest of the connection intact.
  if sid notin conn.streams: return
  quicResetStream(conn.streams[sid].ssl, code)
  conn.failStream(sid)

proc h3StreamAbort*(conn: H3Conn, sid: uint64) =
  ## Abort a streamed response mid-body: RESET_STREAM(H3_INTERNAL_ERROR) so the
  ## peer sees the transfer was cut short, not cleanly finished. No-op unless
  ## the stream is an open streamed response.
  if sid notin conn.streams or not conn.streams[sid].streaming: return
  conn.streams[sid].streaming = false
  conn.streams[sid].onRespDrain = nil
  conn.h3StreamError(sid, h3InternalError)

# --- RFC 9220 WebSockets over HTTP/3 ----------------------------------------

proc h3WsFinalize(conn: H3Conn, sid: uint64, w: WsConn) =
  ## The WebSocket close frame has flushed: deliver onClose, FIN the stream,
  ## and drop it.
  wsStreamClosed(conn.core, nil, w)
  if sid in conn.streams:
    conn.streams[sid].ws = nil
    conn.streams[sid].concludeAfterFlush = true
    discard conn.flushStream(sid)      # FIN + free + del once drained

proc wsFlushH3(core: ptr LoopCore, c: ptr Connection,
               w: WsConn) {.nimcall, gcsafe.} =
  ## `WsConn.flush` for HTTP/3: append produced frames as an h3 DATA frame and
  ## push them (QUIC handles flow control), finalizing on close.
  let conn = H3Conn(w.h3conn)
  let sid = uint64(w.stream)
  if conn == nil or sid notin conn.streams:
    w.outBuf.setLen 0
    return
  template st: H3Stream = conn.streams[sid]
  if w.outBuf.len > 0:
    st.outBuf.addFrame(h3fData, w.outBuf)
    w.outBuf.setLen 0
  discard conn.flushStream(sid)
  if sid notin conn.streams: return
  w.h2Pending = st.outBuf.len - st.outPos
  if w.h2Pending == 0:
    st.outBuf.setLen 0
    st.outPos = 0
    if w.wantClose:
      h3WsFinalize(conn, sid, w)
    elif w.backedUp:
      w.backedUp = false
      if w.onDrain != nil:
        w.onDrain(WebSocket(core: core, fd: w.fd, gen: w.gen, stream: w.stream))
  else:
    w.backedUp = true

proc h3WsAccept*(core: ptr LoopCore, conn: H3Conn, sid: uint64,
                 fd: int32, gen: uint32, maxMessage: int,
                 extensionsOffer, protocolsOffer: string,
                 serverProtocols: openArray[string]): bool =
  ## Accept an RFC 9220 Extended CONNECT WebSocket on stream `sid`: reply 200
  ## HEADERS (no FIN, so the stream stays open) and attach a WsConn.
  if sid notin conn.streams: return false
  template st: H3Stream = conn.streams[sid]
  if not st.isWsConnect or st.responded or st.ws != nil: return false
  st.responded = true
  let (w, proto, ext) = wsSetup(core, fd, gen, maxMessage, uint32(sid),
                                extensionsOffer, protocolsOffer,
                                serverProtocols)
  w.flush = wsFlushH3
  w.h3conn = conn
  st.ws = w
  var fs = ""
  addPrefix(fs)
  qpack.encodeStatus(fs, 200)
  if core.serverHeader.len > 0:
    qpack.encodeHeader(fs, "server", core.serverHeader)
  qpack.encodeHeader(fs, "date", core.dateStr)
  if proto.len > 0: qpack.encodeHeader(fs, "sec-websocket-protocol", proto)
  if ext.len > 0: qpack.encodeHeader(fs, "sec-websocket-extensions", ext)
  st.outBuf.addFrame(h3fHeaders, fs)     # no concludeAfterFlush: stays open
  discard conn.flushStream(sid)
  true

proc h3WsLookup(corep: pointer, fd: int32, gen: uint32,
                stream: uint32): RootRef {.nimcall, gcsafe.} =
  ## LoopCore.wsH3Lookup: resolve a stream's WsConn for the public API.
  let core = cast[ptr LoopCore](corep)
  let conn = h3ConnOf(core, fd, gen)
  if conn != nil and uint64(stream) in conn.streams:
    return conn.streams[uint64(stream)].ws
  nil

proc installH3WsHooks*(core: ptr LoopCore) =
  ## Register the WebSocket-over-HTTP/3 lookup so the WebSocket layer can
  ## reach per-stream state without importing the h3 codec.
  core.wsH3Lookup = h3WsLookup

proc h3WsResume*(core: ptr LoopCore, conn: H3Conn, sid: uint64) =
  ## An h3 ws.blocking worker finished: clear the per-stream pin and pump the
  ## frames buffered while it ran.
  if sid in conn.streams and conn.streams[sid].ws != nil:
    wsResume(core, nil, WsConn(conn.streams[sid].ws))

proc h3WsTeardownAll*(conn: H3Conn) =
  ## Deliver onClose (1006) for every WebSocket stream when the connection
  ## is torn down.
  for sid, st in conn.streams.mpairs:
    if st.ws != nil:
      wsStreamClosed(conn.core, nil, WsConn(st.ws))
      st.ws = nil

type H3HeaderKind* = enum h3hInvalid, h3hRequest, h3hWebSocket

proc classifyH3Headers*(headers: openArray[(string, string)]): H3HeaderKind =
  ## Validate the pseudo-header set and classify it: a normal request, an
  ## RFC 9220 Extended CONNECT websocket, or invalid. Pure (no stream state)
  ## so it is unit-testable without a live QUIC connection.
  var meth, path, scheme, protocol: string
  var seenMethod, seenPath, seenScheme, seenAuthority, seenProtocol = false
  var hasHost = false
  var pseudoDone = false
  for (name, val) in headers:
    if name.len == 0: return h3hInvalid
    if name[0] == ':':
      if pseudoDone: return h3hInvalid          # pseudo after a regular field
      case name
      of ":method":
        if seenMethod: return h3hInvalid        # duplicated pseudo-header
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
      of ":protocol":                           # RFC 9220 Extended CONNECT
        if seenProtocol: return h3hInvalid
        seenProtocol = true; protocol = val
      else: return h3hInvalid                    # unknown / prohibited pseudo
    else:
      pseudoDone = true
      for ch in name:
        if ch in 'A'..'Z': return h3hInvalid
      if name == "host": hasHost = true
  if meth == "CONNECT" and protocol == "websocket":
    if path.len == 0 or scheme.len == 0 or not seenAuthority: return h3hInvalid
    return h3hWebSocket
  if seenProtocol: return h3hInvalid         # :protocol only for a ws-connect
  if meth.len == 0 or path.len == 0 or scheme.len == 0: return h3hInvalid
  # A scheme with a mandatory authority component (http/https) requires an
  # :authority pseudo-header or a Host field (RFC 9114 4.3.1).
  if (scheme == "http" or scheme == "https") and not seenAuthority and
      not hasHost: return h3hInvalid
  h3hRequest

proc validateHeaders(st: var H3Stream): bool =
  let kind = classifyH3Headers(st.headers)
  if kind == h3hInvalid: return false
  st.isWsConnect = kind == h3hWebSocket
  for (name, val) in st.headers:
    if name == ":method": st.isHead = val == "HEAD"
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
        var ric = 0
        try:
          ric = decodeFieldSection(st.rbuf, pos, pos + st.frameLen,
                                   st.headers, conn.qpackDec)
        except QpackError:
          # A field-section decode failure corrupts the shared QPACK state:
          # a connection error (RFC 9204 2.2).
          h3ConnError(conn, qpackDecompressionFailed)
          return false
        if ric > 0:                    # used the dynamic table: acknowledge it
          conn.decBuf.encodeSectionAck(int(sid))
          conn.flushDecStream()
        if not validateHeaders(st):
          # Malformed request: a stream error (RFC 9114 4.1.2).
          h3StreamError(conn, sid, h3MessageError)
          return false
        st.headersDone = true
        if not st.isWsConnect and conn.core.streamRoute != nil and
            conn.core.streamRoute(conn.core, int32(-(conn.slot + 2)),
                                  conn.core.h3slots[conn.slot].gen,
                                  uint32(sid)):
          st.streamingReq = true      # dispatch on headers; DATA -> onBody
      # else: trailers (discarded)
    of h3fData:
      if not st.headersDone:
        # DATA before HEADERS: invalid frame sequence (RFC 9114 4.1).
        h3ConnError(conn, h3FrameUnexpected)
        return false
      if st.ws != nil:
        # RFC 9220 WebSocket stream: DATA payload is WebSocket framing.
        wsFeed(conn.core, nil, WsConn(st.ws),
               st.rbuf.toOpenArray(pos, pos + st.frameLen - 1))
      elif st.isWsConnect:
        break                        # not accepted yet: dispatch first, wait
      else:
        if st.body.len + st.frameLen > conn.maxBody:
          conn.failStream(sid)
          return false
        let old = st.body.len
        st.body.setLen(old + st.frameLen)
        if st.frameLen > 0:
          copyMem(addr st.body[old], addr st.rbuf[pos], st.frameLen)
        if st.streamingReq:
          conn.h3DeliverBody(sid, false)   # to onBody (last comes on FIN)
          if sid notin conn.streams: return false
    of h3fPushPromise, h3fCancelPush, h3fSettings, h3fGoaway:
      # These frames never appear on a request stream (SETTINGS/GOAWAY/
      # CANCEL_PUSH are control-stream only): H3_FRAME_UNEXPECTED (RFC 9114
      # 7.2.x, a connection error).
      h3ConnError(conn, h3FrameUnexpected)
      return false
    else:
      discard                      # unknown frames are skipped
    pos += st.frameLen
    st.frameHdrDone = false
    st.frameLen = 0
  if pos > 0:
    if pos >= st.rbuf.len: st.rbuf.setLen(0)
    else: st.rbuf = st.rbuf.substr(pos)
  if st.ws != nil:
    if st.finSeen:                   # peer closed the WebSocket stream
      wsPeerClosed(conn.core, nil, WsConn(st.ws))
    return true                      # WS streams never take the request path
  if not st.dispatched and st.headersDone:
    # A ws-connect or a streaming route dispatches on headers (the stream stays
    # open, body flows via onBody); an ordinary request waits for the full body.
    if st.isWsConnect or st.streamingReq:
      st.dispatched = true
      ready.add sid
    elif st.finSeen and not st.frameHdrDone:
      st.dispatched = true
      ready.add sid
  if st.streamingReq and st.finSeen:
    conn.h3DeliverBody(sid, true)    # final chunk; may delete the stream
  true

proc pumpRequestStream(conn: H3Conn, sid: uint64, ready: var seq[uint64]) =
  template st: H3Stream = conn.streams[sid]
  if st.outBuf.len > st.outPos or st.concludeAfterFlush:
    if conn.flushStream(sid): return
    conn.h3StreamDrained(sid)          # resume a QUIC-backpressured stream
    if sid notin conn.streams: return
  if st.readPaused:
    return                             # backpressure: stop draining (ackBody resumes)
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

proc h3AckBody*(conn: H3Conn, sid: uint64, n: int) =
  ## req.ackBody for HTTP/3: reduce the outstanding count and, if that lifts the
  ## backpressure pause, resume draining the QUIC stream (OpenSSL then extends
  ## the peer's flow-control window as we read).
  if sid notin conn.streams: return
  template st: H3Stream = conn.streams[sid]
  st.bodyOutstanding -= n
  if st.readPaused and st.bodyOutstanding <= h3BackpressureHigh:
    st.readPaused = false
    var ready: seq[uint64]
    conn.pumpRequestStream(sid, ready)

proc parseControlStream(conn: H3Conn, u: var H3UniStream) =
  ## Enforce RFC 9114 6.2.1 / 7.2 on the peer's control stream: the first
  ## frame must be SETTINGS, no second SETTINGS, no DATA/HEADERS, and no
  ## HTTP/2-only settings identifiers.
  var pos = 0
  while true:
    if not u.frameHdrDone:
      var p = pos
      var typ, length: uint64
      if getVarint(u.buf, p, u.buf.len, typ) != viOk: break
      if getVarint(u.buf, p, u.buf.len, length) != viOk: break
      u.frameType = typ; u.frameLen = int(length); u.frameHdrDone = true
      pos = p
    if not u.settingsSeen and u.frameType != h3fSettings:
      h3ConnError(conn, h3MissingSettings); return
    if u.buf.len - pos < u.frameLen: break
    case u.frameType
    of h3fSettings:
      if u.settingsSeen:
        h3ConnError(conn, h3FrameUnexpected); return   # second SETTINGS
      u.settingsSeen = true
      var sp = pos
      let endp = pos + u.frameLen
      while sp < endp:
        var id, v: uint64
        if getVarint(u.buf, sp, endp, id) != viOk: break
        if getVarint(u.buf, sp, endp, v) != viOk: break
        if id in [0x02'u64, 0x03, 0x04, 0x05]:   # HTTP/2 settings (RFC 9114 7.2.4.1)
          h3ConnError(conn, h3SettingsError); return
    of h3fData, h3fHeaders:
      h3ConnError(conn, h3FrameUnexpected); return   # not allowed on control
    else: discard                                    # unknown frames ignored
    pos += u.frameLen
    u.frameHdrDone = false
    u.frameLen = 0
  if pos > 0: u.buf = u.buf.substr(pos)

proc parseQpackEncoder(conn: H3Conn, u: var H3UniStream) =
  ## Apply the peer's encoder-stream instructions (inserts into our decoder
  ## dynamic table), then acknowledge new insertions with Insert Count
  ## Increment on our decoder stream (RFC 9204 4.3 / 4.4.3).
  let before = conn.qpackDec.insertCount
  var consumed = 0
  try:
    consumed = decodeEncoderInstructions(conn.qpackDec, u.buf,
                                         qpackDecoderMaxCapacity)
  except QpackError:
    h3ConnError(conn, qpackEncoderStreamError); return
  if consumed > 0:
    u.buf = u.buf.substr(consumed)            # keep any partial instruction
  let inserted = conn.qpackDec.insertCount - before
  if inserted > 0:
    conn.decBuf.encodeInsertCountIncrement(inserted)
    conn.flushDecStream()

proc parseQpackDecoder(conn: H3Conn, u: var H3UniStream) =
  ## An Insert Count Increment of 0 is illegal (RFC 9204 4.4.3): byte 0x00
  ## (00xxxxxx prefix, value 0).
  if u.buf.len > 0 and uint8(u.buf[0]) == 0x00:
    h3ConnError(conn, qpackDecoderStreamError); return
  u.buf.setLen 0

proc parseUniStream(conn: H3Conn, u: var H3UniStream) =
  while true:
    let (n, ioSt) = tlsRead(u.ssl, addr conn.scratch[0], conn.scratch.len)
    case ioSt
    of tlsOk:
      let old = u.buf.len
      u.buf.setLen(old + n)
      copyMem(addr u.buf[old], addr conn.scratch[0], n)
    of tlsClosed:
      u.finSeen = true; break
    else: break
  if u.typ < 0:                                # read the stream-type varint
    var p = 0
    var t: uint64
    if getVarint(u.buf, p, u.buf.len, t) != viOk: return
    u.typ = int64(t)
    u.buf = u.buf.substr(p)
  # A control or QPACK stream is critical: closing it is a connection error
  # (RFC 9114 6.2.1).
  if u.finSeen and u.typ in [int64(h3sControl), int64(h3sQpackEncoder),
                             int64(h3sQpackDecoder)]:
    h3ConnError(conn, h3ClosedCriticalStream); return
  case u.typ
  of int64(h3sControl):      conn.parseControlStream(u)
  of int64(h3sQpackEncoder): conn.parseQpackEncoder(u)
  of int64(h3sQpackDecoder): conn.parseQpackDecoder(u)
  else: u.buf.setLen 0                          # push/unknown: drain

proc h3Pump*(conn: H3Conn, ready: var seq[uint64]) =
  ## Accept new streams and advance all existing ones; appends request
  ## streams that became ready for dispatch.
  if conn.closing: return
  conn.flushCtrl()
  conn.flushDecStream()
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
        let sid = quicStreamId(s)
        if sid > conn.lastStreamId: conn.lastStreamId = sid
        conn.streams[sid] = H3Stream(ssl: s, id: sid)
    else:
      conn.unis.add H3UniStream(ssl: s, typ: -1)
  # Parse peer uni streams (control / QPACK), enforcing their error cases.
  for i in 0 ..< conn.unis.len:
    conn.parseUniStream(conn.unis[i])
    if conn.closing: return
  var sids: seq[uint64]
  for sid in conn.streams.keys: sids.add sid
  for sid in sids:
    if sid in conn.streams:
      conn.pumpRequestStream(sid, ready)

proc h3StreamCount*(conn: H3Conn): int =
  ## Open request streams (for graceful-shutdown draining).
  conn.streams.len

proc h3Goaway*(conn: H3Conn) =
  ## Graceful shutdown: send GOAWAY on the control stream (RFC 9114 5.2). The
  ## client stops opening request streams at or above this id; in-flight streams
  ## (all <= lastStreamId) still finish.
  if conn.goneAway or conn.ctrl == nil: return
  conn.goneAway = true
  var payload = ""
  payload.addVarint conn.lastStreamId + 4    # next client bidi stream is refused
  conn.ctrlBuf.addFrame(h3fGoaway, payload)
  conn.flushCtrl()

proc h3Free*(conn: H3Conn) =
  h3WsTeardownAll(conn)             # onClose for any RFC 9220 WebSocket streams
  for sid, st in conn.streams:
    quicFree(st.ssl)
  conn.streams.clear()
  for u in conn.unis:
    quicFree(u.ssl)
  conn.unis.setLen(0)
  if conn.ctrl != nil:
    quicFree(conn.ctrl)
    conn.ctrl = nil
  if conn.qpackDecStream != nil:
    quicFree(conn.qpackDecStream)
    conn.qpackDecStream = nil
  quicFree(conn.ssl)
  conn.ssl = nil

proc h3StreamAlive*(conn: H3Conn, sid: uint64): bool =
  sid in conn.streams

proc h3StreamPtr*(conn: H3Conn, sid: uint64): ptr H3Stream =
  if sid in conn.streams: addr conn.streams[sid] else: nil
