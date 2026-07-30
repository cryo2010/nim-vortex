## HTTP/2 connection state machine (RFC 9113): frame handling, stream
## lifecycle, both directions of flow control, and response serialization.
## One H2Conn per connection, touched only by the owning loop thread
## (workers respond through the protocol-neutral outbox).

import std/[tables, strutils, uri]
import ./frames, ./hpack
import ../connection
import ../websocket/codec as wscodec

type
  H2Stream* = object
    headers*: seq[(string, string)]  ## request fields incl. pseudo-headers
    body*: string
    sendWindow*: int32
    endStreamSeen*: bool             ## client half-closed
    dispatched*: bool
    responded*: bool
    isHead*: bool
    headersDone*: bool
    contentLength*: int64            ## -1 unknown; validated vs body
    urlCached*: bool                 ## lazy per-request caches
    queryCached*: bool
    cachedUrl*: Uri
    cachedQuery*: Table[string, string]
    pathParams*: PathParams          ## written by the router at match time
    pendingBody*: string             ## response bytes awaiting send window
    pendingPos*: int
    pendingIsLast*: bool
    streaming*: bool                 ## res.sendHead opened a streamed body
    respBackedUp*: bool              ## write() hit the window; onDrain pending
    onRespDrain*: RespDrainCb        ## streamed-response drain callback
    streamingReq*: bool              ## router.stream route: dispatch on headers
    onBodyCb*: BodyCb                ## inbound streaming sink (req.onBody)
    bodyManualAck*: bool             ## defer stream WINDOW_UPDATE to req.ackBody
    isWsConnect*: bool               ## RFC 8441 Extended CONNECT websocket
    ws*: RootRef                     ## WsConn when this stream is a WebSocket

  H2Conn* = ref object of RootObj
    core*: ptr LoopCore              ## owning loop core (for WS callbacks)
    streams*: Table[uint32, H2Stream]
    decoder*: HpackDecoder
    parsePos*: int                   ## consumed offset in conn.rbuf
    connSendWindow*: int32
    peerMaxFrame*: int
    peerInitialWindow*: int32
    prefaceDone*: bool
    contStream*: uint32              ## awaiting CONTINUATION for this stream
    contEndStream*: bool
    headerBlock*: string
    lastStreamId*: uint32
    goingAway*: bool          ## our own drain: refuse new streams
    peerGoneAway*: bool       ## peer sent GOAWAY (informational; no push)
    maxBody*: int
    maxHeaderList*: int
    activeStreams*: int
    # DoS budgets (0 disables). rstStreamCount / controlFrameCount are
    # per-connection cumulative; controlFrameCount resets on stream progress.
    maxConcurrentStreams*: int
    maxResetStreams*: int
    maxControlFrames*: int
    rstStreamCount*: int
    controlFrameCount*: int

const
  ourMaxFrameSize = defaultMaxFrameSize

proc h2Conn*(c: ptr Connection): H2Conn {.inline.} =
  H2Conn(c.h2)

proc newH2Conn*(core: ptr LoopCore, maxBody, maxHeaderList,
                maxConcurrentStreams, maxResetStreams,
                maxControlFrames: int): H2Conn =
  H2Conn(
    core: core,
    decoder: initHpackDecoder(4096, maxDecoded = maxHeaderList),
    connSendWindow: defaultInitialWindow,
    peerMaxFrame: defaultMaxFrameSize,
    peerInitialWindow: defaultInitialWindow,
    maxBody: maxBody,
    maxHeaderList: maxHeaderList,
    maxConcurrentStreams: maxConcurrentStreams,
    maxResetStreams: maxResetStreams,
    maxControlFrames: maxControlFrames)

proc sendOurSettings(c: ptr Connection) =
  var payload = ""
  payload.addSetting(setHeaderTableSize, 4096)
  payload.addSetting(setEnablePush, 0)
  payload.addSetting(setMaxConcurrentStreams,
                     uint32(h2Conn(c).maxConcurrentStreams))
  payload.addSetting(setMaxFrameSize, uint32(ourMaxFrameSize))
  payload.addSetting(setEnableConnectProtocol, 1)   # RFC 8441 WebSockets
  c.wbuf.addFrameHeader(payload.len, ftSettings, 0, 0)
  c.wbuf.add payload

proc connError(h2: H2Conn, c: ptr Connection, err: uint32) =
  c.wbuf.addGoaway(h2.lastStreamId, err)
  c.closeAfterFlush = true
  c.state = csClosing

proc h2Goaway*(c: ptr Connection) =
  ## Graceful shutdown: refuse new streams (RFC 9113 6.8) and send
  ## GOAWAY(NO_ERROR) up to the last accepted stream. Existing streams finish.
  let h2 = h2Conn(c)
  if h2 == nil or h2.goingAway: return
  h2.goingAway = true
  c.wbuf.addGoaway(h2.lastStreamId, 0'u32)

proc streamError(h2: H2Conn, c: ptr Connection, sid: uint32, err: uint32) =
  c.wbuf.addRstStream(sid, err)
  if sid in h2.streams:
    if h2.streams[sid].ws != nil:               # WebSocket aborted: onClose
      wsStreamClosed(h2.core, c, WsConn(h2.streams[sid].ws))
      h2.streams[sid].ws = nil
    if h2.streams[sid].onBodyCb != nil:         # streaming request aborted: EOF
      let cb = h2.streams[sid].onBodyCb
      h2.streams[sid].onBodyCb = nil
      var empty: string
      try: cb(toOpenArray(empty, 0, -1), true)
      except CatchableError: discard
    h2.streams.del(sid)
    dec h2.activeStreams

proc noteControlFrame(h2: H2Conn, c: ptr Connection) =
  ## Budget PING/SETTINGS/PRIORITY floods (each queues an ACK or is pure
  ## overhead). The counter resets when a real request arrives, so only
  ## floods with no intervening stream progress trip it.
  inc h2.controlFrameCount
  if h2.maxControlFrames > 0 and h2.controlFrameCount > h2.maxControlFrames:
    h2.connError(c, errEnhanceYourCalm)

# --- response serialization ------------------------------------------------

proc sendData(h2: H2Conn, c: ptr Connection, sid: uint32) =
  ## Push as much of the stream's pending response body as flow control
  ## allows; delete the stream once fully sent.
  if sid notin h2.streams: return
  template st: H2Stream = h2.streams[sid]
  while true:
    let remaining = st.pendingBody.len - st.pendingPos
    if remaining == 0:
      if st.pendingIsLast:
        h2.streams.del(sid)
        dec h2.activeStreams
      return
    var chunk = min(remaining, h2.peerMaxFrame)
    chunk = min(chunk, int(st.sendWindow))
    chunk = min(chunk, int(h2.connSendWindow))
    if chunk <= 0:
      return                        # blocked on window; resume on UPDATE
    let last = st.pendingIsLast and (st.pendingPos + chunk == st.pendingBody.len)
    c.wbuf.addFrameHeader(chunk, ftData,
                          (if last: flagEndStream else: 0'u8), sid)
    let oldLen = c.wbuf.len
    c.wbuf.setLen(oldLen + chunk)
    copyMem(addr c.wbuf[oldLen], addr st.pendingBody[st.pendingPos], chunk)
    st.pendingPos += chunk
    st.sendWindow -= int32(chunk)
    h2.connSendWindow -= int32(chunk)

# --- RFC 8441 WebSockets over HTTP/2 ----------------------------------------

proc h2WsFinalize(h2: H2Conn, c: ptr Connection, sid: uint32, w: WsConn) =
  ## The WebSocket close frame has fully flushed: send END_STREAM, deliver
  ## onClose, and drop the stream.
  c.wbuf.addFrameHeader(0, ftData, flagEndStream, sid)
  wsStreamClosed(h2.core, c, w)
  if sid in h2.streams:
    h2.streams[sid].ws = nil
    h2.streams.del(sid)
    dec h2.activeStreams

proc h2WsPush(h2: H2Conn, c: ptr Connection, sid: uint32) =
  ## Flush a WebSocket stream's queued outbound frames as DATA (bounded by
  ## flow control), finalize on close, and track backpressure for onDrain /
  ## bufferedAmount. `pendingIsLast` stays false so sendData never emits
  ## END_STREAM or deletes the stream on its own.
  if sid notin h2.streams or h2.streams[sid].ws == nil: return
  let w = WsConn(h2.streams[sid].ws)
  h2.sendData(c, sid)
  template st: H2Stream = h2.streams[sid]
  let backlog = st.pendingBody.len - st.pendingPos
  w.h2Pending = backlog
  if backlog == 0:
    st.pendingBody.setLen 0
    st.pendingPos = 0
    if w.wantClose:
      h2WsFinalize(h2, c, sid, w)
    elif w.backedUp:
      w.backedUp = false
      if w.onDrain != nil:
        w.onDrain(WebSocket(core: h2.core, fd: c.fd, gen: c.gen, stream: sid))
  else:
    w.backedUp = true
    if w.wantClose and (st.sendWindow <= 0 or h2.connSendWindow <= 0):
      # Closing, but the send window is exhausted so the close frame + END_STREAM
      # can never drain gracefully. Rather than leave a zombie stream holding a
      # slot (and, being active, stripping the connection's read deadline),
      # RST_STREAM and tear it down.
      c.wbuf.addRstStream(sid, errCancel)
      wsStreamClosed(h2.core, c, w)
      st.ws = nil
      h2.streams.del(sid)
      dec h2.activeStreams

proc wsFlushH2(core: ptr LoopCore, c: ptr Connection,
               w: WsConn) {.nimcall, gcsafe.} =
  ## `WsConn.flush` for HTTP/2: append produced frames to the stream's
  ## pending outbound and push them as DATA.
  let h2 = h2Conn(c)
  let sid = w.stream
  if h2 == nil or sid notin h2.streams:
    w.outBuf.setLen 0
    return
  template st: H2Stream = h2.streams[sid]
  if w.outBuf.len > 0:
    if st.pendingPos > 0 and st.pendingPos == st.pendingBody.len:
      st.pendingBody.setLen 0            # compact a fully-drained buffer
      st.pendingPos = 0
    st.pendingBody.add w.outBuf
    w.outBuf.setLen 0
    st.pendingIsLast = false
  h2WsPush(h2, c, sid)

proc h2RespPush(h2: H2Conn, c: ptr Connection, sid: uint32) =
  ## Flush a streamed response's pending body bounded by flow control and,
  ## when the backlog empties after backpressure, fire onDrain. Mirrors
  ## h2WsPush; `pendingIsLast` is set by h2StreamFinish so the last DATA
  ## carries END_STREAM and sendData deletes the stream on completion.
  if sid notin h2.streams: return
  h2.sendData(c, sid)
  if sid notin h2.streams: return           # finished and fully drained
  template st: H2Stream = h2.streams[sid]
  let backlog = st.pendingBody.len - st.pendingPos
  if backlog == 0:
    st.pendingBody.setLen 0
    st.pendingPos = 0
    if st.respBackedUp:
      st.respBackedUp = false
      if st.onRespDrain != nil:
        st.onRespDrain(h2.core, c.fd, c.gen, sid)
  else:
    st.respBackedUp = true

proc h2ResumeSend(h2: H2Conn, c: ptr Connection, sid: uint32) =
  ## Resume a stream blocked on the send window: WebSocket streams need the
  ## WS finalize/backpressure bookkeeping, streamed responses need the
  ## response drain bookkeeping, ordinary responses just sendData.
  if sid notin h2.streams:
    return
  elif h2.streams[sid].ws != nil:
    h2WsPush(h2, c, sid)
  elif h2.streams[sid].streaming:
    h2RespPush(h2, c, sid)
  else:
    h2.sendData(c, sid)

# --- streaming responses (res.sendHead / write / finish over HTTP/2) --------

proc h2SendHead*(c: ptr Connection, code: int, sid: uint32,
                 dateStr, serverHeader, contentType: string,
                 extraHeaders: openArray[(string, string)], altSvc = "") =
  ## Send a streamed response's HEADERS (no content-length, no END_STREAM) and
  ## open the body. Subsequent bytes flow via h2StreamWrite/h2StreamFinish.
  let h2 = h2Conn(c)
  if sid notin h2.streams or h2.streams[sid].responded: return
  template st: H2Stream = h2.streams[sid]
  st.responded = true
  st.streaming = true
  if st.isHead:
    st.pendingIsLast = true            # HEAD: headers only, close the stream
  var hb = ""
  encodeStatus(hb, code)
  if serverHeader.len > 0:
    encodeHeader(hb, "server", serverHeader)
  encodeHeader(hb, "date", dateStr)
  if contentType.len > 0:
    encodeHeader(hb, "content-type", contentType)
  if altSvc.len > 0:
    encodeHeader(hb, "alt-svc", altSvc)
  for (name, val) in extraHeaders:
    encodeHeader(hb, name.toLowerAscii, val)
  var off = 0
  var first = true
  while first or off < hb.len:
    let chunk = min(hb.len - off, h2.peerMaxFrame)
    let lastFrag = off + chunk >= hb.len
    var flags = if lastFrag: flagEndHeaders else: 0'u8
    if first and st.isHead: flags = flags or flagEndStream
    c.wbuf.addFrameHeader(chunk,
      (if first: ftHeaders else: ftContinuation), flags, sid)
    c.wbuf.add hb[off ..< off + chunk]
    off += chunk
    first = false
  if st.isHead:
    h2.streams.del(sid)
    dec h2.activeStreams

proc h2StreamWrite*(c: ptr Connection, sid: uint32,
                    data: openArray[char]): int =
  ## Append a body chunk to a streamed response and push it bounded by flow
  ## control. Returns the unsent backlog (pending body bytes) for backpressure.
  let h2 = h2Conn(c)
  if h2 == nil or sid notin h2.streams or not h2.streams[sid].streaming:
    return 0
  template st: H2Stream = h2.streams[sid]
  if st.isHead: return 0
  if data.len > 0:
    if st.pendingPos > 0 and st.pendingPos == st.pendingBody.len:
      st.pendingBody.setLen 0            # compact a fully-drained buffer
      st.pendingPos = 0
    let oldLen = st.pendingBody.len
    st.pendingBody.setLen(oldLen + data.len)
    copyMem(addr st.pendingBody[oldLen], unsafeAddr data[0], data.len)
  h2RespPush(h2, c, sid)
  if sid notin h2.streams: return 0
  h2.streams[sid].pendingBody.len - h2.streams[sid].pendingPos

proc h2StreamFinish*(c: ptr Connection, sid: uint32) =
  ## Terminate a streamed response: mark the pending body final so the last
  ## DATA frame carries END_STREAM, then push.
  let h2 = h2Conn(c)
  if h2 == nil or sid notin h2.streams or not h2.streams[sid].streaming:
    return
  template st: H2Stream = h2.streams[sid]
  st.streaming = false
  st.onRespDrain = nil
  if st.isHead:
    return                               # HEAD stream already closed at head
  st.pendingIsLast = true
  if st.pendingBody.len - st.pendingPos > 0:
    # A final real DATA chunk remains; sendData tags it END_STREAM (and, if the
    # window is closed, h2ResumeSend does so when it reopens).
    h2.sendData(c, sid)
  else:
    # The body already fully drained before finish: the prior DATA frames went
    # out without END_STREAM, so emit a bare END_STREAM DATA frame to close it.
    c.wbuf.addFrameHeader(0, ftData, flagEndStream, sid)
    h2.streams.del(sid)
    dec h2.activeStreams

proc h2StreamAbort*(c: ptr Connection, sid: uint32) =
  ## Abort a streamed response mid-body: RST_STREAM(INTERNAL_ERROR) so the peer
  ## sees the transfer was cut short, not cleanly completed. No-op unless the
  ## stream is an open streamed response.
  let h2 = h2Conn(c)
  if h2 == nil or sid notin h2.streams or not h2.streams[sid].streaming:
    return
  h2.streams[sid].streaming = false
  h2.streams[sid].onRespDrain = nil
  h2.streamError(c, sid, errInternal)

proc h2WsLookup(cp: pointer, stream: uint32): RootRef {.nimcall, gcsafe.} =
  ## LoopCore.wsStreamLookup: resolve a stream's WsConn for the public API.
  let c = cast[ptr Connection](cp)
  if c.h2 != nil:
    let h2 = H2Conn(c.h2)
    if stream in h2.streams: return h2.streams[stream].ws
  nil

proc installWsHooks*(core: ptr LoopCore) =
  ## Register the WebSocket-over-HTTP/2 lookup so the WebSocket layer can
  ## reach per-stream state without importing the h2 codec.
  core.wsStreamLookup = h2WsLookup

proc h2WsTeardownAll*(c: ptr Connection) =
  ## Deliver onClose (1006) for every WebSocket stream when the connection
  ## dies. Loop thread; called from the event loop's closeConn.
  if c.h2 == nil: return
  let h2 = H2Conn(c.h2)
  for sid, st in h2.streams.mpairs:
    if st.ws != nil:
      wsStreamClosed(h2.core, c, WsConn(st.ws))
      st.ws = nil

proc h2NotifyClosed*(c: ptr Connection) =
  ## Deliver a final onBody(last=true) for every streaming request whose body
  ## was still open when the connection died, so an async adapter suspended in
  ## await req.read() resumes at end-of-body and its Future / reader-table entry
  ## are released instead of leaking. Loop thread; called from closeConn.
  if c.h2 == nil: return
  let h2 = H2Conn(c.h2)
  var empty: string
  for sid, st in h2.streams.mpairs:
    if st.onBodyCb != nil:
      let cb = st.onBodyCb
      st.onBodyCb = nil
      try: cb(toOpenArray(empty, 0, -1), true)
      except CatchableError: discard

proc h2WsAccept*(c: ptr Connection, sid: uint32, maxMessage: int,
                 extensionsOffer, protocolsOffer: string,
                 serverProtocols: openArray[string],
                 dateStr, serverHeader: string): bool =
  ## Accept an RFC 8441 Extended CONNECT WebSocket on stream `sid`: reply 200
  ## (no END_STREAM, so the stream stays open for framing) and attach a
  ## WsConn. Returns false if the stream is not an unanswered ws-connect.
  let h2 = h2Conn(c)
  if sid notin h2.streams: return false
  template st: H2Stream = h2.streams[sid]
  if not st.isWsConnect or st.responded or st.ws != nil: return false
  st.responded = true
  let (w, proto, ext) = wsSetup(h2.core, c.fd, c.gen, maxMessage, sid,
                                extensionsOffer, protocolsOffer,
                                serverProtocols)
  w.flush = wsFlushH2
  st.ws = w
  # Hand over any frames the client pipelined with the CONNECT handshake
  # (buffered in st.body before acceptance). They are pumped once the handler
  # installs onMessage (see h2Input), not here, so no message is dispatched
  # into a nil callback.
  if st.body.len > 0:
    w.inBuf.add st.body
    st.body.setLen(0)
  w.preAcceptFin = st.endStreamSeen
  var hb = ""
  encodeStatus(hb, 200)
  if serverHeader.len > 0: encodeHeader(hb, "server", serverHeader)
  encodeHeader(hb, "date", dateStr)
  if proto.len > 0: encodeHeader(hb, "sec-websocket-protocol", proto)
  if ext.len > 0: encodeHeader(hb, "sec-websocket-extensions", ext)
  var off = 0
  var first = true
  while first or off < hb.len:
    let chunk = min(hb.len - off, h2.peerMaxFrame)
    let lastFrag = off + chunk >= hb.len
    let flags = if lastFrag: flagEndHeaders else: 0'u8   # never END_STREAM
    c.wbuf.addFrameHeader(chunk,
      (if first: ftHeaders else: ftContinuation), flags, sid)
    c.wbuf.add hb[off ..< off + chunk]
    off += chunk
    first = false
  true

proc h2Respond*(c: ptr Connection, code: int, sid: uint32,
                dateStr, serverHeader, contentType: string,
                extraHeaders: openArray[(string, string)],
                body: openArray[char], altSvc = "") =
  let h2 = h2Conn(c)
  if sid notin h2.streams: return
  if h2.streams[sid].responded: return
  h2.streams[sid].responded = true
  let skipBody = h2.streams[sid].isHead
  # RFC 9110 8.6: 1xx, 204, and 304 responses carry no representation, so
  # they must not advertise content-length (or content-type). Distinct
  # from HEAD (skipBody), which keeps the length a GET would have sent.
  let bodiless = code in 100 .. 199 or code == 204 or code == 304
  var hb = ""
  encodeStatus(hb, code)
  if serverHeader.len > 0:
    encodeHeader(hb, "server", serverHeader)
  encodeHeader(hb, "date", dateStr)
  if contentType.len > 0 and not bodiless:
    encodeHeader(hb, "content-type", contentType)
  if not bodiless:
    encodeHeader(hb, "content-length", $body.len)
  if altSvc.len > 0:
    encodeHeader(hb, "alt-svc", altSvc)
  for (name, val) in extraHeaders:
    encodeHeader(hb, name.toLowerAscii, val)
  let noBody = body.len == 0 or skipBody or bodiless
  # Header block fits one frame in practice; chunk defensively anyway.
  var off = 0
  var first = true
  while first or off < hb.len:
    let chunk = min(hb.len - off, h2.peerMaxFrame)
    let lastFrag = off + chunk >= hb.len
    var flags = if lastFrag: flagEndHeaders else: 0'u8
    if first and noBody: flags = flags or flagEndStream
    c.wbuf.addFrameHeader(chunk,
      (if first: ftHeaders else: ftContinuation), flags, sid)
    c.wbuf.add hb[off ..< off + chunk]
    off += chunk
    first = false
  if noBody:
    h2.streams.del(sid)
    dec h2.activeStreams
  else:
    template st: H2Stream = h2.streams[sid]
    st.pendingBody = newString(body.len)
    copyMem(addr st.pendingBody[0], unsafeAddr body[0], body.len)
    st.pendingPos = 0
    st.pendingIsLast = true
    h2.sendData(c, sid)

# --- inbound streaming (req.onBody) -----------------------------------------

proc h2DeliverBody(h2: H2Conn, c: ptr Connection, sid: uint32, last: bool) =
  ## Hand buffered request-body bytes to a streaming stream's onBody and clear
  ## the buffer (bounded memory). No-op until the handler registers onBody.
  ## For the auto-ack default, replenish the stream flow-control window by the
  ## delivered bytes once the callback returns; manualAck leaves it to
  ## req.ackBody so a slow consumer throttles the peer.
  if sid notin h2.streams: return
  template st: H2Stream = h2.streams[sid]
  if st.onBodyCb == nil: return
  if st.body.len > 0 or last:
    # The callback may res.send (deleting this stream from the table), so move
    # the buffer out and clear it *before* the call, and touch nothing on `st`
    # afterwards.
    let cb = st.onBodyCb
    let manualAck = st.bodyManualAck
    var buf: string
    swap(buf, st.body)
    cb(buf.toOpenArray(0, buf.len - 1), last)
    if not manualAck and buf.len > 0:
      c.wbuf.addWindowUpdate(sid, buf.len)

proc h2AckBody*(c: ptr Connection, sid: uint32, n: int) =
  ## Replenish `n` consumed body bytes of a streaming stream's flow-control
  ## window (req.ackBody). The connection window was replenished on receipt.
  let h2 = h2Conn(c)
  if h2 == nil or sid notin h2.streams or not h2.streams[sid].streamingReq:
    return
  c.wbuf.addWindowUpdate(sid, n)

proc h2SetOnBody*(c: ptr Connection, sid: uint32, cb: BodyCb,
                  manualAck = false) =
  ## request.onBody for HTTP/2: store the sink on the stream and flush whatever
  ## body already arrived before the handler ran (with last=true if the peer
  ## already half-closed).
  let h2 = h2Conn(c)
  if h2 == nil or sid notin h2.streams: return
  h2.streams[sid].onBodyCb = cb
  h2.streams[sid].bodyManualAck = manualAck
  h2DeliverBody(h2, c, sid, h2.streams[sid].endStreamSeen)

# --- request validation / dispatch -----------------------------------------

proc finishHeaders(h2: H2Conn, c: ptr Connection, sid: uint32,
                   endStream: bool, ready: var seq[uint32]) =
  ## Decode the accumulated header block and validate the request head.
  var fields: seq[(string, string)]
  try:
    h2.decoder.decodeHeaderBlock(h2.headerBlock, 0, h2.headerBlock.len, fields)
  except HpackError:
    h2.connError(c, errCompression)
    return
  h2.headerBlock.setLen(0)
  if sid notin h2.streams: return    # e.g. trailers for a reset stream
  template st: H2Stream = h2.streams[sid]
  if st.headersDone:
    # Trailers: allowed only with END_STREAM; fields are discarded.
    if not endStream:
      h2.connError(c, errProtocol)
      return
    st.endStreamSeen = true
    if st.streamingReq and st.dispatched:
      # A streaming route consumed the DATA via onBody as it arrived; the
      # trailers carry no body, but the sink still needs its terminating
      # last=true callback (otherwise the handler hangs and the stream leaks).
      # h2DeliverBody may res.send and delete the stream, so return after.
      h2.h2DeliverBody(c, sid, true)
      return
    # A buffered route falls through: the dispatch tail runs the handler now
    # that endStreamSeen is set.
  else:
    var meth, path, scheme, protocol: string
    var hasAuthority = false
    var pseudoDone = false
    var listSize = 0
    for (name, val) in fields:
      listSize += name.len + val.len + 32
      if name.len == 0:
        h2.streamError(c, sid, errProtocol)
        return
      if name[0] == ':':
        if pseudoDone:
          h2.streamError(c, sid, errProtocol)  # pseudo after regular
          return
        case name
        of ":method":
          if meth.len > 0: h2.streamError(c, sid, errProtocol); return
          meth = val
        of ":path":
          if path.len > 0: h2.streamError(c, sid, errProtocol); return
          path = val
        of ":scheme":
          if scheme.len > 0: h2.streamError(c, sid, errProtocol); return
          scheme = val
        of ":authority":
          if hasAuthority: h2.streamError(c, sid, errProtocol); return
          hasAuthority = true
        of ":protocol":                        # RFC 8441 Extended CONNECT
          if protocol.len > 0: h2.streamError(c, sid, errProtocol); return
          protocol = val
        else:
          h2.streamError(c, sid, errProtocol)  # unknown/response pseudo
          return
      else:
        pseudoDone = true
        for ch in name:
          if ch in 'A'..'Z':
            h2.streamError(c, sid, errProtocol)
            return
        case name
        of "connection", "proxy-connection", "keep-alive",
           "transfer-encoding", "upgrade":
          h2.streamError(c, sid, errProtocol)
          return
        of "te":
          if val != "trailers":
            h2.streamError(c, sid, errProtocol)
            return
        of "content-length":
          try:
            st.contentLength = parseBiggestInt(val)
          except ValueError:
            h2.streamError(c, sid, errProtocol)
            return
        else: discard
    # RFC 8441: an Extended CONNECT websocket carries :protocol plus a full
    # :scheme/:path/:authority (unlike a plain CONNECT, which omits them and
    # we do not support). The stream stays open for framing after dispatch.
    let isWs = meth == "CONNECT" and protocol == "websocket"
    if isWs:
      if path.len == 0 or scheme.len == 0 or not hasAuthority:
        h2.streamError(c, sid, errProtocol); return
      st.isWsConnect = true
    else:
      if protocol.len > 0:                 # :protocol only for a ws-connect
        h2.streamError(c, sid, errProtocol); return
      if meth.len == 0 or path.len == 0 or scheme.len == 0:
        h2.streamError(c, sid, errProtocol); return
    if listSize > h2.maxHeaderList:
      h2.streamError(c, sid, errEnhanceYourCalm)
      return
    if st.contentLength > int64(h2.maxBody):
      h2.streamError(c, sid, errRefusedStream)
      return
    st.headers = move(fields)
    st.headersDone = true
    st.isHead = meth == "HEAD"
    if endStream:
      st.endStreamSeen = true
    if not st.isWsConnect and hasStreamRoute(h2.core) and
        callStreamRoute(h2.core, c.fd, c.gen, sid):
      st.streamingReq = true          # dispatch on headers; DATA -> onBody
  if st.isWsConnect and not st.dispatched:
    # Dispatch as soon as the headers are in; DATA becomes WebSocket framing.
    st.dispatched = true
    ready.add sid
  elif st.streamingReq and not st.dispatched:
    # Streaming route: run the handler now so it can register req.onBody; the
    # body is delivered as DATA frames arrive.
    st.dispatched = true
    ready.add sid
  elif st.endStreamSeen and not st.dispatched:
    if st.contentLength >= 0 and int64(st.body.len) != st.contentLength:
      h2.streamError(c, sid, errProtocol)
      return
    st.dispatched = true
    ready.add sid

# --- frame ingestion --------------------------------------------------------

proc handleFrame(h2: H2Conn, c: ptr Connection, fh: FrameHeader,
                 payloadPos: int, ready: var seq[uint32]) =
  template payload(i: int): char = c.rbuf[payloadPos + i]

  if h2.contStream != 0 and
      (fh.typ != uint8(ftContinuation) or fh.streamId != h2.contStream):
    h2.connError(c, errProtocol)
    return

  if fh.typ > uint8(high(FrameType)):
    return                          # unknown frame types are ignored

  case FrameType(fh.typ)
  of ftData:
    let sid = fh.streamId
    if sid == 0: h2.connError(c, errProtocol); return
    if sid > h2.lastStreamId:
      h2.connError(c, errProtocol)   # DATA on an idle stream
      return
    # Flow control applies to the whole payload regardless of validity.
    if sid notin h2.streams or h2.streams[sid].endStreamSeen or
        not h2.streams[sid].headersDone:
      h2.streamError(c, sid, errStreamClosed)
    else:
      var dataStart = payloadPos
      var dataLen = fh.length
      if (fh.flags and flagPadded) != 0:
        if dataLen < 1: h2.connError(c, errFrameSize); return
        let padLen = int(uint8(payload(0)))
        if padLen >= dataLen: h2.connError(c, errProtocol); return
        dataStart += 1
        dataLen -= 1 + padLen
      template st: H2Stream = h2.streams[sid]
      if st.ws != nil:
        # RFC 8441 WebSocket stream: DATA payload is WebSocket framing.
        wsFeed(h2.core, c, WsConn(st.ws),
                 c.rbuf.toOpenArray(dataStart, dataStart + dataLen - 1))
        if (fh.flags and flagEndStream) != 0 and sid in h2.streams and
            h2.streams[sid].ws != nil:
          wsPeerClosed(h2.core, c, WsConn(h2.streams[sid].ws))
      elif st.body.len + dataLen > h2.maxBody:
        h2.streamError(c, sid, errRefusedStream)
      elif st.isWsConnect:
        # WebSocket frames can arrive in the same read batch as the Extended
        # CONNECT HEADERS, before the handler runs acceptWebSocket. Buffer them
        # in st.body (bounded by the maxBody check above); h2WsAccept moves them
        # into the WsConn's inBuf, pumped once the handler installs onMessage.
        if dataLen > 0:
          let old = st.body.len
          st.body.setLen(old + dataLen)
          copyMem(addr st.body[old], addr c.rbuf[dataStart], dataLen)
        if (fh.flags and flagEndStream) != 0:
          st.endStreamSeen = true
      elif st.streamingReq:
        # Inbound streaming: hand DATA to onBody and clear (bounded memory);
        # no content-length reconciliation since the body is not retained. The
        # stream flow-control window is replenished on consume (h2DeliverBody /
        # ackBody), not here, so a slow consumer throttles the peer; padding is
        # discarded now, so credit its flow-control bytes now.
        if fh.length > dataLen:
          c.wbuf.addWindowUpdate(sid, fh.length - dataLen)
        if dataLen > 0:
          let old = st.body.len
          st.body.setLen(old + dataLen)
          copyMem(addr st.body[old], addr c.rbuf[dataStart], dataLen)
        let endS = (fh.flags and flagEndStream) != 0
        if endS: st.endStreamSeen = true
        h2.h2DeliverBody(c, sid, endS)
      else:
        let old = st.body.len
        st.body.setLen(old + dataLen)
        if dataLen > 0:
          copyMem(addr st.body[old], addr c.rbuf[dataStart], dataLen)
        if (fh.flags and flagEndStream) != 0:
          st.endStreamSeen = true
          if st.contentLength >= 0 and
              int64(st.body.len) != st.contentLength:
            h2.streamError(c, sid, errProtocol)
          elif not st.dispatched:
            st.dispatched = true
            ready.add sid
    # Replenish the connection window eagerly (so a slow stream can't starve
    # the others); the stream window is eager too, except a streaming request
    # defers it to consumption (handled above / via ackBody).
    if fh.length > 0:
      c.wbuf.addWindowUpdate(0, fh.length)
      if fh.streamId in h2.streams and
          not h2.streams[fh.streamId].endStreamSeen and
          not h2.streams[fh.streamId].streamingReq:
        c.wbuf.addWindowUpdate(fh.streamId, fh.length)

  of ftHeaders:
    let sid = fh.streamId
    if sid == 0 or (sid mod 2) == 0: h2.connError(c, errProtocol); return
    var fragStart = payloadPos
    var fragLen = fh.length
    if (fh.flags and flagPadded) != 0:
      if fragLen < 1: h2.connError(c, errFrameSize); return
      let padLen = int(uint8(payload(0)))
      fragStart += 1
      fragLen -= 1
      if padLen > fragLen: h2.connError(c, errProtocol); return
      fragLen -= padLen
    if (fh.flags and flagPriority) != 0:
      if fragLen < 5: h2.connError(c, errFrameSize); return
      if (get32(c.rbuf, fragStart) and 0x7fffffff'u32) == sid:
        h2.connError(c, errProtocol); return   # self-dependency
      fragStart += 5
      fragLen -= 5
    if sid in h2.streams:
      if not h2.streams[sid].headersDone:
        h2.connError(c, errProtocol); return   # HEADERS while mid-request
      if h2.streams[sid].endStreamSeen:
        h2.connError(c, errStreamClosed); return
      # else: trailers (allowed)
    else:
      if sid <= h2.lastStreamId:
        h2.connError(c, errStreamClosed); return  # closed stream reuse
      if h2.goingAway:
        h2.streamError(c, sid, errRefusedStream); return
      if h2.maxConcurrentStreams > 0 and
          h2.activeStreams >= h2.maxConcurrentStreams:
        h2.streamError(c, sid, errRefusedStream); return
      h2.lastStreamId = sid
      h2.streams[sid] = H2Stream(
        sendWindow: h2.peerInitialWindow, contentLength: -1)
      inc h2.activeStreams
      h2.controlFrameCount = 0       # a real request: reset the flood budget
    h2.headerBlock.setLen(0)
    for i in 0 ..< fragLen:
      h2.headerBlock.add c.rbuf[fragStart + i]
    if (fh.flags and flagEndHeaders) != 0:
      h2.finishHeaders(c, sid, (fh.flags and flagEndStream) != 0, ready)
    else:
      h2.contStream = sid
      h2.contEndStream = (fh.flags and flagEndStream) != 0

  of ftContinuation:
    if h2.contStream == 0 or fh.streamId != h2.contStream:
      h2.connError(c, errProtocol)
      return
    # Budget CONTINUATION fragments (CVE-2024-27316 class): a flood of
    # zero-length CONTINUATION frames never grows headerBlock past the byte cap
    # below, so count them against the control-frame budget, which resets only on
    # real stream progress.
    h2.noteControlFrame(c)
    if c.state == csClosing: return
    if h2.headerBlock.len + fh.length > h2.maxHeaderList * 2:
      h2.connError(c, errEnhanceYourCalm)
      return
    for i in 0 ..< fh.length:
      h2.headerBlock.add c.rbuf[payloadPos + i]
    if (fh.flags and flagEndHeaders) != 0:
      let sid = h2.contStream
      h2.contStream = 0
      h2.finishHeaders(c, sid, h2.contEndStream, ready)

  of ftSettings:
    if fh.streamId != 0: h2.connError(c, errProtocol); return
    if (fh.flags and flagAck) != 0:
      if fh.length != 0: h2.connError(c, errFrameSize)
      return
    if fh.length mod 6 != 0: h2.connError(c, errFrameSize); return
    h2.noteControlFrame(c)
    if c.state == csClosing: return
    var i = 0
    var initialWindowChanged = false
    while i < fh.length:
      let id = get16(c.rbuf, payloadPos + i)
      let value = get32(c.rbuf, payloadPos + i + 2)
      case id
      of setInitialWindowSize:
        if value > 0x7fffffff'u32:
          h2.connError(c, errFlowControl); return
        let delta = int32(value) - h2.peerInitialWindow
        h2.peerInitialWindow = int32(value)
        for sid, st in h2.streams.mpairs:
          # A stream's send window may already be near 2^31-1 (raised by
          # WINDOW_UPDATE); a positive delta must not push it past the signed
          # 31-bit ceiling, and the accounting must not wrap int32 either.
          # RFC 9113 6.9.2 makes an out-of-range result a FLOW_CONTROL_ERROR.
          let nw = int64(st.sendWindow) + int64(delta)
          if nw > 0x7fffffff'i64 or nw < -0x80000000'i64:
            h2.connError(c, errFlowControl); return
          st.sendWindow = int32(nw)
        initialWindowChanged = true
      of setMaxFrameSize:
        if value < 16384'u32 or value > 16777215'u32:
          h2.connError(c, errProtocol); return
        h2.peerMaxFrame = int(value)
      of setEnablePush:
        if value > 1'u32: h2.connError(c, errProtocol); return
      else: discard                  # header table size: encoder is static-only
      i += 6
    c.wbuf.addFrameHeader(0, ftSettings, flagAck, 0)
    if initialWindowChanged:
      # Raising SETTINGS_INITIAL_WINDOW_SIZE grows every stream's send
      # window (RFC 7540 6.9.2): flush DATA it may have unblocked, the same
      # retry the connection-level WINDOW_UPDATE path does.
      var retry: seq[uint32]
      for sid, st in h2.streams:
        if st.pendingBody.len - st.pendingPos > 0: retry.add sid
      for sid in retry: h2ResumeSend(h2, c, sid)

  of ftPing:
    if fh.streamId != 0: h2.connError(c, errProtocol); return
    if fh.length != 8: h2.connError(c, errFrameSize); return
    if (fh.flags and flagAck) == 0:
      h2.noteControlFrame(c)
      if c.state == csClosing: return
      c.wbuf.addPingAck(c.rbuf.toOpenArray(payloadPos, payloadPos + 7))

  of ftWindowUpdate:
    if fh.length != 4: h2.connError(c, errFrameSize); return
    let inc32 = get32(c.rbuf, payloadPos) and 0x7fffffff'u32
    if inc32 == 0:
      if fh.streamId == 0: h2.connError(c, errProtocol)
      else: h2.streamError(c, fh.streamId, errProtocol)
      return
    if fh.streamId == 0:
      if int64(h2.connSendWindow) + int64(inc32) > 0x7fffffff'i64:
        h2.connError(c, errFlowControl); return
      let wasBlocked = h2.connSendWindow <= 0
      h2.connSendWindow += int32(inc32)
      if wasBlocked and h2.connSendWindow > 0:
        # The connection window just went positive: retry stalled streams. Only
        # scan on this transition, not on every WINDOW_UPDATE.
        var retry: seq[uint32]
        for sid, st in h2.streams:
          if st.pendingBody.len - st.pendingPos > 0: retry.add sid
        for sid in retry: h2ResumeSend(h2, c, sid)
      else:
        # A WINDOW_UPDATE that unblocked nothing is pure overhead; budget it so a
        # flood trips ENHANCE_YOUR_CALM (the counter resets on real progress).
        h2.noteControlFrame(c)
        if c.state == csClosing: return
    elif fh.streamId in h2.streams:
      template st: H2Stream = h2.streams[fh.streamId]
      if int64(st.sendWindow) + int64(inc32) > 0x7fffffff'i64:
        h2.streamError(c, fh.streamId, errFlowControl); return
      st.sendWindow += int32(inc32)
      h2ResumeSend(h2, c, fh.streamId)
    elif fh.streamId > h2.lastStreamId:
      h2.connError(c, errProtocol)   # WINDOW_UPDATE on idle stream

  of ftRstStream:
    if fh.streamId == 0: h2.connError(c, errProtocol); return
    if fh.length != 4: h2.connError(c, errFrameSize); return
    if fh.streamId > h2.lastStreamId:
      h2.connError(c, errProtocol); return   # RST on idle stream
    if fh.streamId in h2.streams:
      if h2.streams[fh.streamId].ws != nil:      # WebSocket reset: onClose
        wsStreamClosed(h2.core, c, WsConn(h2.streams[fh.streamId].ws))
        h2.streams[fh.streamId].ws = nil
      h2.streams.del(fh.streamId)
      dec h2.activeStreams
    # Rapid Reset (CVE-2023-44487): a peer that opens then immediately
    # resets streams costs handler work while never holding concurrency.
    # Cap cumulative resets per connection.
    inc h2.rstStreamCount
    if h2.maxResetStreams > 0 and h2.rstStreamCount > h2.maxResetStreams:
      h2.connError(c, errEnhanceYourCalm)

  of ftPriority:
    if fh.streamId == 0: h2.connError(c, errProtocol); return
    if fh.length != 5: h2.connError(c, errFrameSize); return
    if (get32(c.rbuf, payloadPos) and 0x7fffffff'u32) == fh.streamId:
      h2.connError(c, errProtocol); return   # self-dependency
    h2.noteControlFrame(c)         # PRIORITY has no productive use here
    # Otherwise ignored (RFC 9113 deprecates the priority tree).

  of ftGoaway:
    if fh.streamId != 0: h2.connError(c, errProtocol); return
    # A peer (client) GOAWAY is informational for a server that never pushes;
    # record it separately from our own drain flag so we do not start refusing
    # the client's own subsequent streams (which `goingAway` would do).
    h2.peerGoneAway = true

  of ftPushPromise:
    h2.connError(c, errProtocol)     # clients cannot push

proc h2Feed*(c: ptr Connection, ready: var seq[uint32]) =
  ## Consume the connection preface and all complete frames from the
  ## receive buffer; append stream ids ready for handler dispatch.
  let h2 = h2Conn(c)
  if not h2.prefaceDone:
    if c.rlen - h2.parsePos < connectionPreface.len:
      return
    for i in 0 ..< connectionPreface.len:
      if c.rbuf[h2.parsePos + i] != connectionPreface[i]:
        h2.connError(c, errProtocol)
        return
    h2.parsePos += connectionPreface.len
    h2.prefaceDone = true
    sendOurSettings(c)
  while c.state != csClosing:
    let avail = c.rlen - h2.parsePos
    if avail < frameHeaderLen: break
    let fh = parseFrameHeader(c.rbuf, h2.parsePos)
    if fh.length > ourMaxFrameSize:
      h2.connError(c, errFrameSize)
      break
    if avail < frameHeaderLen + fh.length: break
    let payloadPos = h2.parsePos + frameHeaderLen
    h2.parsePos += frameHeaderLen + fh.length
    h2.handleFrame(c, fh, payloadPos, ready)
  # Compact consumed bytes.
  if h2.parsePos > 0:
    if h2.parsePos >= c.rlen:
      c.rlen = 0
    else:
      moveMem(addr c.rbuf[0], addr c.rbuf[h2.parsePos], c.rlen - h2.parsePos)
      c.rlen -= h2.parsePos
    h2.parsePos = 0

proc h2ActiveStreams*(c: ptr Connection): int =
  if c.h2 == nil: 0 else: h2Conn(c).activeStreams

proc h2StreamAlive*(c: ptr Connection, sid: uint32): bool =
  c.h2 != nil and sid in h2Conn(c).streams

proc h2Stream*(c: ptr Connection, sid: uint32): ptr H2Stream =
  ## nil if gone. Pointer valid until the streams table is next mutated.
  let h2 = h2Conn(c)
  if sid in h2.streams: addr h2.streams[sid] else: nil
