## HTTP/2 connection state machine (RFC 9113): frame handling, stream
## lifecycle, both directions of flow control, and response serialization.
## One H2Conn per connection, touched only by the owning loop thread
## (workers respond through the protocol-neutral outbox).

import std/[tables, strutils, uri, json, deques]
import ./frames, ./hpack
import ../connection
import ../websocket/codec as wscodec

const h2FieldNameDelims = {'"', '(', ')', ',', '/', ':', ';', '<', '=', '>',
                           '?', '@', '[', '\\', ']', '{', '}'}
  ## RFC 9110 5.6.2 token separators forbidden in a field name. Mirrors the h1
  ## parser's tokenDelims, kept local so the h2 codec has no dependency on the
  ## h1 parser.

type
  H2Stream* = object
    headers*: seq[(string, string)]  ## request fields incl. pseudo-headers
    trailers*: seq[(string, string)] ## request trailer fields (after the body)
    respTrailers*: seq[(string, string)] ## response trailers to emit at END_STREAM
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
    jsonCached*: bool
    cachedUrl*: Uri
    cachedQuery*: Table[string, string]
    cachedJson*: JsonNode
    pathParams*: PathParams          ## written by the router at match time
    pendingBody*: string             ## response bytes awaiting send window
    pendingPos*: int
    pendingIsLast*: bool
    streaming*: bool                 ## res.sendHead opened a streamed body
    respComp*: RootRef               ## streaming compressor (Gzip/BrotliStream);
                                     ## =destroy frees it on streams.del
    respEnc*: string                 ## "gzip"/"br" for respComp
    respBackedUp*: bool              ## write() hit the window; onDrain pending
    onRespDrain*: RespDrainCb        ## streamed-response drain callback
    streamingReq*: bool              ## router.stream route: dispatch on headers
    onBodyCb*: BodyCb                ## inbound streaming sink (req.onBody)
    bodyManualAck*: bool             ## defer stream WINDOW_UPDATE to req.ackBody
    isWsConnect*: bool               ## RFC 8441 Extended CONNECT websocket
    ws*: RootRef                     ## WsConn when this stream is a WebSocket
    pendingWindow*: int              ## consumed bytes not yet returned as a
                                     ## stream WINDOW_UPDATE (batched at half-window)
    inSendQ*: bool                   ## currently queued in H2Conn.sendQ (dedupe)
    urgency*: uint8                  ## RFC 9218 priority: 0 (highest) .. 7, default 3
    incremental*: bool               ## RFC 9218: true = interleave (round-robin),
                                     ## false (default) = deliver sequentially

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
    streamRecvWindow*: int    ## per-stream receive window we advertise
    connRecvWindow*: int      ## per-connection receive window (streaming cap)
    pendingConnWindow*: int   ## consumed bytes not yet returned as a connection
                              ## WINDOW_UPDATE (batched at half-window)
    # Per-connection write scheduler (RFC 9218): one round-robin ready-queue per
    # urgency level (0 highest .. 7). The scheduler serves the lowest non-empty
    # urgency, popping a stream and emitting one frame; incremental streams
    # re-enqueue at the back (interleave), non-incremental at the front (deliver
    # sequentially, one stream at a time within its level).
    sendQ*: array[8, Deque[uint32]]
    scheduling*: bool         ## reentrancy guard for h2Schedule
    resuming*: bool           ## reentrancy guard for h2ResumeProducers
    # RFC 9218 PRIORITY_UPDATE that arrived before a stream's HEADERS: the raw
    # Priority field value, applied when the stream opens. Capped to bound a flood.
    pendingPriority*: Table[uint32, string]

const
  ourMaxFrameSize = defaultMaxFrameSize
  defaultUrgency* = 3'u8          ## RFC 9218 default urgency when none is signalled
  maxPendingPriority = 128        ## cap on buffered pre-HEADERS PRIORITY_UPDATEs

proc parsePriorityField(v: string, urgency: var uint8, incremental: var bool) =
  ## Parse an RFC 9218 Priority field value (an RFC 8941 Structured Field
  ## dictionary), updating `urgency`/`incremental` in place. Recognises `u`
  ## (integer 0..7) and `i` (boolean: bare or `?1` = true, `?0` = false);
  ## unknown members and malformed values are ignored (leave the current value).
  for part in v.split(','):
    let kv = part.strip()
    if kv.len == 0: continue
    let eq = kv.find('=')
    if eq < 0:
      if kv == "i": incremental = true          # bare boolean member = true
    else:
      let key = kv[0 ..< eq].strip()
      let val = kv[eq + 1 .. ^1].strip()
      case key
      of "u":
        try:
          let n = parseInt(val)
          if n in 0 .. 7: urgency = uint8(n)
        except ValueError: discard
      of "i":
        incremental = val != "?0"               # ?1 / anything but ?0 = true
      else: discard

proc h2Conn*(c: ptr Connection): H2Conn {.inline.} =
  H2Conn(c.h2)

proc newH2Conn*(core: ptr LoopCore, maxBody, maxHeaderList,
                maxConcurrentStreams, maxResetStreams,
                maxControlFrames: int,
                streamRecvWindow = 1024 * 1024,
                connRecvWindow = 1024 * 1024): H2Conn =
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
    maxControlFrames: maxControlFrames,
    streamRecvWindow: max(streamRecvWindow, int(defaultInitialWindow)),
    connRecvWindow: max(connRecvWindow, int(defaultInitialWindow)))

proc sendOurSettings(c: ptr Connection) =
  var payload = ""
  payload.addSetting(setHeaderTableSize, 4096)
  payload.addSetting(setEnablePush, 0)
  payload.addSetting(setMaxConcurrentStreams,
                     uint32(h2Conn(c).maxConcurrentStreams))
  payload.addSetting(setMaxFrameSize, uint32(ourMaxFrameSize))
  # Advertise our per-stream receive window. The HTTP/2 default is only 64 KiB,
  # which throttles uploads to (window / round-trip): a large streaming upload,
  # especially on an async/manualAck handler that replenishes the window on
  # consumption, drains it and stalls each cycle. A larger window keeps the pipe
  # full (bandwidth-delay product). Bounded per stream by this value and per
  # connection by connRecvWindow (see the DATA flow-control handling).
  payload.addSetting(setInitialWindowSize, uint32(h2Conn(c).streamRecvWindow))
  payload.addSetting(setEnableConnectProtocol, 1)   # RFC 8441 WebSockets
  payload.addSetting(setNoRfc7540Priorities, 1)     # RFC 9218 prioritization
  c.wbuf.addFrameHeader(payload.len, ftSettings, 0, 0)
  c.wbuf.add payload
  # Grow the connection-level receive window from the fixed 64 KiB default to
  # connRecvWindow, so the whole connection (not just one stream) can keep a
  # large upload in flight. Streaming-body bytes are credited back on
  # consumption, so this doubles as the cap on total un-consumed upload buffer.
  let connGrow = h2Conn(c).connRecvWindow - int(defaultInitialWindow)
  if connGrow > 0:
    c.wbuf.addWindowUpdate(0, connGrow)

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

proc emitTrailers(h2: H2Conn, c: ptr Connection, sid: uint32) =
  ## Emit a streamed response's trailer section as a trailing HEADERS frame
  ## carrying END_STREAM, then drop the stream. Called once the response body
  ## has fully drained; HEADERS are not flow-controlled, so this always fits.
  if sid notin h2.streams: return
  template st: H2Stream = h2.streams[sid]
  var hb = ""
  for (name, val) in st.respTrailers:
    encodeHeader(hb, name.toLowerAscii, val)
  var off = 0
  var first = true
  while first or off < hb.len:
    let chunk = min(hb.len - off, h2.peerMaxFrame)
    let lastFrag = off + chunk >= hb.len
    var flags = if lastFrag: flagEndHeaders else: 0'u8
    if first: flags = flags or flagEndStream   # END_STREAM rides the HEADERS
    c.wbuf.addFrameHeader(chunk,
      (if first: ftHeaders else: ftContinuation), flags, sid)
    c.wbuf.add hb[off ..< off + chunk]
    off += chunk
    first = false
  h2.streams.del(sid)
  dec h2.activeStreams

proc h2Sendable(h2: H2Conn, st: H2Stream): bool =
  ## Can this stream emit a frame right now, ignoring the connection window
  ## (which gates the whole pass, not queue membership)? A backlog needs its
  ## own send window; an empty backlog is sendable only when it still owes a
  ## terminal frame -- END_STREAM for a response, the close for a WebSocket.
  let backlog = st.pendingBody.len - st.pendingPos
  if backlog > 0: return st.sendWindow > 0
  if st.ws != nil: return WsConn(st.ws).wantClose
  st.pendingIsLast

proc h2Enqueue(h2: H2Conn, sid: uint32) =
  ## Add a stream to the round-robin ready-queue if it can send now and is not
  ## already queued (O(1) dedupe via inSendQ).
  if sid notin h2.streams: return
  template st: H2Stream = h2.streams[sid]
  if not st.inSendQ and h2.h2Sendable(st):
    st.inSendQ = true
    h2.sendQ[st.urgency].addLast(sid)

proc emitOneFrame(h2: H2Conn, c: ptr Connection, sid: uint32): bool =
  ## Emit exactly one DATA frame for a stream, bounded by the peer max frame
  ## size and both flow-control windows. Returns true if a body frame went out.
  ## Terminal handling for an empty backlog that owes END_STREAM: emit trailers
  ## (trailing HEADERS) or a bare END_STREAM DATA, then drop the stream.
  if sid notin h2.streams: return false
  template st: H2Stream = h2.streams[sid]
  let remaining = st.pendingBody.len - st.pendingPos
  if remaining == 0:
    if st.ws == nil and st.pendingIsLast:
      if st.respTrailers.len > 0:
        h2.emitTrailers(c, sid)              # trailing HEADERS(END_STREAM) + drop
      else:
        c.wbuf.addFrameHeader(0, ftData, flagEndStream, sid)
        h2.streams.del(sid)
        dec h2.activeStreams
    return false
  var chunk = min(remaining, h2.peerMaxFrame)
  chunk = min(chunk, int(st.sendWindow))
  chunk = min(chunk, int(h2.connSendWindow))
  if chunk <= 0: return false                # blocked on a window; re-enter on UPDATE
  # With trailers pending the last DATA must NOT carry END_STREAM; the trailing
  # HEADERS frame closes the stream instead. WebSocket DATA never ends the stream.
  let last = st.ws == nil and st.pendingIsLast and st.respTrailers.len == 0 and
             (st.pendingPos + chunk == st.pendingBody.len)
  c.wbuf.addFrameHeader(chunk, ftData,
                        (if last: flagEndStream else: 0'u8), sid)
  let oldLen = c.wbuf.len
  c.wbuf.setLen(oldLen + chunk)
  copyMem(addr c.wbuf[oldLen], addr st.pendingBody[st.pendingPos], chunk)
  st.pendingPos += chunk
  st.sendWindow -= int32(chunk)
  h2.connSendWindow -= int32(chunk)
  if st.pendingPos == st.pendingBody.len:
    st.pendingBody.setLen 0                  # compact a fully-drained buffer
    st.pendingPos = 0
  if last:
    h2.streams.del(sid)
    dec h2.activeStreams
  true

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

proc h2WsAfterEmit(h2: H2Conn, c: ptr Connection, sid: uint32) =
  ## WebSocket post-emit bookkeeping after the scheduler pushed a frame for this
  ## stream: finalize on close, clear/fire onDrain backpressure, or RST a close
  ## that can never drain (window exhausted).
  if sid notin h2.streams or h2.streams[sid].ws == nil: return
  let w = WsConn(h2.streams[sid].ws)
  template st: H2Stream = h2.streams[sid]
  let backlog = st.pendingBody.len - st.pendingPos
  w.h2Pending = backlog
  if backlog == 0:
    if w.wantClose:
      # A user onClose fires inside; contain it so the effect stays `raises: []`
      # (the scheduler is reachable from strict-effect async handlers via send).
      try: h2WsFinalize(h2, c, sid, w)
      except Exception: discard
    elif w.backedUp:
      w.backedUp = false
      if w.onDrain != nil:
        try: w.onDrain(WebSocket(core: h2.core, fd: c.fd, gen: c.gen, stream: sid))
        except Exception: discard
  else:
    w.backedUp = true
    if w.wantClose and (st.sendWindow <= 0 or h2.connSendWindow <= 0):
      # Closing, but the send window is exhausted so the close frame + END_STREAM
      # can never drain gracefully. Rather than leave a zombie stream holding a
      # slot (and, being active, stripping the connection's read deadline),
      # RST_STREAM and tear it down.
      c.wbuf.addRstStream(sid, errCancel)
      try: wsStreamClosed(h2.core, c, w)
      except Exception: discard
      st.ws = nil
      h2.streams.del(sid)
      dec h2.activeStreams

proc h2ResumeProducers(h2: H2Conn, c: ptr Connection) =
  ## Resume streamed-response producers parked on the connection write-buffer
  ## cap (respHighWater), now that a scheduler pass or a socket drain left room.
  ## A parked producer's frames have already been emitted, so its backlog is
  ## empty and it is NOT in the ready-queue -- only this scan finds it. Collect
  ## ids first (an onRespDrain callback may res.write and mutate the table) and
  ## stop early if a resumed producer refills the buffer.
  if h2.resuming: return
  if pendingOut(c) >= respHighWater: return
  h2.resuming = true
  var resumable: seq[uint32]
  for sid in h2.streams.keys:
    template st: H2Stream = h2.streams[sid]
    if st.respBackedUp and st.onRespDrain != nil and
       st.pendingBody.len - st.pendingPos < respHighWater:
      resumable.add sid
  for sid in resumable:
    if pendingOut(c) >= respHighWater: break
    if sid notin h2.streams: continue
    template st: H2Stream = h2.streams[sid]
    if not st.respBackedUp or st.onRespDrain == nil: continue
    st.respBackedUp = false
    let cb = st.onRespDrain
    st.onRespDrain = nil            # fire once; the producer re-registers if it
    # backs up again (res.write -> enqueue+schedule). Contain a raising producer
    # so the effect stays `raises: []`: the scheduler is reachable from a
    # strict-effect async handler (res.send -> h2Respond -> h2Schedule).
    try: cb(h2.core, c.fd, c.gen, sid)
    except Exception: discard
  h2.resuming = false

proc h2NextUrgency(h2: H2Conn): int =
  ## Lowest non-empty urgency level (the highest-priority ready streams), or -1
  ## when nothing is queued. RFC 9218: urgency is the primary ordering key.
  for u in 0 .. 7:
    if h2.sendQ[u].len > 0: return u
  -1

proc h2Schedule(h2: H2Conn, c: ptr Connection) =
  ## RFC 9218 write pass: serve the lowest non-empty urgency level, pop a stream,
  ## emit ONE frame, and requeue it. Incremental streams go to the BACK of their
  ## level (interleave/round-robin); non-incremental go to the FRONT so a single
  ## stream is delivered sequentially within its level before the next. Bounded
  ## by the connection send window and the write-buffer cap (respHighWater) so no
  ## level monopolises the wire or buffers a whole response in RAM. When the pass
  ## ends with room, resume any producer parked on the buffer cap.
  if h2.scheduling: return
  h2.scheduling = true
  while h2.connSendWindow > 0 and pendingOut(c) < respHighWater:
    let u = h2.h2NextUrgency()
    if u < 0: break
    let sid = h2.sendQ[u].popFirst()
    if sid notin h2.streams: continue
    template st: H2Stream = h2.streams[sid]
    st.inSendQ = false
    let isWs = st.ws != nil
    discard emitOneFrame(h2, c, sid)
    if sid notin h2.streams: continue        # emitted a terminal frame and dropped
    if isWs:
      h2.h2WsAfterEmit(c, sid)               # WebSockets interleave (incremental)
      if sid in h2.streams and h2.h2Sendable(h2.streams[sid]): h2.h2Enqueue(sid)
    elif h2.h2Sendable(st):
      st.inSendQ = true
      if st.incremental: h2.sendQ[st.urgency].addLast(sid)   # round-robin
      else: h2.sendQ[st.urgency].addFirst(sid)               # keep this stream's turn
  h2.scheduling = false
  h2.h2ResumeProducers(c)

proc h2Reprioritize(h2: H2Conn, sid: uint32, fieldVal: string) =
  ## Apply an RFC 9218 Priority field value to an open stream (Priority request
  ## header or PRIORITY_UPDATE frame). If the stream is already queued it stays
  ## in its old level until the next pop, then migrates to the new urgency via
  ## h2Enqueue -- no need to hunt it out of the deque.
  if sid notin h2.streams: return
  template st: H2Stream = h2.streams[sid]
  parsePriorityField(fieldVal, st.urgency, st.incremental)

proc handlePriorityUpdate(h2: H2Conn, c: ptr Connection, fh: FrameHeader,
                          payloadPos: int) =
  ## RFC 9218 7.1 PRIORITY_UPDATE (frame type 0x10): a connection-level frame
  ## carrying a Prioritized Stream ID plus a Priority field value. Apply it to
  ## the open stream, or buffer it (capped) when it arrives ahead of HEADERS.
  if fh.streamId != 0: h2.connError(c, errProtocol); return
  if fh.length < 4: h2.connError(c, errFrameSize); return
  h2.noteControlFrame(c)
  if c.state == csClosing: return
  let psid = get32(c.rbuf, payloadPos) and 0x7fffffff'u32
  if psid == 0 or (psid and 1'u32) == 0:
    h2.connError(c, errProtocol); return       # must name a client-initiated stream
  var field = newString(fh.length - 4)
  for i in 0 ..< field.len: field[i] = c.rbuf[payloadPos + 4 + i]
  if psid in h2.streams:
    h2.h2Reprioritize(psid, field)
  elif psid > h2.lastStreamId and h2.pendingPriority.len < maxPendingPriority:
    h2.pendingPriority[psid] = field            # ahead of HEADERS: apply on open

proc wsFlushH2(core: ptr LoopCore, c: ptr Connection,
               w: WsConn) {.nimcall, gcsafe.} =
  ## `WsConn.flush` for HTTP/2: append produced frames to the stream's
  ## pending outbound and schedule them as DATA.
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
  h2.h2Enqueue(sid)
  h2.h2Schedule(c)

proc h2SetPriority*(c: ptr Connection, sid: uint32, urgency: uint8,
                    incremental: bool) {.raises: [].} =
  ## RFC 9218 server-side override of a stream's scheduling priority (res.setPriority).
  ## Effect-clean (`withValue`, no KeyError) so it composes in strict-effect async.
  let h2 = h2Conn(c)
  if h2 == nil: return
  h2.streams.withValue(sid, st):
    st.urgency = min(urgency, 7'u8)
    st.incremental = incremental

proc h2MarkRespBackedUp*(c: ptr Connection, sid: uint32) =
  ## Mark a streamed response as backed up (write() returned false), so a drain
  ## path resumes its producer. Used when the connection write buffer is full
  ## even though this stream's send window still has room.
  let h2 = h2Conn(c)
  if h2 != nil and sid in h2.streams:
    h2.streams[sid].respBackedUp = true

proc h2DrainResume*(c: ptr Connection, core: ptr LoopCore) =
  ## The connection write buffer drained to the socket: run a scheduler pass to
  ## refill it from the ready-queue and resume any producer parked on the cap.
  let h2 = h2Conn(c)
  if h2 == nil: return
  h2.h2Schedule(c)

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
  h2.h2Enqueue(sid)
  h2.h2Schedule(c)
  if sid notin h2.streams: return 0
  h2.streams[sid].pendingBody.len - h2.streams[sid].pendingPos

proc h2StreamFinish*(c: ptr Connection, sid: uint32,
                     trailers: openArray[(string, string)] = []) =
  ## Terminate a streamed response: mark the pending body final so the last
  ## DATA frame carries END_STREAM (or, when `trailers` are given, a trailing
  ## HEADERS frame does), then push.
  let h2 = h2Conn(c)
  if h2 == nil or sid notin h2.streams or not h2.streams[sid].streaming:
    return
  template st: H2Stream = h2.streams[sid]
  st.streaming = false
  st.onRespDrain = nil
  st.respBackedUp = false          # finished: never let a drain path resume it
  if st.isHead:
    return                               # HEAD stream already closed at head
  st.pendingIsLast = true
  if trailers.len > 0: st.respTrailers = @trailers
  if st.pendingBody.len - st.pendingPos > 0:
    # A final real DATA chunk remains; the scheduler tags it END_STREAM (or, with
    # trailers pending, emits the trailing HEADERS once the body drains; a closed
    # window re-enters via the stream WINDOW_UPDATE path).
    h2.h2Enqueue(sid)
    h2.h2Schedule(c)
  elif st.respTrailers.len > 0:
    # The body already drained; close with the trailer section.
    h2.emitTrailers(c, sid)
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
    h2.h2Enqueue(sid)
    h2.h2Schedule(c)

proc h2SendInformational*(c: ptr Connection, code: int, sid: uint32,
                          headers: openArray[(string, string)]) =
  ## Send a 1xx informational HEADERS block (e.g. 103 Early Hints) on `sid`
  ## WITHOUT ending the stream or marking it responded -- the final response
  ## still follows via h2Respond, and this may be sent several times. No-op if
  ## `code` is not 1xx, or the stream is gone / already finally answered.
  if code < 100 or code > 199: return
  let h2 = h2Conn(c)
  if h2 == nil or sid notin h2.streams or h2.streams[sid].responded: return
  var hb = ""
  encodeStatus(hb, code)
  for (name, val) in headers:
    encodeHeader(hb, name.toLowerAscii, val)
  var off = 0
  var first = true
  while first or off < hb.len:
    let chunk = min(hb.len - off, h2.peerMaxFrame)
    let flags = if off + chunk >= hb.len: flagEndHeaders else: 0'u8  # no END_STREAM
    c.wbuf.addFrameHeader(chunk, (if first: ftHeaders else: ftContinuation),
                          flags, sid)
    c.wbuf.add hb[off ..< off + chunk]
    off += chunk
    first = false

# --- receive-window replenishment (batched WINDOW_UPDATE) -------------------

proc creditStream(h2: H2Conn, c: ptr Connection, sid: uint32, n: int) =
  ## Return `n` consumed bytes to a stream's receive window, batched: accumulate
  ## and emit a WINDOW_UPDATE only once the un-returned credit reaches half the
  ## window. The peer keeps >= half the window to send into, so it never stalls,
  ## while a large upload emits far fewer control frames (as nghttp2 / Go do).
  if n <= 0 or sid notin h2.streams: return
  template st: H2Stream = h2.streams[sid]
  st.pendingWindow += n
  if st.pendingWindow * 2 >= h2.streamRecvWindow:
    c.wbuf.addWindowUpdate(sid, st.pendingWindow)
    st.pendingWindow = 0

proc creditConn(h2: H2Conn, c: ptr Connection, n: int) =
  ## Connection-level counterpart, batched at half the connection window;
  ## accumulates across all streams on the connection.
  if n <= 0: return
  h2.pendingConnWindow += n
  if h2.pendingConnWindow * 2 >= h2.connRecvWindow:
    c.wbuf.addWindowUpdate(0, h2.pendingConnWindow)
    h2.pendingConnWindow = 0

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
      # Auto-ack: consumed on delivery. Replenish both the stream and the
      # connection window (the connection window is credited on consume for
      # streaming bodies, so it bounds total un-consumed upload buffer).
      h2.creditStream(c, sid, buf.len)
      h2.creditConn(c, buf.len)

proc h2AckBody*(c: ptr Connection, sid: uint32, n: int) =
  ## Replenish `n` consumed body bytes of a streaming stream's flow-control
  ## window (req.ackBody). Credits both the stream and the connection window:
  ## for a streaming body the connection window is credited on consumption (not
  ## receipt), so it caps total un-consumed upload buffer across all streams.
  let h2 = h2Conn(c)
  if h2 == nil or sid notin h2.streams or not h2.streams[sid].streamingReq:
    return
  h2.creditStream(c, sid, n)
  h2.creditConn(c, n)

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
    # Trailers: allowed only with END_STREAM. Capture the fields for
    # req.trailers; a pseudo-header in the trailer section is malformed
    # (RFC 9113 8.1), so reject it rather than expose it.
    if not endStream:
      h2.connError(c, errProtocol)
      return
    for (name, val) in fields:
      if name.len == 0 or name[0] == ':':
        h2.streamError(c, sid, errProtocol)
        return
      st.trailers.add (name, val)
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
      # RFC 9113 8.2.1: no field (pseudo or regular) may carry NUL, CR, or LF in
      # its value -- a header-injection / smuggling vector if reflected or
      # proxied to h1. The strict h1 parser rejects these bytes outright.
      for ch in val:
        let b = uint8(ch)
        if b == 0x00'u8 or b == 0x0a'u8 or b == 0x0d'u8:
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
        # RFC 9113 8.2.1: a regular field name must be a valid lowercase token;
        # uppercase, controls, or separators make it malformed (mirrors the h1
        # parser's token check so h2 cannot smuggle a name h1 would reject).
        for ch in name:
          let b = uint8(ch)
          if ch in 'A'..'Z' or b <= 0x20'u8 or b >= 0x7f'u8 or
             ch in h2FieldNameDelims:
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
        of "priority":
          parsePriorityField(val, st.urgency, st.incremental)  # RFC 9218 request signal
        of "content-length":
          var n: BiggestInt
          try:
            n = parseBiggestInt(val)
          except ValueError:
            h2.streamError(c, sid, errProtocol)
            return
          # RFC 9113 8.1.1: a negative length, or a second content-length whose
          # value differs from the first, is malformed. A negative value would
          # also disable the body-length reconciliation below (a smuggling
          # vector when proxied to h1). st.contentLength starts at -1 (unset).
          if n < 0 or (st.contentLength >= 0 and st.contentLength != n):
            h2.streamError(c, sid, errProtocol)
            return
          st.contentLength = n
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

  if fh.typ == ftPriorityUpdate:
    h2.handlePriorityUpdate(c, fh, payloadPos)
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
    # A streaming body's DATA payload has its connection-window credit deferred
    # to consumption (set below); 0 means credit the whole frame eagerly.
    var streamingConnDefer = 0
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
        # stream AND connection flow-control windows are replenished on consume
        # (h2DeliverBody / ackBody), not here, so a slow consumer throttles the
        # peer and the connection window caps total un-consumed buffer; padding
        # is discarded now, so credit its flow-control bytes now.
        if fh.length > dataLen:
          h2.creditStream(c, sid, fh.length - dataLen)
        streamingConnDefer = dataLen    # connection credit deferred to consume
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
    # the others), EXCEPT a streaming body's DATA payload, which is credited on
    # consumption (h2DeliverBody / ackBody) so the connection window bounds the
    # total un-consumed upload buffer across all streams. The stream window is
    # eager too, except a streaming request defers it to consumption likewise.
    if fh.length > 0:
      let connNow = fh.length - streamingConnDefer
      if connNow > 0:
        h2.creditConn(c, connNow)
      if fh.streamId in h2.streams and
          not h2.streams[fh.streamId].endStreamSeen and
          not h2.streams[fh.streamId].streamingReq:
        h2.creditStream(c, fh.streamId, fh.length)

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
        sendWindow: h2.peerInitialWindow, contentLength: -1,
        urgency: defaultUrgency)
      inc h2.activeStreams
      if h2.pendingPriority.len > 0 and sid in h2.pendingPriority:
        h2.h2Reprioritize(sid, h2.pendingPriority[sid])   # buffered PRIORITY_UPDATE
        h2.pendingPriority.del(sid)
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
      # Raising SETTINGS_INITIAL_WINDOW_SIZE grows every stream's send window
      # (RFC 7540 6.9.2): re-enqueue any stream with a backlog and run a pass.
      for sid, st in h2.streams:
        if st.pendingBody.len - st.pendingPos > 0: h2.h2Enqueue(sid)
      h2.h2Schedule(c)

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
      if h2.h2NextUrgency() >= 0 or (wasBlocked and h2.connSendWindow > 0):
        # The connection window moved: run a scheduler pass. The ready-queue
        # already holds the stream-sendable streams, so no scan is needed.
        h2.h2Schedule(c)
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
      h2.h2Enqueue(fh.streamId)
      h2.h2Schedule(c)
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
