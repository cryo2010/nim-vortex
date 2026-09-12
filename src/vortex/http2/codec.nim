## HTTP/2 connection state machine (RFC 9113): frame handling, stream
## lifecycle, both directions of flow control, and response serialization.
## One H2Conn per connection, touched only by the owning loop thread
## (workers respond through the protocol-neutral outbox).

import std/[tables, strutils, json, deques, sets]
import ./frames, ./hpack
import ../connection
import ../fieldrules   # token delimiters + pseudo-header machine shared with
                       # the h1 parser and the h3 backend (no drift)
import ../websocket/codec as wscodec

type
  H2Stream* = object
    headers*: seq[(string, string)]  ## request fields incl. pseudo-headers
    trailers*: seq[(string, string)] ## request trailer fields (after the body)
    respTrailers*: seq[(string, string)] ## response trailers to emit at END_STREAM
    body*: string
    sendWindow*: int32
    recvRemaining*: int              ## bytes the peer may still send into this
                                     ## stream's receive window (we enforce it)
    endStreamSeen*: bool             ## client half-closed
    dispatched*: bool
    isHead*: bool
    headersDone*: bool
    contentLength*: int64            ## -1 unknown; validated vs body
    bodyReceived*: int64             ## cumulative DATA payload bytes received;
                                     ## reconciled against contentLength at
                                     ## END_STREAM even for streaming routes,
                                     ## which do not retain the body (#237)
    rs*: RequestState                ## per-request state shared with h1/h3
                                     ## (responded, lazy caches, pathParams,
                                     ## streaming flags/callbacks)
    pendingBody*: string             ## response bytes awaiting send window
    pendingPos*: int
    pendingIsLast*: bool
    respBackedUp*: bool              ## write() hit the window; onDrain pending
    bodyManualAck*: bool             ## defer stream WINDOW_UPDATE to req.ackBody
    isWsConnect*: bool               ## RFC 8441 Extended CONNECT websocket
    ws*: RootRef                     ## WsConn when this stream is a WebSocket
    pendingWindow*: int              ## consumed bytes not yet returned as a
                                     ## stream WINDOW_UPDATE (batched at half-window)
    bufferedCounted*: int            ## bytes this un-dispatched buffered body
                                     ## currently contributes to H2Conn.bufferedBytes
                                     ## (the per-connection memory cap, #235)
    connDeferred*: int               ## connection-window bytes debited from
                                     ## connRecvRemaining on receipt but not yet
                                     ## returned via creditConn (a streaming
                                     ## body defers its connection credit to
                                     ## consumption). Reclaimed to the connection
                                     ## window on every teardown path so an
                                     ## abnormal end cannot leak the grant and
                                     ## deadlock later uploads (#231).
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
    sawFirstFrame*: bool      ## the first frame after the preface was seen
                              ## (RFC 9113 3.4: it MUST be a SETTINGS frame)
    contStream*: uint32              ## awaiting CONTINUATION for this stream
    contEndStream*: bool
    contRefuse*: uint32              ## if non-zero, the stream now buffering its
                                     ## header block is being REFUSED with this
                                     ## error code: decode the block (keep HPACK
                                     ## in sync) but RST instead of dispatch (#233)
    headerBlock*: string
    lastStreamId*: uint32
    # Streams the SERVER closed while the client was still open (no END_STREAM
    # seen): a client's legally in-flight DATA/trailer HEADERS may race the
    # deletion, so we answer those with RST_STREAM instead of a connection error
    # (#239). A stream the client itself finished (END_STREAM) is NOT recorded --
    # a HEADERS on it is a genuine violation and stays a connection error
    # (RFC 9113 5.1, h2spec 5.1). Bounded FIFO so it cannot grow without limit.
    earlyClosed*: HashSet[uint32]
    earlyClosedQ*: Deque[uint32]
    goingAway*: bool          ## our own drain: final GOAWAY sent, refuse new streams
    drainNoticeSent*: bool    ## initial GOAWAY(2^31-1) sent (graceful drain notice);
                              ## new/racing streams are still processed until the
                              ## final GOAWAY(lastStreamId) sets goingAway
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
    connRecvRemaining*: int   ## bytes the peer may still send at the connection
                              ## level before overrunning the advertised window
    pendingConnWindow*: int   ## consumed bytes not yet returned as a connection
                              ## WINDOW_UPDATE (batched at half-window)
    encTableMax*: int         ## the dynamic-table max our (static-only) encoder
                              ## currently signals to the peer's decoder (starts
                              ## at the HPACK default 4096)
    pendingTableSizeUpdate*: int  ## >=0: emit an HPACK dynamic-table-size-update
                              ## instruction of this value at the start of the
                              ## next response header block (-1 = none), owed when
                              ## the peer lowers SETTINGS_HEADER_TABLE_SIZE (#240.8)
    bufferedBytes*: int       ## total un-dispatched buffered (non-streaming)
                              ## request-body bytes held across all streams. The
                              ## connection receive window credits buffered bodies
                              ## eagerly (a body larger than the window must, or it
                              ## could never arrive), so this independent aggregate
                              ## is what caps per-connection buffered memory (#235).
    # Per-connection write scheduler (RFC 9218): one round-robin ready-queue per
    # urgency level (0 highest .. 7). The scheduler serves the lowest non-empty
    # urgency, popping a stream and emitting one frame; incremental streams
    # re-enqueue at the back (interleave), non-incremental at the front (deliver
    # sequentially, one stream at a time within its level).
    sendQ*: array[8, Deque[uint32]]
    scheduling*: bool         ## reentrancy guard for h2Schedule
    resuming*: bool           ## reentrancy guard for h2ResumeProducers
    backedUpProducers*: int   ## streams with respBackedUp set: lets
                              ## h2ResumeProducers skip the full stream-table
                              ## scan when nothing is parked (the common case).
                              ## Maintained only via setBackedUp/clearBackedUp.
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
  # Index-scan the RFC 8941 dictionary in place: no split/strip/substr/parseInt
  # allocations (this runs per request carrying a `priority` header).
  const ows = {' ', '\t'}
  const sep = {' ', '\t', ','}
  var i = 0
  let n = v.len
  while i < n:
    while i < n and v[i] in sep: inc i             # skip OWS and commas
    if i >= n: break
    let ks = i                                    # member key [ks ..< ke)
    while i < n and v[i] notin ows and v[i] != '=' and v[i] != ',': inc i
    let ke = i
    let isU = ke - ks == 1 and v[ks] == 'u'
    let isI = ke - ks == 1 and v[ks] == 'i'
    while i < n and v[i] in ows: inc i
    if i < n and v[i] == '=':
      inc i
      while i < n and v[i] in ows: inc i
      let vs = i                                  # value [vs ..< ve)
      while i < n and v[i] notin ows and v[i] != ',': inc i
      let ve = i
      if isU:                                     # sf-integer 0..7 (else ignore)
        var num = 0
        var ok = ve > vs
        for k in vs ..< ve:
          if v[k] in '0'..'9' and num <= 7: num = num * 10 + (ord(v[k]) - ord('0'))
          else: ok = false; break
        if ok and num in 0 .. 7: urgency = uint8(num)
      elif isI:                                   # ?1 / anything but ?0 = true
        incremental = not (ve - vs == 2 and v[vs] == '?' and v[vs + 1] == '0')
    elif isI:
      incremental = true                          # bare boolean member = true

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
    connRecvWindow: max(connRecvWindow, int(defaultInitialWindow)),
    connRecvRemaining: max(connRecvWindow, int(defaultInitialWindow)),
    encTableMax: 4096, pendingTableSizeUpdate: -1)

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

const goawayMaxStreamId = 0x7fffffff'u32
  ## RFC 9113 6.8: the initial graceful-shutdown GOAWAY uses the maximum stream
  ## id so the peer keeps processing in-flight/racing streams until the final
  ## GOAWAY carries the real last-accepted id.

proc h2GoawayNotice*(c: ptr Connection) =
  ## Step 1 of the RFC 9113 6.8 two-step graceful drain (as Go/Node do): send
  ## GOAWAY(2^31-1, NO_ERROR) as a shutdown *notice*. It does NOT set goingAway,
  ## so streams already on the wire (and new ones during the grace window) are
  ## still accepted and completed; h2Goaway later sends the real cutoff.
  let h2 = h2Conn(c)
  if h2 == nil or h2.goingAway or h2.drainNoticeSent: return
  h2.drainNoticeSent = true
  c.wbuf.addGoaway(goawayMaxStreamId, 0'u32)

proc h2Goaway*(c: ptr Connection) =
  ## Step 2 (or the immediate cutoff): refuse new streams (RFC 9113 6.8) and send
  ## GOAWAY(NO_ERROR) up to the last accepted stream. Existing streams finish.
  let h2 = h2Conn(c)
  if h2 == nil or h2.goingAway: return
  h2.goingAway = true
  c.wbuf.addGoaway(h2.lastStreamId, 0'u32)

proc creditConn(h2: H2Conn, c: ptr Connection, n: int) {.gcsafe, raises: [].}

const maxEarlyClosed = 256
  ## Cap on remembered server-early-closed stream ids (bounds the racing-frame
  ## tolerance window; a flood of new streams evicts old entries FIFO).

proc recordEarlyClosed(h2: H2Conn, sid: uint32) {.raises: [].} =
  ## Remember `sid` as closed by the server while the client was still open, so a
  ## racing frame gets RST_STREAM (tolerated) rather than a connection error (#239).
  if sid in h2.earlyClosed: return
  h2.earlyClosed.incl sid
  h2.earlyClosedQ.addLast sid
  if h2.earlyClosedQ.len > maxEarlyClosed:
    h2.earlyClosed.excl h2.earlyClosedQ.popFirst()

proc setBackedUp(h2: H2Conn, st: var H2Stream) {.inline.} =
  ## Mark a stream's producer parked and keep h2.backedUpProducers exact.
  ## Idempotent: a re-mark does not double-count.
  if not st.respBackedUp:
    st.respBackedUp = true
    inc h2.backedUpProducers

proc clearBackedUp(h2: H2Conn, st: var H2Stream) {.inline.} =
  ## Clear the parked flag (resume, finish, or teardown) and keep the counter
  ## exact. Idempotent, so every teardown path can call it unconditionally.
  if st.respBackedUp:
    st.respBackedUp = false
    dec h2.backedUpProducers

proc teardownStream(h2: H2Conn, c: ptr Connection, sid: uint32) {.gcsafe, raises: [].} =
  ## The single stream-removal primitive for every teardown path (normal
  ## completion, RST_STREAM in either direction, stream error, connection
  ## close). It reconciles outstanding flow-control credit and fires any parked
  ## handler callbacks so no path leaks a connection-window grant (#231) or
  ## strands an async handler (#232):
  ##   * return the stream's un-credited connection-window bytes (connDeferred)
  ##     so an abnormal end cannot drain connRecvRemaining and deadlock later
  ##     uploads on the connection;
  ##   * deliver onClose (1006) to a live WebSocket;
  ##   * deliver onBodyCb(last=true) to a streaming request sink, so a handler
  ##     suspended in await req.read() resumes at EOF and its reader-table entry
  ##     is released instead of leaking;
  ##   * fire a parked onRespDrain so a producer suspended in await res.drained()
  ##     wakes and runs its finally/defer cleanup.
  ## The stream is removed BEFORE the callbacks run, so a callback that responds
  ## (res.send/res.write) sees the stream already gone and cannot double-delete
  ## or double-decrement activeStreams.
  # withValue (not h2.streams[sid]) so this stays raises:[] -- the Table `[]`
  # accessor raises KeyError, which would flag the whole res.send path in the
  # strict-effect async build even behind the membership guard.
  var w: WsConn = nil
  var bodyCb: BodyCb = nil
  var drainCb: RespDrainCb = nil
  h2.streams.withValue(sid, st):
    if not st.endStreamSeen:
      # Closed with the client still sending: its in-flight frames may race this
      # deletion, so remember the id to answer them with RST rather than GOAWAY.
      h2.recordEarlyClosed(sid)
    if st.connDeferred > 0:
      h2.creditConn(c, st.connDeferred)
      st.connDeferred = 0
    if st.bufferedCounted > 0:            # release its buffered-memory reservation
      h2.bufferedBytes -= st.bufferedCounted
      st.bufferedCounted = 0
    if st.ws != nil:
      w = WsConn(st.ws)
      st.ws = nil
    bodyCb = st.rs.onBodyCb
    st.rs.onBodyCb = nil
    drainCb = st.rs.onRespDrain
    st.rs.onRespDrain = nil
    clearBackedUp(h2, st[])               # drop from the parked-producer count
  do:
    return                                # not present (already gone)
  h2.streams.del(sid)
  dec h2.activeStreams
  # teardownStream is reachable from the normal res.send path (h2Respond ->
  # h2Schedule -> teardownStream), which in the strict-effect async build must be
  # raises:[]. The user callbacks are unannotated (raises: [Exception]), so
  # contain Exception (not just CatchableError) at every call, as h2ResumeProducers
  # does -- otherwise res.send is flagged "can raise an unlisted exception".
  if w != nil:
    try: wsStreamClosed(h2.core, c, w)
    except Exception: discard
  if bodyCb != nil:
    var empty: string
    try: bodyCb(toOpenArray(empty, 0, -1), true)
    except Exception: discard
  if drainCb != nil:
    try: drainCb(h2.core, c.fd, c.gen, sid)
    except Exception: discard

proc streamError(h2: H2Conn, c: ptr Connection, sid: uint32, err: uint32) =
  # RFC 9113 5.1 forbids RST_STREAM on an idle stream id (one never opened): a
  # peer must treat RST-on-idle as a connection PROTOCOL_ERROR. Only emit the
  # reset for an id we have actually seen (<= lastStreamId); an idle-id caller
  # (e.g. a self-dependency PRIORITY on stream 2^n never opened) just tears down
  # whatever is present (nothing) without an illegal reset.
  if sid != 0 and sid <= h2.lastStreamId:
    c.wbuf.addRstStream(sid, err)
  h2.teardownStream(c, sid)

proc noteControlFrame(h2: H2Conn, c: ptr Connection, n = 1) =
  ## Budget control/overhead frames (PING incl. ACK, SETTINGS per entry,
  ## WINDOW_UPDATE / PRIORITY / GOAWAY / unknown types, and every RST_STREAM we
  ## emit in reply to a flood). `n` charges an amplifying frame per unit of work
  ## it forces (e.g. SETTINGS charges per entry). A real request only *decays*
  ## the counter (noteControlProgress), so a genuine few-frames-per-request ratio
  ## never trips while a flood with negligible real progress does.
  h2.controlFrameCount += n
  if h2.maxControlFrames > 0 and h2.controlFrameCount > h2.maxControlFrames:
    h2.connError(c, errEnhanceYourCalm)

proc noteControlProgress(h2: H2Conn) =
  ## An accepted request partially forgives the control-frame budget instead of
  ## zeroing it. Zeroing made maxControlFrames a per-request ratio (interleaving
  ## one minimal request per ~maxControlFrames control frames sustained a flood
  ## forever); a bounded decay caps the sustained ratio instead (#234).
  if h2.maxControlFrames <= 0: return
  let forgive = max(1, h2.maxControlFrames div 10)
  h2.controlFrameCount = max(0, h2.controlFrameCount - forgive)

# --- response serialization ------------------------------------------------

proc encodeExtraHeader(hb: var string, name, val: string) =
  ## Encode one handler-supplied response header, dropping the connection-
  ## specific fields RFC 9113 8.2.2 forbids an h2 endpoint from generating
  ## (connection, keep-alive, transfer-encoding, upgrade, proxy-connection). A
  ## strict client (nghttp2-based, browsers) treats a response carrying them as
  ## malformed and cancels the stream, so h1-portable handler code would break on
  ## h2. The inbound direction is already filtered; this closes the outbound gap
  ## (#240.3). Names are lowercased to h2 wire form regardless.
  ##
  ## The forbidden-set check is allocation-free (eqIgnoreAsciiCase), and the
  ## `toLowerAscii` copy is taken only when the name is not already lowercase --
  ## an h2-aware handler using lowercase names then pays no per-header alloc.
  if isForbiddenResponseField(name):             # shared set (fieldrules), also h1/h3
    return
  if isLowerAscii(name): encodeHeader(hb, name, val)
  else: encodeHeader(hb, name.toLowerAscii, val)

proc emitTableSizeUpdate(h2: H2Conn, hb: var string) =
  ## Prepend a pending HPACK dynamic-table-size-update instruction (RFC 7541
  ## 4.2) to a response header block. Our encoder is static-only, but when the
  ## peer lowers SETTINGS_HEADER_TABLE_SIZE the decoder still requires us to
  ## signal the reduced maximum before the next block, or it raises
  ## COMPRESSION_ERROR (nghttp2 does when the peer sets it to 0). Emitted once,
  ## by whichever header block is serialized first after the change (#240.8).
  if h2.pendingTableSizeUpdate >= 0:
    encodeInt(hb, h2.pendingTableSizeUpdate, 5, 0x20)
    h2.pendingTableSizeUpdate = -1

proc emitTrailers(h2: H2Conn, c: ptr Connection, sid: uint32) =
  ## Emit a streamed response's trailer section as a trailing HEADERS frame
  ## carrying END_STREAM, then drop the stream. Called once the response body
  ## has fully drained; HEADERS are not flow-controlled, so this always fits.
  if sid notin h2.streams: return
  template st: H2Stream = h2.streams[sid]
  var hb = ""
  h2.emitTableSizeUpdate(hb)
  for (name, val) in st.respTrailers:
    encodeExtraHeader(hb, name, val)
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
  h2.teardownStream(c, sid)

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
        h2.teardownStream(c, sid)
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
    h2.teardownStream(c, sid)
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
    # Do NOT RST_STREAM(CANCEL) a close just because a send window is exhausted.
    # A later WINDOW_UPDATE resumes the drain via h2Enqueue, and connSendWindow
    # can be drained by an entirely unrelated stream -- cancelling here dropped
    # the queued frames and the close frame for a merely-slow peer. Leave them to
    # drain gracefully; a genuinely stuck stream is reaped by the body deadline
    # (a ws stream has no END_STREAM, so h2AwaitingClient arms it, #236) or the
    # WebSocket ping/pong idle timeout (#240.9).

proc h2ResumeProducers(h2: H2Conn, c: ptr Connection) =
  ## Resume streamed-response producers parked on the connection write-buffer
  ## cap (respHighWater), now that a scheduler pass or a socket drain left room.
  ## A parked producer's frames have already been emitted, so its backlog is
  ## empty and it is NOT in the ready-queue -- only this scan finds it. Collect
  ## ids first (an onRespDrain callback may res.write and mutate the table) and
  ## stop early if a resumed producer refills the buffer.
  if h2.resuming: return
  if h2.backedUpProducers == 0: return   # nothing parked: skip the table scan
  if pendingOut(c) >= respHighWater: return
  h2.resuming = true
  var resumable: seq[uint32]
  for sid in h2.streams.keys:
    template st: H2Stream = h2.streams[sid]
    if st.respBackedUp and st.rs.onRespDrain != nil and
       st.pendingBody.len - st.pendingPos < respHighWater:
      resumable.add sid
  for sid in resumable:
    if pendingOut(c) >= respHighWater: break
    if sid notin h2.streams: continue
    template st: H2Stream = h2.streams[sid]
    if not st.respBackedUp or st.rs.onRespDrain == nil: continue
    clearBackedUp(h2, st)
    let cb = st.rs.onRespDrain
    st.rs.onRespDrain = nil            # fire once; the producer re-registers if it
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
    setBackedUp(h2, h2.streams[sid])

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
  if sid notin h2.streams or h2.streams[sid].rs.responded: return
  template st: H2Stream = h2.streams[sid]
  st.rs.responded = true
  st.rs.respStreaming = true
  if st.isHead:
    st.pendingIsLast = true            # HEAD: headers only, close the stream
  var hb = ""
  h2.emitTableSizeUpdate(hb)
  encodeStatus(hb, code)
  if serverHeader.len > 0:
    encodeHeader(hb, "server", serverHeader)
  encodeHeader(hb, "date", dateStr)
  if contentType.len > 0:
    encodeHeader(hb, "content-type", contentType)
  if altSvc.len > 0:
    encodeHeader(hb, "alt-svc", altSvc)
  for (name, val) in extraHeaders:
    encodeExtraHeader(hb, name, val)
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
    h2.teardownStream(c, sid)

proc h2StreamWrite*(c: ptr Connection, sid: uint32,
                    data: openArray[char]): int =
  ## Append a body chunk to a streamed response and push it bounded by flow
  ## control. Returns the unsent backlog (pending body bytes) for backpressure.
  let h2 = h2Conn(c)
  if h2 == nil or sid notin h2.streams or not h2.streams[sid].rs.respStreaming:
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
  if h2 == nil or sid notin h2.streams or not h2.streams[sid].rs.respStreaming:
    return
  template st: H2Stream = h2.streams[sid]
  st.rs.respStreaming = false
  st.rs.onRespDrain = nil
  clearBackedUp(h2, st)            # finished: never let a drain path resume it
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
    h2.teardownStream(c, sid)

proc h2StreamAbort*(c: ptr Connection, sid: uint32) =
  ## Abort a streamed response mid-body: RST_STREAM(INTERNAL_ERROR) so the peer
  ## sees the transfer was cut short, not cleanly completed. No-op unless the
  ## stream is an open streamed response.
  let h2 = h2Conn(c)
  if h2 == nil or sid notin h2.streams or not h2.streams[sid].rs.respStreaming:
    return
  h2.streams[sid].rs.respStreaming = false
  h2.streams[sid].rs.onRespDrain = nil
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
  ## Deliver a final onBody(last=true) AND fire any parked onRespDrain for every
  ## stream still open when the connection died, so a handler suspended in
  ## await req.read() (consumer) or await res.drained() (producer) resumes and
  ## its Future / reader-table entry / finally-cleanup runs instead of leaking a
  ## zombie coroutine. Loop thread; called from closeConn. No flow-control credit
  ## is reconciled here -- the connection (and its windows) are being torn down.
  if c.h2 == nil: return
  let h2 = H2Conn(c.h2)
  # Snapshot and detach the callbacks BEFORE firing any, so a callback that
  # responds (res.write/res.send mutating the streams table) cannot invalidate
  # the iterator we are walking.
  var bodyCbs: seq[(uint32, BodyCb)]
  var drainCbs: seq[(uint32, RespDrainCb)]
  for sid, st in h2.streams.mpairs:
    if st.rs.onBodyCb != nil:
      bodyCbs.add (sid, st.rs.onBodyCb)
      st.rs.onBodyCb = nil
    if st.rs.onRespDrain != nil:
      drainCbs.add (sid, st.rs.onRespDrain)
      st.rs.onRespDrain = nil
  var empty: string
  for (sid, cb) in bodyCbs:
    try: cb(toOpenArray(empty, 0, -1), true)
    except CatchableError: discard
  for (sid, cb) in drainCbs:
    # onRespDrain wraps an unannotated user producer (raises: [Exception]); catch
    # Exception so the connection-close path stays raises:[] under strict-effect
    # async (as teardownStream / h2ResumeProducers do).
    try: cb(h2.core, c.fd, c.gen, sid)
    except Exception: discard

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
  if not st.isWsConnect or st.rs.responded or st.ws != nil: return false
  st.rs.responded = true
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
  h2.emitTableSizeUpdate(hb)
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
                body: openArray[char], altSvc = "",
                secHeaders: openArray[(string, string)] = []) =
  let h2 = h2Conn(c)
  if sid notin h2.streams: return
  if h2.streams[sid].rs.responded: return
  h2.streams[sid].rs.responded = true
  let skipBody = h2.streams[sid].isHead
  let bodiless = bodilessStatus(code)
  var hb = ""
  h2.emitTableSizeUpdate(hb)
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
    encodeExtraHeader(hb, name, val)
  for (name, val) in secHeaders:               # OWASP baseline; app header wins
    var shadowed = false
    for (hn, _) in extraHeaders:
      if cmpIgnoreCase(hn, name) == 0: shadowed = true; break
    if not shadowed: encodeExtraHeader(hb, name, val)
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
    h2.teardownStream(c, sid)
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
  if h2 == nil or sid notin h2.streams or h2.streams[sid].rs.responded: return
  var hb = ""
  h2.emitTableSizeUpdate(hb)
  encodeStatus(hb, code)
  for (name, val) in headers:
    encodeExtraHeader(hb, name, val)
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
    st.recvRemaining += st.pendingWindow   # window grows by what we just granted
    st.pendingWindow = 0

proc creditConn(h2: H2Conn, c: ptr Connection, n: int) {.gcsafe, raises: [].} =
  ## Connection-level counterpart, batched at half the connection window;
  ## accumulates across all streams on the connection.
  if n <= 0: return
  h2.pendingConnWindow += n
  if h2.pendingConnWindow * 2 >= h2.connRecvWindow:
    c.wbuf.addWindowUpdate(0, h2.pendingConnWindow)
    h2.connRecvRemaining += h2.pendingConnWindow  # window grows by the grant
    h2.pendingConnWindow = 0

proc creditConnFor(h2: H2Conn, c: ptr Connection, sid: uint32, n: int) =
  ## Credit `n` connection-window bytes attributed to stream `sid`'s deferred
  ## body (streaming consume / manual ack) and drop them from the stream's
  ## outstanding tally, so a later teardownStream does not credit them a second
  ## time. Only for connection credit that was deferred (tracked in
  ## connDeferred); eager framing-overhead credit uses creditConn directly.
  if n <= 0: return
  if sid in h2.streams:
    template st: H2Stream = h2.streams[sid]
    st.connDeferred -= min(n, st.connDeferred)
  h2.creditConn(c, n)

# --- inbound streaming (req.onBody) -----------------------------------------

proc h2DeliverBody(h2: H2Conn, c: ptr Connection, sid: uint32, last: bool) =
  ## Hand buffered request-body bytes to a streaming stream's onBody and clear
  ## the buffer (bounded memory). No-op until the handler registers onBody.
  ## For the auto-ack default, replenish the stream flow-control window by the
  ## delivered bytes once the callback returns; manualAck leaves it to
  ## req.ackBody so a slow consumer throttles the peer.
  if sid notin h2.streams: return
  template st: H2Stream = h2.streams[sid]
  if st.rs.onBodyCb == nil: return
  if st.body.len > 0 or last:
    # The callback may res.send (deleting this stream from the table), so move
    # the buffer out and clear it *before* the call, and touch nothing on `st`
    # afterwards.
    let cb = st.rs.onBodyCb
    let manualAck = st.bodyManualAck
    var buf: string
    swap(buf, st.body)
    if not manualAck and buf.len > 0:
      # Auto-ack consumes on delivery: drop these bytes from the deferred
      # connection-window tally NOW, before cb (which may res.send and delete
      # the stream), so a teardown triggered inside cb won't also credit them.
      st.connDeferred -= min(buf.len, st.connDeferred)
    cb(buf.toOpenArray(0, buf.len - 1), last)
    if not manualAck and buf.len > 0:
      # Replenish both the stream and the connection window (the connection
      # window is credited on consume for streaming bodies, so it bounds total
      # un-consumed upload buffer). creditStream is a no-op if cb deleted the
      # stream; the connection credit is global and still owed regardless.
      h2.creditStream(c, sid, buf.len)
      h2.creditConn(c, buf.len)

proc h2AckBody*(c: ptr Connection, sid: uint32, n: int) =
  ## Replenish `n` consumed body bytes of a streaming stream's flow-control
  ## window (req.ackBody). Credits both the stream and the connection window:
  ## for a streaming body the connection window is credited on consumption (not
  ## receipt), so it caps total un-consumed upload buffer across all streams.
  let h2 = h2Conn(c)
  if h2 == nil or sid notin h2.streams or not h2.streams[sid].rs.reqStreaming:
    return
  h2.creditStream(c, sid, n)
  h2.creditConnFor(c, sid, n)   # drops n from connDeferred, then credits conn

proc h2SetOnBody*(c: ptr Connection, sid: uint32, cb: BodyCb,
                  manualAck = false) =
  ## request.onBody for HTTP/2: store the sink on the stream and flush whatever
  ## body already arrived before the handler ran (with last=true if the peer
  ## already half-closed).
  let h2 = h2Conn(c)
  if h2 == nil or sid notin h2.streams: return
  h2.streams[sid].rs.onBodyCb = cb
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
      # A malformed request is a STREAM error (RFC 9113 8.1, as Go's http2
      # does), not a connection teardown that would abort every concurrent
      # request on the connection (#239).
      h2.streamError(c, sid, errProtocol)
      return
    for (name, val) in fields:
      # RFC 9113 8.2.1 applies the field-validity rules to the trailer section
      # too, but the HPACK decoder does no byte validation. Without this a
      # trailer value could carry CR/LF/NUL (header injection / response
      # splitting if logged, reflected, or relayed to an h1 upstream) or a
      # non-token / uppercase name, or a connection-specific field (#238).
      # Shared rule (fieldrules.validTrailerField, also the h3 backend's).
      if not validTrailerField(name, val):
        h2.streamError(c, sid, errProtocol)
        return
      st.trailers.add (name, val)
    st.endStreamSeen = true
    if st.rs.reqStreaming and st.dispatched:
      # A streaming route consumed the DATA via onBody as it arrived; the
      # trailers carry no body, but the sink still needs its terminating
      # last=true callback (otherwise the handler hangs and the stream leaks).
      # Reconcile content-length first (END_STREAM arriving via a trailer
      # section, #237); h2DeliverBody may res.send and delete the stream.
      if st.contentLength >= 0 and st.bodyReceived != st.contentLength:
        h2.streamError(c, sid, errProtocol)
        return
      h2.h2DeliverBody(c, sid, true)
      return
    # A buffered route falls through: the dispatch tail runs the handler now
    # that endStreamSeen is set.
  else:
    # Shared machine (fieldrules.classifyRequestHead, also the h3 backend's):
    # pseudo-header dedup/ordering, unknown pseudo names, field name/value
    # byte validation (RFC 9113 8.2.1), the authority-or-Host rule
    # (RFC 9113 8.3.1), and RFC 8441 Extended CONNECT classification (the
    # stream stays open for WebSocket framing after dispatch).
    var meth, path, scheme, authority, protocol: string
    let klass = classifyRequestHead(fields, meth, path, scheme, authority,
                                    protocol)
    if klass == rhInvalid:
      h2.streamError(c, sid, errProtocol)
      return
    st.isWsConnect = klass == rhWebSocket
    # h2-local concerns: header-list size accounting, connection-specific
    # field bans (RFC 9113 8.2.2), and content-length capture.
    var listSize = 0
    for (name, val) in fields:
      listSize += name.len + val.len + 32
      if name[0] == ':': continue        # pseudo-headers validated above
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
        # RFC 9110 8.6 (1*DIGIT, digits-only so a '+'/'-' or Nim underscore a
        # re-serializing proxy reads differently can't smuggle) + RFC 9113 8.1.1
        # (non-negative, no duplicate-with-different value). st.contentLength
        # starts at -1 (unset). Shared grammar (fieldrules, also h1/h3) (#240.6).
        var n: int64
        case parseContentLength(val, st.contentLength, n)
        of clOk: st.contentLength = n
        else:
          h2.streamError(c, sid, errProtocol)
          return
      else: discard
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
      st.rs.reqStreaming = true          # dispatch on headers; DATA -> onBody
  if st.isWsConnect and not st.dispatched:
    # Dispatch as soon as the headers are in; DATA becomes WebSocket framing.
    st.dispatched = true
    ready.add sid
  elif st.rs.reqStreaming and not st.dispatched:
    # Streaming route: run the handler now so it can register req.onBody; the
    # body is delivered as DATA frames arrive.
    st.dispatched = true
    ready.add sid
  elif st.endStreamSeen and not st.dispatched:
    # Dispatched (END_STREAM reached here, e.g. on the initial HEADERS or via a
    # trailer section): release any un-dispatched buffered-body reservation (#235).
    if st.bufferedCounted > 0:
      h2.bufferedBytes -= st.bufferedCounted
      st.bufferedCounted = 0
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
    # Unknown frame types are ignored (RFC 9113 4.1) but still cost a parse and
    # are pure overhead: budget them so a flood trips ENHANCE_YOUR_CALM (#234).
    h2.noteControlFrame(c)
    return

  case FrameType(fh.typ)
  of ftData:
    let sid = fh.streamId
    if sid == 0: h2.connError(c, errProtocol); return
    # An even stream id is server-initiated (push) space the client may never
    # use, so it is permanently idle. A frame on it (like any frame on an idle
    # stream) is a connection PROTOCOL_ERROR (RFC 9113 5.1) -- the `> lastStreamId`
    # check alone misses even ids below the high-water mark (#240.1).
    if (sid and 1'u32) == 0: h2.connError(c, errProtocol); return
    if sid > h2.lastStreamId:
      h2.connError(c, errProtocol)   # DATA on an idle stream
      return
    # Enforce the RECEIVE flow-control window we advertised (RFC 9113 6.9): the
    # entire DATA payload counts against both windows, even on a stream in error.
    # A peer that overruns the window is a FLOW_CONTROL_ERROR -- connection-level
    # for the connection window, stream-level for the stream (matching Go's
    # inflow.take / nghttp2). Credit is returned by creditStream/creditConn.
    if fh.length > 0:
      h2.connRecvRemaining -= fh.length
      if h2.connRecvRemaining < 0: h2.connError(c, errFlowControl); return
      if sid in h2.streams:
        h2.streams[sid].recvRemaining -= fh.length
        if h2.streams[sid].recvRemaining < 0:
          # Stream-window overrun: RST this stream but return its connection-window
          # bytes (this branch returns before the eager credit below, so record
          # them as deferred and let teardownStream reclaim them -- #231).
          h2.streams[sid].connDeferred += fh.length
          h2.streamError(c, sid, errFlowControl); return
    # Flow control applies to the whole payload regardless of validity.
    # A streaming body's DATA payload has its connection-window credit deferred
    # to consumption (set below); 0 means credit the whole frame eagerly.
    var streamingConnDefer = 0
    if sid notin h2.streams or h2.streams[sid].endStreamSeen or
        not h2.streams[sid].headersDone:
      # DATA on a closed / half-closed(remote) / never-headered stream: each
      # small frame elicits a RST_STREAM reply, so budget it as overhead (a
      # non-reading peer would otherwise grow wbuf without bound) -- #234.
      h2.noteControlFrame(c)
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
      elif st.rs.reqStreaming:
        # Inbound streaming: hand DATA to onBody and clear (bounded memory);
        # no content-length reconciliation since the body is not retained. The
        # stream AND connection flow-control windows are replenished on consume
        # (h2DeliverBody / ackBody), not here, so a slow consumer throttles the
        # peer and the connection window caps total un-consumed buffer; padding
        # is discarded now, so credit its flow-control bytes now.
        if fh.length > dataLen:
          h2.creditStream(c, sid, fh.length - dataLen)
        streamingConnDefer = dataLen    # connection credit deferred to consume
        st.connDeferred += dataLen      # owed back on consume / at teardown (#231)
        st.bodyReceived += dataLen      # for content-length reconciliation (#237)
        if dataLen > 0:
          let old = st.body.len
          st.body.setLen(old + dataLen)
          copyMem(addr st.body[old], addr c.rbuf[dataStart], dataLen)
        let endS = (fh.flags and flagEndStream) != 0
        if endS:
          st.endStreamSeen = true
          # A streaming route does not retain the body, but the declared
          # content-length must still match the DATA received (RFC 9113 8.1.1):
          # a mismatch desynchronizes an h1 upstream if the request is forwarded
          # (smuggling). Fail the stream instead of delivering a clean last=true.
          if st.contentLength >= 0 and st.bodyReceived != st.contentLength:
            h2.streamError(c, sid, errProtocol)
          else:
            h2.h2DeliverBody(c, sid, true)
        else:
          h2.h2DeliverBody(c, sid, false)
      else:
        let old = st.body.len
        st.body.setLen(old + dataLen)
        if dataLen > 0:
          copyMem(addr st.body[old], addr c.rbuf[dataStart], dataLen)
        # A buffered body is retained (not consumed on receipt) until END_STREAM
        # dispatch, and its connection-window bytes are credited eagerly (a body
        # larger than the window must be, or it could never arrive). So the
        # window does NOT bound buffered memory; an independent per-connection
        # aggregate does. cap >= maxBody, so any single upload fits; concurrent
        # trickled bodies that together exceed it get the offender REFUSED_STREAM
        # (retryable) instead of pinning ~2 GiB (#235).
        st.bufferedCounted += dataLen
        h2.bufferedBytes += dataLen
        if h2.bufferedBytes > max(h2.connRecvWindow, h2.maxBody):
          h2.streamError(c, sid, errRefusedStream)
        elif (fh.flags and flagEndStream) != 0:
          st.endStreamSeen = true
          # Dispatched now: it leaves the un-dispatched aggregate (the handler
          # will consume st.body and complete). Release its reservation.
          h2.bufferedBytes -= st.bufferedCounted
          st.bufferedCounted = 0
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
          not h2.streams[fh.streamId].rs.reqStreaming:
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
    var selfDep = false
    if (fh.flags and flagPriority) != 0:
      if fragLen < 5: h2.connError(c, errFrameSize); return
      selfDep = (get32(c.rbuf, fragStart) and 0x7fffffff'u32) == sid
      fragStart += 5
      fragLen -= 5
    # A stream can be REFUSED (self-dependency, graceful drain, or the
    # concurrency cap) without tearing the connection down. RFC 9113 4.3 still
    # requires the field block to be HPACK-decoded even when discarded, or the
    # server's dynamic table desyncs from the client's encoder; and the refused
    # id must advance lastStreamId and track CONTINUATION so legally-pipelined
    # frames behind it are not mistaken for idle-stream connection errors (#233).
    # So: buffer + decode the block as usual, then RST with this code instead of
    # dispatching -- never create the stream or reset the flood budget for it.
    var refuseErr = 0'u32
    if sid in h2.streams:
      if not h2.streams[sid].headersDone:
        h2.connError(c, errProtocol); return   # HEADERS while mid-request
      if h2.streams[sid].endStreamSeen:
        # HEADERS on a half-closed(remote) stream: RFC 9113 5.1 mandates a
        # STREAM error STREAM_CLOSED, not a connection teardown (#239).
        h2.streamError(c, sid, errStreamClosed); return
      # else: trailers (allowed); the deprecated priority flag is ignored
    elif sid <= h2.lastStreamId:
      if sid in h2.earlyClosed:
        # The server closed this stream early (final response before the client
        # finished) and the client's legally in-flight HEADERS raced the
        # deletion. Decode the block (keep HPACK in sync for the client's other
        # streams) and answer RST_STREAM(STREAM_CLOSED) rather than GOAWAY-ing
        # every concurrent request for correct client behavior (#239). Do NOT
        # advance lastStreamId.
        h2.earlyClosed.excl sid
        refuseErr = errStreamClosed
      else:
        # A stream the client itself finished (END_STREAM), or an id below the
        # high-water mark that was never opened: a HEADERS here is a genuine
        # violation -> connection error STREAM_CLOSED (RFC 9113 5.1, h2spec 5.1).
        h2.connError(c, errStreamClosed); return
    else:
      if selfDep:
        # RFC 7540 5.3.1: self-dependency is a stream error PROTOCOL_ERROR.
        refuseErr = errProtocol
      elif h2.goingAway:
        refuseErr = errRefusedStream
      elif h2.maxConcurrentStreams > 0 and
          h2.activeStreams >= h2.maxConcurrentStreams:
        refuseErr = errRefusedStream
      h2.lastStreamId = sid
      if refuseErr == 0:
        h2.streams[sid] = H2Stream(
          sendWindow: h2.peerInitialWindow, contentLength: -1,
          recvRemaining: h2.streamRecvWindow, urgency: defaultUrgency)
        inc h2.activeStreams
        if h2.pendingPriority.len > 0 and sid in h2.pendingPriority:
          h2.h2Reprioritize(sid, h2.pendingPriority[sid])   # buffered PRIORITY_UPDATE
          h2.pendingPriority.del(sid)
        h2.noteControlProgress()     # a real request: decay the flood budget
    h2.headerBlock.setLen(fragLen)
    if fragLen > 0:
      copyMem(addr h2.headerBlock[0], addr c.rbuf[fragStart], fragLen)
    if (fh.flags and flagEndHeaders) != 0:
      h2.finishHeaders(c, sid, (fh.flags and flagEndStream) != 0, ready)
      # finishHeaders decoded the block; a refused stream is not in the table so
      # it returned without dispatching. Budget the refusal (overhead) then RST
      # it. Skip if decoding or the budget already tore the connection down.
      if refuseErr != 0 and c.state != csClosing:
        h2.noteControlFrame(c)
        if c.state != csClosing: h2.streamError(c, sid, refuseErr)
    else:
      h2.contStream = sid
      h2.contEndStream = (fh.flags and flagEndStream) != 0
      h2.contRefuse = refuseErr

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
    let hbOld = h2.headerBlock.len
    h2.headerBlock.setLen(hbOld + fh.length)
    if fh.length > 0:
      copyMem(addr h2.headerBlock[hbOld], addr c.rbuf[payloadPos], fh.length)
    if (fh.flags and flagEndHeaders) != 0:
      let sid = h2.contStream
      h2.contStream = 0
      let refuse = h2.contRefuse
      h2.contRefuse = 0
      h2.finishHeaders(c, sid, h2.contEndStream, ready)
      if refuse != 0 and c.state != csClosing:   # decoded above; now refuse (#233/#239)
        h2.noteControlFrame(c)
        if c.state != csClosing: h2.streamError(c, sid, refuse)

  of ftSettings:
    if fh.streamId != 0: h2.connError(c, errProtocol); return
    if (fh.flags and flagAck) != 0:
      if fh.length != 0: h2.connError(c, errFrameSize)
      return
    if fh.length mod 6 != 0: h2.connError(c, errFrameSize); return
    # Charge per setting entry, not per frame: a single 16 KiB SETTINGS carries
    # ~2730 INITIAL_WINDOW_SIZE entries, each rewriting every open stream's send
    # window (O(entries x streams)). One budget unit per frame let that amplify
    # for free (#234).
    h2.noteControlFrame(c, max(1, fh.length div 6))
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
      of setHeaderTableSize:
        # Our encoder is static-only (no dynamic entries), but RFC 7541 4.2 still
        # requires signaling a reduced maximum to the peer's decoder. Cap our
        # signalled max at the peer's value; when it drops, owe a size-update
        # instruction on the next header block (#240.8).
        let newMax = min(int(value), 4096)
        if newMax != h2.encTableMax:
          h2.encTableMax = newMax
          h2.pendingTableSizeUpdate = newMax
      else: discard
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
    # Budget PING AND its ACK: a PING-ACK flood (we never solicit one) is pure
    # overhead that the ACK-only guard used to let through unbudgeted (#234).
    h2.noteControlFrame(c)
    if c.state == csClosing: return
    if (fh.flags and flagAck) == 0:
      c.wbuf.addPingAck(c.rbuf.toOpenArray(payloadPos, payloadPos + 7))

  of ftWindowUpdate:
    if fh.length != 4: h2.connError(c, errFrameSize); return
    if fh.streamId != 0 and (fh.streamId and 1'u32) == 0:
      h2.connError(c, errProtocol); return   # even id = idle push stream (#240.1)
    let inc32 = get32(c.rbuf, payloadPos) and 0x7fffffff'u32
    if inc32 == 0:
      # A WINDOW_UPDATE referencing an idle stream (never opened) is a
      # connection-level PROTOCOL_ERROR (RFC 9113 5.1), like any frame on an
      # idle stream -- check that before the stream-scoped 0-increment error, so
      # id > lastStreamId GOAWAYs instead of RST-ing a stream that never existed.
      if fh.streamId == 0 or fh.streamId > h2.lastStreamId:
        h2.connError(c, errProtocol)
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
    else:
      # Closed stream (<= lastStreamId, no longer in the table): the update is
      # ignored, but a flood of them is pure overhead -- budget it (#234).
      h2.noteControlFrame(c)

  of ftRstStream:
    if fh.streamId == 0: h2.connError(c, errProtocol); return
    if fh.length != 4: h2.connError(c, errFrameSize); return
    if (fh.streamId and 1'u32) == 0:
      h2.connError(c, errProtocol); return   # even id = idle push stream (#240.1)
    if fh.streamId > h2.lastStreamId:
      h2.connError(c, errProtocol); return   # RST on idle stream
    if fh.streamId in h2.streams:
      # Unified teardown: reclaim deferred connection-window credit (#231),
      # deliver onClose to a WebSocket, and fire onBodyCb(last=true) /
      # onRespDrain so a handler suspended in await req.read()/res.drained()
      # resumes instead of leaking a zombie coroutine (#232).
      h2.teardownStream(c, fh.streamId)
    # Rapid Reset (CVE-2023-44487): a peer that opens then immediately
    # resets streams costs handler work while never holding concurrency.
    # Cap cumulative resets per connection.
    inc h2.rstStreamCount
    if h2.maxResetStreams > 0 and h2.rstStreamCount > h2.maxResetStreams:
      h2.connError(c, errEnhanceYourCalm)

  of ftPriority:
    if fh.streamId == 0: h2.connError(c, errProtocol); return
    if fh.length != 5: h2.connError(c, errFrameSize); return
    # Budget PRIORITY before any branch: a self-dependency flood used to run
    # streamError (one RST per frame) and return *before* noteControlFrame, so it
    # was entirely unbudgeted (#234). PRIORITY has no productive use here anyway.
    h2.noteControlFrame(c)
    if c.state == csClosing: return
    if (get32(c.rbuf, payloadPos) and 0x7fffffff'u32) == fh.streamId:
      # Self-dependency is a PROTOCOL_ERROR (RFC 7540 5.3.1). On an opened stream
      # it is a STREAM error (RST_STREAM, connection survives -- Go/nghttp2). On
      # an idle stream RST_STREAM is forbidden (RFC 9113 5.1), so the only legal
      # signal is a connection error (h2spec expects GOAWAY here).
      if fh.streamId > h2.lastStreamId:
        h2.connError(c, errProtocol)
      else:
        h2.streamError(c, fh.streamId, errProtocol)
    # Otherwise ignored (RFC 9113 deprecates the priority tree).

  of ftGoaway:
    if fh.streamId != 0: h2.connError(c, errProtocol); return
    # GOAWAY carries a 4-byte last-stream-id + 4-byte error code (8 octets min);
    # a short frame is a connection FRAME_SIZE_ERROR (RFC 9113 4.2/6.8), like the
    # ftPing/ftWindowUpdate length checks -- GOAWAY silently accepted it (#240.10).
    if fh.length < 8: h2.connError(c, errFrameSize); return
    # A peer (client) GOAWAY is informational for a server that never pushes;
    # record it separately from our own drain flag so we do not start refusing
    # the client's own subsequent streams (which `goingAway` would do). Budget
    # it: a GOAWAY flood was previously unbudgeted overhead (#234).
    h2.noteControlFrame(c)
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
    # RFC 9113 3.4: the client preface MUST be followed by a SETTINGS frame.
    # Reject any other first frame as a connection error (as Go/nghttp2 do)
    # before it is dispatched.
    if not h2.sawFirstFrame:
      h2.sawFirstFrame = true
      if fh.typ != uint8(ftSettings):
        h2.connError(c, errProtocol)
        break
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

proc h2AwaitingClient*(c: ptr Connection): bool =
  ## True if any open stream is still expecting bytes from the client (its
  ## request head/body is not finished: no END_STREAM seen). Such a stream is a
  ## slowloris vector, so the loop arms a read-idle deadline while it is true.
  ## A stream the client has finished (endStreamSeen) while the server streams a
  ## long response back is NOT counted -- read-timing it would kill a legitimate
  ## SSE/download where the client is silent by design.
  if c.h2 == nil: return false
  let h2 = h2Conn(c)
  for sid, st in h2.streams.mpairs:   # mpairs: no per-stream value copy
    if not st.endStreamSeen: return true
  false

proc h2BlockedOnPeerWindow*(c: ptr Connection): bool =
  ## True if any open stream owes response bytes (queued in pendingBody) it
  ## cannot send because a flow-control send window is exhausted. Such a stream
  ## is waiting on the client to grant window (WINDOW_UPDATE); a client that
  ## absorbs the initial window then stays silent would otherwise pin the fd, the
  ## connection slot, and the multi-MB pendingBody buffers forever -- zero
  ## traffic, no timeout (the slow-read / zero-window attack, #236). The loop
  ## arms a body deadline while this holds so a genuinely stalled reader is cut
  ## off; a client that keeps reading re-arms it on every pass that drains bytes.
  if c.h2 == nil: return false
  let h2 = h2Conn(c)
  for sid, st in h2.streams.mpairs:
    if st.pendingBody.len - st.pendingPos > 0 and
        (st.sendWindow <= 0 or h2.connSendWindow <= 0):
      return true
  false

proc h2StreamAlive*(c: ptr Connection, sid: uint32): bool =
  c.h2 != nil and sid in h2Conn(c).streams

proc h2Stream*(c: ptr Connection, sid: uint32): ptr H2Stream =
  ## nil if gone. Pointer valid until the streams table is next mutated.
  let h2 = h2Conn(c)
  if sid in h2.streams: addr h2.streams[sid] else: nil
