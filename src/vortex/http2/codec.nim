## HTTP/2 connection state machine (RFC 9113): frame handling, stream
## lifecycle, both directions of flow control, and response serialization.
## One H2Conn per connection, touched only by the owning loop thread
## (workers respond through the protocol-neutral outbox).

import std/[tables, strutils, uri]
import ./frames, ./hpack
import ../connection

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

  H2Conn* = ref object of RootObj
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
    goingAway*: bool
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

proc newH2Conn*(maxBody, maxHeaderList, maxConcurrentStreams,
                maxResetStreams, maxControlFrames: int): H2Conn =
  H2Conn(
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
  c.wbuf.addFrameHeader(payload.len, ftSettings, 0, 0)
  c.wbuf.add payload

proc connError(h2: H2Conn, c: ptr Connection, err: uint32) =
  c.wbuf.addGoaway(h2.lastStreamId, err)
  c.closeAfterFlush = true
  c.state = csClosing

proc streamError(h2: H2Conn, c: ptr Connection, sid: uint32, err: uint32) =
  c.wbuf.addRstStream(sid, err)
  if sid in h2.streams:
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

proc h2Respond*(c: ptr Connection, code: int, sid: uint32,
                dateStr, serverHeader, contentType: string,
                extraHeaders: openArray[(string, string)],
                body: openArray[char], altSvc = "") =
  let h2 = h2Conn(c)
  if sid notin h2.streams: return
  if h2.streams[sid].responded: return
  h2.streams[sid].responded = true
  let skipBody = h2.streams[sid].isHead
  var hb = ""
  encodeStatus(hb, code)
  if serverHeader.len > 0:
    encodeHeader(hb, "server", serverHeader)
  encodeHeader(hb, "date", dateStr)
  if contentType.len > 0:
    encodeHeader(hb, "content-type", contentType)
  encodeHeader(hb, "content-length", $body.len)
  if altSvc.len > 0:
    encodeHeader(hb, "alt-svc", altSvc)
  for (name, val) in extraHeaders:
    encodeHeader(hb, name.toLowerAscii, val)
  let noBody = body.len == 0 or skipBody
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
  else:
    var meth, path, scheme: string
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
        of ":authority": discard
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
    if meth.len == 0 or path.len == 0 or scheme.len == 0:
      h2.streamError(c, sid, errProtocol)
      return
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
  if st.endStreamSeen and not st.dispatched:
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
      if st.body.len + dataLen > h2.maxBody:
        h2.streamError(c, sid, errRefusedStream)
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
    # Replenish both windows eagerly (we never apply backpressure here).
    if fh.length > 0:
      c.wbuf.addWindowUpdate(0, fh.length)
      if fh.streamId in h2.streams and
          not h2.streams[fh.streamId].endStreamSeen:
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
          st.sendWindow += delta
      of setMaxFrameSize:
        if value < 16384'u32 or value > 16777215'u32:
          h2.connError(c, errProtocol); return
        h2.peerMaxFrame = int(value)
      of setEnablePush:
        if value > 1'u32: h2.connError(c, errProtocol); return
      else: discard                  # header table size: encoder is static-only
      i += 6
    c.wbuf.addFrameHeader(0, ftSettings, flagAck, 0)

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
      h2.connSendWindow += int32(inc32)
      # Connection window freed: retry every stream with pending data.
      var retry: seq[uint32]
      for sid, st in h2.streams:
        if st.pendingBody.len - st.pendingPos > 0: retry.add sid
      for sid in retry: h2.sendData(c, sid)
    elif fh.streamId in h2.streams:
      template st: H2Stream = h2.streams[fh.streamId]
      if int64(st.sendWindow) + int64(inc32) > 0x7fffffff'i64:
        h2.streamError(c, fh.streamId, errFlowControl); return
      st.sendWindow += int32(inc32)
      h2.sendData(c, fh.streamId)
    elif fh.streamId > h2.lastStreamId:
      h2.connError(c, errProtocol)   # WINDOW_UPDATE on idle stream

  of ftRstStream:
    if fh.streamId == 0: h2.connError(c, errProtocol); return
    if fh.length != 4: h2.connError(c, errFrameSize); return
    if fh.streamId > h2.lastStreamId:
      h2.connError(c, errProtocol); return   # RST on idle stream
    if fh.streamId in h2.streams:
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
    h2.goingAway = true

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
