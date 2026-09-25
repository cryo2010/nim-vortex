## WebSocket protocol layer (RFC 6455): the handshake, the per-connection
## state that hangs off `Connection.ws`, the inbound frame pump, and the
## public `WebSocket` handle with its send/close/callback API.
##
## Everything here runs on the connection's owning loop thread, except
## `send`/`close`, which detect an off-loop caller and route the frame
## through the loop's outbox (as `res.send` does for HTTP responses), so a
## worker or timer holding a `WebSocket` handle can push safely.

import std/[base64, strutils]
import ../connection
import ./frames
# Sec-WebSocket-Accept SHA-1: OpenSSL EVP (hardware SHA where available) in the
# TLS build; the bundled pure-Nim SHA-1 only when OpenSSL is absent (plainHttp).
when defined(plainHttp):
  import ./sha1
else:
  import ../hwcrypto
when defined(wsDeflate):
  import ./deflate

type
  WsKind* {.pure.} = enum
    Text, Binary

  WebSocket* = object
    ## Handle to an upgraded connection: the same four words as Request,
    ## copyable and safe to move across threads. `stream` is 0 for an
    ## HTTP/1.1 WebSocket and the HTTP/2 stream id for an RFC 8441 one.
    core*: ptr LoopCore
    fd*: int32
    gen*: uint32
    stream*: uint32

  WsMessageCb* = proc (ws: WebSocket, data: string,
                       kind: WsKind) {.closure, gcsafe.}
  WsCloseCb* = proc (ws: WebSocket, code: uint16,
                     reason: string) {.closure, gcsafe.}
  WsDrainCb* = proc (ws: WebSocket) {.closure, gcsafe.}

  WsFlush* = proc (core: ptr LoopCore, c: ptr Connection,
                   w: WsConn) {.nimcall, gcsafe.}
    ## Move `w.outBuf` to the wire and apply `w.wantClose`. Set at accept
    ## time per transport (`wsFlushH1`, or the HTTP/2 one in http2/codec),
    ## which keeps the WebSocket codec free of any HTTP/2 import. Doubles as the
    ## transport tag: `wsOut` writes h1 frames straight into `c.wbuf` and only
    ## h2/h3 stage them in `outBuf` (#337).

  WsConn* = ref object of RootObj
    ## The per-WebSocket state: on `Connection.ws` for HTTP/1.1, or on an
    ## `H2Stream.ws` for an HTTP/2 (RFC 8441) stream. Loop-thread only, so
    ## the callbacks may be capturing closures (unlike `blocking:`).
    onMessage*: WsMessageCb
    onClose*: WsCloseCb
    onDrain*: WsDrainCb       ## fired when the write backlog empties
    backedUp*: bool          ## the socket refused bytes; onDrain owes a call
    frag: string             ## reassembly buffer for a fragmented message
    fragOp: WsOpcode         ## opcode of the message being assembled
    fragging: bool
    maxMessage: int
    closeSent: bool          ## a close frame has been queued
    closeNotified*: bool     ## onClose has been delivered (the ws is finished)
    subprotocol: string      ## negotiated Sec-WebSocket-Protocol ("" = none)
    # Transport abstraction: the core appends serialized frames to the buffer
    # `wsOut` picks (HTTP/1: straight into c.wbuf; h2/h3: `outBuf`) and sets
    # `wantClose`; `flush` concludes them (HTTP/1: apply the close, HTTP/2:
    # stream DATA). `stream`/`inBuf`/`pinnedByWorker` back the HTTP/2 side.
    stream*: uint32          ## 0 for HTTP/1.1, else the h2/h3 stream id
    fd*: int32               ## handle identity for callbacks (h3 has no Connection)
    gen*: uint32
    outBuf*: string          ## serialized frames awaiting flush (h2/h3 only)
    wantClose*: bool         ## close the transport once the frames are flushed
    flush*: WsFlush
    inBuf*: string           ## h2/h3 inbound bytes accumulated from DATA frames
    preAcceptFin*: bool      ## client half-closed (END_STREAM) before accept
    pinnedByWorker*: bool    ## a per-stream ws.blocking worker holds this h2/h3
                             ## stream (the per-stream twin of pkWsBlocking; at
                             ## most one ws.blocking runs per stream, so a bool
                             ## is the honest type). Loop-thread only; set and
                             ## cleared exclusively via wsAcquireStreamPin /
                             ## wsReleaseStreamPin.
    h2Pending*: int          ## h2/h3 outbound bytes queued but not yet on the wire
    h3conn*: RootRef         ## the H3Conn for an h3 stream (reach it + stream)
    # Idle keepalive for h2/h3 streams (h1 uses the connection deadline wheel).
    lastRx*: int64           ## nowSec of the last inbound frame (activity)
    pingSent*: bool          ## a keepalive ping is outstanding, awaiting any frame
    pingAt*: int64           ## nowSec the outstanding ping was sent
    when defined(wsDeflate):
      pmd: bool              ## permessage-deflate negotiated on this connection
      msgCompressed: bool    ## the in-progress message's first frame had RSV1
      deflate: Deflator      ## compresses outbound messages
      inflate: Inflator      ## decompresses inbound messages

const
  wsMagic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    ## RFC 6455 4.2.2: appended to the client key before hashing.

var cachedThreadId {.threadvar.}: int

proc currentThreadId(): int {.inline.} =
  if cachedThreadId == 0:
    cachedThreadId = getThreadId()
  cachedThreadId

proc acceptKey(clientKey: string): string =
  encode(sha1(clientKey & wsMagic))

proc negotiateProtocol(offer: string, serverProtocols: openArray[string]): string =
  ## Choose a subprotocol: the first one in the server's list (server
  ## preference) that the client also offered. "" if none match.
  if serverProtocols.len == 0 or offer.len == 0: return ""
  var offered: seq[string]
  for p in offer.split(','):
    offered.add p.strip
  for sp in serverProtocols:
    if sp in offered: return sp
  ""

proc armWsPing*(core: ptr LoopCore, c: ptr Connection) =
  ## (Re)start the WebSocket idle timer: after wsPingInterval seconds with
  ## no inbound frame the loop sends a keepalive ping (see the event loop's
  ## sweep). 0 disables it, leaving the connection without a read deadline.
  if core.config.wsPingInterval > 0:
    c.dlKind = dkWsPing
    c.deadline = core.nowSec + int64(core.config.wsPingInterval)
  else:
    c.dlKind = dkNone
    c.deadline = 0

proc wsAppendPing*(c: ptr Connection) =
  ## Queue a keepalive ping frame (empty payload). Loop thread only.
  c.wbuf.appendFrame(opPing, "")

when defined(wsDeflate):
  type PmdNegotiation = object
    accept: bool
    respHeader: string        ## the negotiated Sec-WebSocket-Extensions value
    serverNoCtx: bool         ## reset our deflate window per message
    clientNoCtx: bool         ## client resets its window per message
    serverWindow: int         ## our deflate window (from server_max_window_bits)

  proc negotiatePmd(offer: string): PmdNegotiation =
    ## Parse the client's Sec-WebSocket-Extensions offer (RFC 7692 7.1) and,
    ## if it includes an acceptable permessage-deflate offer, produce the
    ## agreed parameters and the response header value. Our inflate always
    ## uses the max window, so client_max_window_bits is accepted but not
    ## echoed (omitting it is a valid response and simplest to reason about).
    result.serverWindow = 15
    for ext in offer.split(','):
      let parts = ext.split(';')
      if parts.len == 0 or parts[0].strip.toLowerAscii != "permessage-deflate":
        continue
      var srvNoCtx, cliNoCtx = false
      var srvWin = 15
      var ok = true
      for i in 1 ..< parts.len:
        let p = parts[i].strip
        if p.len == 0: continue
        let eq = p.find('=')
        let name = (if eq >= 0: p[0 ..< eq] else: p).strip.toLowerAscii
        let val = (if eq >= 0: p[eq+1 .. ^1].strip.strip(chars = {'"'}) else: "")
        case name
        of "server_no_context_takeover": srvNoCtx = true
        of "client_no_context_takeover": cliNoCtx = true
        of "server_max_window_bits":
          if val.len > 0:
            let n = (try: parseInt(val) except: -1)
            # zlib raw deflate has no window below 9, so we cannot honor a
            # request for 8 (advertising 8 while emitting a 9-bit window would
            # violate RFC 7692 7.1.2.2): decline this offer rather than
            # mis-advertise. 9..15 are honored.
            if n in 9 .. 15: srvWin = n else: ok = false
        of "client_max_window_bits":
          if val.len > 0 and (try: parseInt(val) except: -1) notin 8 .. 15:
            ok = false                         # malformed value
        else: ok = false                       # unknown param: decline offer
      if not ok: continue
      result.accept = true
      result.serverNoCtx = srvNoCtx
      result.clientNoCtx = cliNoCtx
      result.serverWindow = srvWin
      var h = "permessage-deflate"
      if srvNoCtx: h.add "; server_no_context_takeover"
      if cliNoCtx: h.add "; client_no_context_takeover"
      if srvWin < 15: h.add "; server_max_window_bits=" & $srvWin
      result.respHeader = h
      return

# --- transport flush --------------------------------------------------------

proc wsFlushH1*(core: ptr LoopCore, c: ptr Connection,
                w: WsConn) {.nimcall, gcsafe.} =
  ## HTTP/1 transport: apply a requested close once the produced frames flush.
  ## On HTTP/1 the frames are already in `c.wbuf` (see wsOut), so there is
  ## nothing to move; the drain of a non-empty `outBuf` stays as a backstop for
  ## any producer that predates that and would otherwise silently drop frames.
  if w.outBuf.len > 0:
    c.wbuf.add w.outBuf
    w.outBuf.setLen 0
  if w.wantClose:
    c.closeAfterFlush = true

proc wsOut(c: ptr Connection, w: WsConn): ptr string {.inline.} =
  ## Where a produced frame is serialized. On HTTP/1 the connection's write
  ## buffer IS the WebSocket transport buffer, so frames are appended straight
  ## into it (#337): staging them in `w.outBuf` first cost a second full copy
  ## (and a realloc of wbuf) of every outbound message before the syscall.
  ## HTTP/2 and HTTP/3 keep `outBuf`: their flush re-frames it as per-stream
  ## DATA, which needs the frame bytes held apart from the connection buffer.
  ## Backpressure accounting is unaffected: bufferedAmount already reported
  ## `c.pendingOut` for h1 (the old staging was moved into wbuf by the very next
  ## `w.flush`) and `h2Pending` for h2/h3.
  if c != nil and w.flush == wsFlushH1: addr c.wbuf else: addr w.outBuf

# --- handshake --------------------------------------------------------------

proc wsSetup*(core: ptr LoopCore, fd: int32, gen: uint32, maxMessage: int,
              stream: uint32, extensionsOffer, protocolsOffer: string,
              serverProtocols: openArray[string]):
              tuple[w: WsConn, protocol: string, extensions: string] =
  ## Build a `WsConn` and negotiate the subprotocol + permessage-deflate from
  ## the client's offers, without touching any wire buffer. Returns the
  ## chosen subprotocol ("" = none) and the Sec-WebSocket-Extensions response
  ## value ("" = no compression) for the caller's handshake. Shared by the
  ## HTTP/1.1, HTTP/2 (RFC 8441) and HTTP/3 (RFC 9220) accept paths. `fd`/`gen`
  ## identify the handle so callbacks can be delivered without a `Connection`.
  let w = WsConn(maxMessage: maxMessage, stream: stream, fd: fd, gen: gen)
  w.lastRx = core.nowSec
  # h2 (stream != 0) and h3 (fd < 0) multiplex many WebSockets over one
  # connection, so they can't use the per-connection deadline wheel h1 uses;
  # register them for the loop's per-stream idle sweep instead.
  if stream != 0 or fd < 0:
    core.wsIdle.add w
  result.w = w
  let chosen = negotiateProtocol(protocolsOffer, serverProtocols)
  if chosen.len > 0:
    w.subprotocol = chosen
    result.protocol = chosen
  when defined(wsDeflate):
    if core.config.wsCompression and extensionsOffer.len > 0:
      let neg = negotiatePmd(extensionsOffer)
      if neg.accept:
        w.deflate = initDeflator(neg.serverWindow, neg.serverNoCtx)
        w.inflate = initInflator(neg.clientNoCtx)
        if w.deflate.inited and w.inflate.inited:
          w.pmd = true
          result.extensions = neg.respHeader
        else:
          w.deflate.close(); w.inflate.close()

proc wsAccept*(core: ptr LoopCore, c: ptr Connection, clientKey: string,
               maxMessage: int, extensionsOffer = "", protocolsOffer = "",
               serverProtocols: openArray[string] = []): WsConn =
  ## Write the 101 handshake into the connection's write buffer and switch
  ## it into WebSocket mode. Loop thread only. A dedicated serializer is
  ## needed because appendResponse always emits Content-Length, which a
  ## 101 upgrade must not carry. `extensionsOffer` is the client's
  ## Sec-WebSocket-Extensions value (permessage-deflate); `protocolsOffer`
  ## is its Sec-WebSocket-Protocol value, negotiated against
  ## `serverProtocols`.
  let (w, proto, ext) = wsSetup(core, c.fd, c.gen, maxMessage, 0,
                                extensionsOffer, protocolsOffer,
                                serverProtocols)
  w.flush = wsFlushH1
  c.wbuf.add "HTTP/1.1 101 Switching Protocols\r\n"
  if core.serverHeader.len > 0:
    c.wbuf.add "Server: "
    c.wbuf.add core.serverHeader
    c.wbuf.add "\r\n"
  c.wbuf.add "Upgrade: websocket\r\n"
  c.wbuf.add "Connection: Upgrade\r\n"
  c.wbuf.add "Sec-WebSocket-Accept: "
  c.wbuf.add acceptKey(clientKey)
  c.wbuf.add "\r\n"
  if proto.len > 0:
    c.wbuf.add "Sec-WebSocket-Protocol: "
    c.wbuf.add proto
    c.wbuf.add "\r\n"
  if ext.len > 0:
    c.wbuf.add "Sec-WebSocket-Extensions: "
    c.wbuf.add ext
    c.wbuf.add "\r\n"
  c.wbuf.add "\r\n"
  c.rs.responded = true
  c.ws = w
  # Drop the consumed HTTP request bytes so the frame pump starts at the
  # first WebSocket byte (any the client pipelined after the upgrade).
  let consumed = c.parser.pos
  if consumed >= c.rlen:
    c.rlen = 0
  elif consumed > 0:
    moveMem(addr c.rbuf[0], addr c.rbuf[consumed], c.rlen - consumed)
    c.rlen -= consumed
  # Long-lived: replace the HTTP read deadline with the WebSocket keepalive.
  armWsPing(core, c)
  w

# --- output helpers (loop thread) -------------------------------------------

proc notifyClose(core: ptr LoopCore, c: ptr Connection, w: WsConn,
                 code: uint16, reason: string) =
  if w.closeNotified: return
  w.closeNotified = true
  if w.onClose != nil:
    w.onClose(WebSocket(core: core, fd: w.fd, gen: w.gen, stream: w.stream),
              code, reason)

proc failClose(core: ptr LoopCore, c: ptr Connection, w: WsConn,
               code: uint16) =
  ## Queue a close frame with `code`, deliver onClose, and close the
  ## transport (connection for HTTP/1, stream for HTTP/2) once it flushes.
  if not w.closeSent:
    w.closeSent = true
    wsOut(c, w)[].appendClose(code)
  notifyClose(core, c, w, code, "")
  w.wantClose = true

proc validUtf8(s: openArray[char]): bool =
  ## Strict UTF-8 per RFC 3629: rejects overlong forms, surrogate code
  ## points (U+D800..U+DFFF), values above U+10FFFF, and truncated
  ## sequences. std/unicode.validateUtf8 accepts several of these, which
  ## fails the Autobahn UTF-8 cases.
  var i = 0
  let n = s.len
  while i < n:
    let b0 = uint8(s[i])
    if b0 < 0x80:
      inc i
    elif b0 shr 5 == 0b110:                       # 2-byte
      if i + 1 >= n or (uint8(s[i+1]) and 0xC0) != 0x80: return false
      let cp = (uint32(b0 and 0x1F) shl 6) or uint32(uint8(s[i+1]) and 0x3F)
      if cp < 0x80: return false                  # overlong
      i += 2
    elif b0 shr 4 == 0b1110:                      # 3-byte
      if i + 2 >= n or (uint8(s[i+1]) and 0xC0) != 0x80 or
         (uint8(s[i+2]) and 0xC0) != 0x80: return false
      let cp = (uint32(b0 and 0x0F) shl 12) or
               (uint32(uint8(s[i+1]) and 0x3F) shl 6) or
               uint32(uint8(s[i+2]) and 0x3F)
      if cp < 0x800 or (cp >= 0xD800 and cp <= 0xDFFF): return false
      i += 3
    elif b0 shr 3 == 0b11110:                     # 4-byte
      if i + 3 >= n or (uint8(s[i+1]) and 0xC0) != 0x80 or
         (uint8(s[i+2]) and 0xC0) != 0x80 or
         (uint8(s[i+3]) and 0xC0) != 0x80: return false
      let cp = (uint32(b0 and 0x07) shl 18) or
               (uint32(uint8(s[i+1]) and 0x3F) shl 12) or
               (uint32(uint8(s[i+2]) and 0x3F) shl 6) or
               uint32(uint8(s[i+3]) and 0x3F)
      if cp < 0x10000 or cp > 0x10FFFF: return false
      i += 4
    else:
      return false                                # stray continuation / F8+
  true

proc validCloseCode(code: uint16): bool =
  ## RFC 6455 7.4: application-usable close codes. Excludes the reserved
  ## 1004/1005/1006/1015, the unassigned 1016..2999, and 0..999.
  code in {1000'u16, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011} or
  (code >= 3000 and code <= 4999)

proc dispatchMessage(core: ptr LoopCore, c: ptr Connection, w: WsConn,
                     op: WsOpcode, data: string, compressed: bool): bool =
  ## Deliver a complete message, decompressing first if it was compressed.
  ## Returns false if the connection is now closing.
  var payload = data
  when defined(wsDeflate):
    if compressed:
      let r = w.inflate.decompress(data, w.maxMessage)
      case r.status
      of dsTooBig: failClose(core, c, w, 1009); return false   # bomb / too big
      of dsError:  failClose(core, c, w, 1002); return false   # bad deflate
      of dsOk:     payload = r.data
  if op == opText and not validUtf8(payload):
    failClose(core, c, w, 1007)          # not valid UTF-8
    return false
  if w.onMessage != nil:
    let kind = if op == opBinary: WsKind.Binary else: WsKind.Text
    w.onMessage(WebSocket(core: core, fd: w.fd, gen: w.gen, stream: w.stream),
                payload, kind)
  true

proc rsv1Ok(w: WsConn, fr: WsFrame): bool =
  ## RSV1 is only legal on the first frame of a data message, and only when
  ## permessage-deflate was negotiated.
  if not fr.rsv1: return true
  when defined(wsDeflate):
    return w.pmd
  else:
    return false

proc handleFrame(core: ptr LoopCore, c: ptr Connection, w: WsConn,
                 fr: WsFrame): bool =
  ## Process one parsed frame. Returns false when the connection should
  ## stop reading (a close was initiated).
  if fr.rsv1 and fr.opcode.isControl:
    failClose(core, c, w, 1002)  # RSV1 has no meaning on a control frame
    return false
  case fr.opcode
  of opPing:
    if not w.closeSent:                    # nothing may follow a sent close
      wsOut(c, w)[].appendFrame(opPong, fr.payload)
    true
  of opPong:
    true                                   # unsolicited pong: ignore
  of opClose:
    # A close payload is either empty or at least a 2-byte code; a lone
    # byte is a protocol error (RFC 6455 5.5.1).
    if fr.payload.len == 1:
      failClose(core, c, w, 1002)
      return false
    var code = 1000'u16
    var reason = ""
    if fr.payload.len >= 2:
      code = (uint16(uint8(fr.payload[0])) shl 8) or uint16(uint8(fr.payload[1]))
      if fr.payload.len > 2: reason = fr.payload[2 .. ^1]
      if not validCloseCode(code):
        failClose(core, c, w, 1002)        # reserved/invalid close code
        return false
      if not validUtf8(reason):
        failClose(core, c, w, 1007)        # reason must be valid UTF-8
        return false
    if not w.closeSent:
      w.closeSent = true
      wsOut(c, w)[].appendClose(code)      # echo the (valid) code back
    notifyClose(core, c, w, code, reason)
    w.wantClose = true
    false
  of opText, opBinary:
    if w.fragging:
      failClose(core, c, w, 1002)          # data frame mid-fragment
      return false
    if not rsv1Ok(w, fr):
      failClose(core, c, w, 1002)          # RSV1 set without permessage-deflate
      return false
    let compressed = fr.rsv1
    if fr.fin:
      dispatchMessage(core, c, w, fr.opcode, fr.payload, compressed)
    else:
      w.fragging = true
      w.fragOp = fr.opcode
      w.frag = fr.payload
      when defined(wsDeflate): w.msgCompressed = compressed
      true
  of opContinuation:
    if not w.fragging:
      failClose(core, c, w, 1002)          # continuation with nothing open
      return false
    if fr.rsv1:
      failClose(core, c, w, 1002)          # RSV1 only on the first frame
      return false
    if w.frag.len + fr.payload.len > w.maxMessage:
      failClose(core, c, w, 1009)          # message too big (still compressed)
      return false
    w.frag.add fr.payload
    if fr.fin:
      w.fragging = false
      let op = w.fragOp
      let msg = move w.frag
      w.frag = ""
      var compressed = false
      when defined(wsDeflate): compressed = w.msgCompressed
      dispatchMessage(core, c, w, op, msg, compressed)
    else:
      true

# --- inbound pump -----------------------------------------------------------

proc wsPump(core: ptr LoopCore, c: ptr Connection, w: WsConn,
            buf: string, avail: int): int =
  ## Parse and dispatch complete frames from buf[0 ..< avail]; return the
  ## number of bytes consumed. Transport-agnostic (the buffer is the h1
  ## receive buffer or an h2 stream's inBuf); the caller compacts and flushes.
  var pos = 0
  var open = true
  while open:
    # Once onClose has been delivered (peer close, error, or teardown) the ws is
    # finished: do not dispatch further frames onto freed handler state.
    if w.closeNotified or w.wantClose: break
    var fr: WsFrame
    case parseFrame(buf, avail, pos, w.maxMessage, fr)
    of wpNeedMore:
      break
    of wpError:
      failClose(core, c, w, 1002)
      open = false
    of wpFrame:
      open = handleFrame(core, c, w, fr)
      # A ws.blocking dispatch paused this WebSocket: stop and leave the rest
      # buffered so messages run one at a time, in order. An upgraded HTTP/1
      # connection holds a pkWsBlocking connection pin -- the only pin kind
      # that can be live on an upgraded conn, since no HTTP request can
      # dispatch after the 101 (so this deliberately narrows the former
      # totalPins gate to the ws kind). h2 and h3 use the per-stream
      # pinnedByWorker instead, so one pinned stream never stalls its
      # siblings' frames; on an h2 conn pins[pkWsBlocking] is always 0, and
      # `c != nil` is only deref-safety for h3 (which has no Connection --
      # note QUIC stream ids start at 0, so w.stream alone cannot
      # discriminate h1 from h3 here).
      if (c != nil and c.pins[pkWsBlocking] > 0) or w.pinnedByWorker:
        break
  pos

proc wsInput*(core: ptr LoopCore, c: ptr Connection) =
  ## Parse and dispatch every complete frame in the receive buffer, then
  ## compact. Loop thread only; called from the event loop's processInput.
  let w = WsConn(c.ws)
  let consumed = wsPump(core, c, w, c.rbuf, c.rlen)
  wsFlushH1(core, c, w)                     # move frames out; may set close
  if consumed > 0:
    if consumed >= c.rlen:
      c.rlen = 0
    else:
      moveMem(addr c.rbuf[0], addr c.rbuf[consumed], c.rlen - consumed)
      c.rlen -= consumed
    # An inbound frame (pong or data) means the peer is alive: restart the
    # idle timer, which also cancels a pending pong deadline.
    if c.ws != nil and not c.closeAfterFlush:
      armWsPing(core, c)

proc wsFeed*(core: ptr LoopCore, c: ptr Connection, w: WsConn,
               data: openArray[char]) =
  ## Feed inbound WebSocket bytes carried in an HTTP/2 or HTTP/3 DATA frame:
  ## buffer them and pump complete frames (unless a ws.blocking worker holds
  ## this stream), then flush any produced frames via the stream's transport.
  ## `c` is the h2 connection, or nil for h3 (the flush reaches the stream
  ## through the WsConn).
  if data.len > 0:
    w.lastRx = core.nowSec           # inbound frame(s): the peer is alive
    w.pingSent = false               # any frame answers an outstanding ping
    let old = w.inBuf.len
    w.inBuf.setLen(old + data.len)
    copyMem(addr w.inBuf[old], unsafeAddr data[0], data.len)
  if not w.pinnedByWorker:
    let consumed = wsPump(core, c, w, w.inBuf, w.inBuf.len)
    if consumed > 0:
      let remain = w.inBuf.len - consumed
      if remain > 0:
        moveMem(addr w.inBuf[0], addr w.inBuf[consumed], remain)
      w.inBuf.setLen(remain)
  # Bound the buffer like HTTP/1 bounds its receive buffer: if frames pile up
  # faster than they drain (a flood while a ws.blocking worker holds the
  # stream, or an over-long message), close instead of buffering unboundedly.
  if w.inBuf.len > w.maxMessage + 1024:
    failClose(core, c, w, 1009)
  if w.flush != nil:
    w.flush(core, c, w)

proc wsAcquireStreamPin*(core: ptr LoopCore, w: WsConn) =
  ## Pin one h2/h3 WebSocket stream for a ws.blocking worker: frame dispatch
  ## for this stream pauses until wsReleaseStreamPin. The per-stream twin of
  ## acquirePin(pkWsBlocking); loop thread only, same contract.
  doAssert currentThreadId() == core.threadId,
    "ws stream pins may only be acquired on the owning loop thread"
  w.pinnedByWorker = true

proc wsReleaseStreamPin*(core: ptr LoopCore, w: WsConn) =
  ## Release the stream pin. Loop thread only (applied from omWsDone).
  doAssert currentThreadId() == core.threadId,
    "ws stream pins may only be released on the owning loop thread"
  w.pinnedByWorker = false

proc wsResume*(core: ptr LoopCore, c: ptr Connection, w: WsConn) =
  ## A per-stream ws.blocking worker (h2 or h3) finished: release the stream
  ## pin and pump any frames buffered while it ran.
  wsReleaseStreamPin(core, w)
  wsFeed(core, c, w, [])

proc wsStreamClosed*(core: ptr LoopCore, c: ptr Connection, w: WsConn) =
  ## Tear down one WebSocket's WsConn: deliver an abnormal onClose (1006) if
  ## the peer never closed cleanly, and free zlib state. Used for an h2
  ## stream reset and for every WS stream when the connection dies.
  notifyClose(core, c, w, 1006, "")
  when defined(wsDeflate):
    if w.pmd:
      w.deflate.close()
      w.inflate.close()

proc wsPeerClosed*(core: ptr LoopCore, c: ptr Connection, w: WsConn) =
  ## The transport reports the peer closed without a WebSocket close frame
  ## (e.g. an h2 stream END_STREAM): queue a normal close and flush it.
  if w.closeSent: return
  w.closeSent = true
  wsOut(c, w)[].appendClose(1000)
  w.wantClose = true
  if w.flush != nil:
    w.flush(core, c, w)

proc wsSweepIdle*(core: ptr LoopCore, c: ptr Connection, w: WsConn): bool =
  ## Per-stream WebSocket keepalive for h2/h3, called ~once a second by the loop
  ## for each tracked WsConn. After `wsPingInterval` idle seconds it sends a
  ## ping; if no frame arrives within `wsPongTimeout` after that, it closes the
  ## stream (1011) as an unresponsive peer. Returns true when the caller should
  ## stop tracking this ws (it timed out, or already closed). h1 uses the
  ## connection deadline wheel instead. `c` is the h2 connection, nil for h3.
  if w.closeNotified: return true            # already closed: reap
  if core.config.wsPingInterval <= 0: return false  # keepalive disabled
  if w.pingSent:
    if core.nowSec - w.pingAt >= int64(core.config.wsPongTimeout):
      failClose(core, c, w, 1011)            # no reply: peer is gone
      if w.flush != nil: w.flush(core, c, w) # push the close / conclude the stream
      return true
  elif core.nowSec - w.lastRx >= int64(core.config.wsPingInterval):
    wsOut(c, w)[].appendFrame(opPing, "")
    w.pingSent = true
    w.pingAt = core.nowSec
    if w.flush != nil: w.flush(core, c, w)
  false

proc wsClosed*(core: ptr LoopCore, c: ptr Connection) =
  ## Called by the loop when an HTTP/1 connection is torn down.
  if c.ws == nil: return
  wsStreamClosed(core, c, WsConn(c.ws))
  c.ws = nil

proc wsBackpressure*(c: ptr Connection) {.inline.} =
  ## The socket refused the last write, so bytes are parked in the write
  ## buffer: remember it so onDrain fires once they flush. Loop thread only.
  WsConn(c.ws).backedUp = true

proc wsDrained*(core: ptr LoopCore, c: ptr Connection) =
  ## The write buffer just emptied. If this connection had been backed up,
  ## clear the flag and fire onDrain so the app can resume sending. Loop
  ## thread only; called from the event loop's flushOut.
  let w = WsConn(c.ws)
  if w.backedUp:
    w.backedUp = false
    if w.onDrain != nil:
      w.onDrain(WebSocket(core: core, fd: w.fd, gen: w.gen, stream: w.stream))

# --- public send/close API --------------------------------------------------

proc wsConnOf*(ws: WebSocket): (ptr Connection, WsConn) =
  ## Resolve the connection and WsConn for a handle: `c.ws` for HTTP/1.1, the
  ## stream's WsConn via a lookup hook for HTTP/2 / HTTP/3. `(nil, nil)` when
  ## the WebSocket is gone. For h3 (`fd < 0`) there is no `ptr Connection`, so
  ## the returned connection is nil and the flush reaches the stream through
  ## the WsConn.
  if ws.fd < 0:
    if ws.core.hooks.wsH3Lookup != nil:
      return (nil, WsConn(ws.core.hooks.wsH3Lookup(cast[pointer](ws.core), ws.fd,
                                             ws.gen, ws.stream)))
    return (nil, nil)
  let c = conn(ws.core, ws.fd, ws.gen)
  if c == nil: return (nil, nil)
  if ws.stream == 0:
    return (c, WsConn(c.ws))
  if ws.core.hooks.wsStreamLookup != nil:
    return (c, WsConn(ws.core.hooks.wsStreamLookup(cast[pointer](c), ws.stream)))
  (c, nil)

proc wsConnForStream*(core: ptr LoopCore, c: ptr Connection,
                      stream: uint32): WsConn =
  ## Resolve the WsConn for a connection + stream (h1 `c.ws` or the h2 stream
  ## via the lookup hook). Used by the event loop's outbox routing.
  if stream == 0: return WsConn(c.ws)
  if core.hooks.wsStreamLookup != nil:
    return WsConn(core.hooks.wsStreamLookup(cast[pointer](c), stream))
  nil

proc wsConnForH3*(core: ptr LoopCore, fd: int32, gen: uint32,
                  stream: uint32): WsConn =
  ## Resolve an h3 stream's WsConn from a handle (`fd < 0`). Used by the event
  ## loop's outbox routing for HTTP/3 WebSockets.
  if core.hooks.wsH3Lookup != nil:
    return WsConn(core.hooks.wsH3Lookup(cast[pointer](core), fd, gen, stream))
  nil

proc wsFlushRaw*(core: ptr LoopCore, c: ptr Connection, w: WsConn,
                 data: string, close: bool) =
  ## Enqueue an already-serialized frame from an off-loop sender and flush it
  ## through the transport; `close` marks the WebSocket closing afterward.
  if w.closeSent:
    # A close frame has already been queued; nothing may follow it (RFC 6455
    # 5.5.1). Flush whatever is buffered but append nothing more (drops a
    # send-after-close or a second close racing a peer close).
    if w.flush != nil: w.flush(core, c, w)
    return
  wsOut(c, w)[].add data
  if close:
    w.closeSent = true
    w.wantClose = true
  if w.flush != nil:
    w.flush(core, c, w)

proc close*(ws: WebSocket, code: uint16 = 1000, reason = "") {.gcsafe, raises: [].}
  ## Forward declaration: sendFrame closes the connection if permessage-deflate
  ## compression fails (see below).

template withWsConn(ws: WebSocket; c, w, body: untyped) =
  ## Loop-thread contract for the WsConn-resolving entry points. Off the loop
  ## thread these cannot touch the ref (mutating/reading it would race the loop's
  ## non-atomic ORC refcount), so bail with the proc's default result; on-loop,
  ## resolve the (Connection, WsConn) pair into `c`/`w`, nil-guard, then run body.
  if currentThreadId() != ws.core.threadId: return
  let (c, w) = wsConnOf(ws)
  if w == nil: return
  body

template withWsConn(ws: WebSocket; c, w, offThread, body: untyped) =
  ## As above, but the entry point must still deliver off the loop thread: run
  ## `offThread` (route the frame through the outbox) before bailing.
  if currentThreadId() != ws.core.threadId:
    offThread
    return
  let (c, w) = wsConnOf(ws)
  if w == nil: return
  body

proc sendFrame(ws: WebSocket, op: WsOpcode,
               data: openArray[char]) {.raises: [].} =
  # Declared {.raises: [].} (the flushHook proc pointer otherwise gives an
  # Exception effect) so send/close compose inside chronos {.async.}
  # bodies, which only permit CatchableError. A send is best-effort: a
  # failure just means the connection is going away.
  try:
    withWsConn(ws, c, w,
      (var frame = "";
       frame.appendFrame(op, data);
       push(ws.core.outbox, OutMsg(kind: omWs, fd: ws.fd, gen: ws.gen,
                                   stream: ws.stream, data: frame)))):
      if w.closeSent: return   # nothing may follow a sent close frame
      when defined(wsDeflate):
        # Compress data messages when permessage-deflate is negotiated; control
        # frames and empty messages go out uncompressed. (Off-loop sends above
        # are always uncompressed: the deflate stream is loop-thread state.)
        if w.pmd and (op == opText or op == opBinary) and data.len > 0:
          var comp: string
          try:
            comp = w.deflate.compress(data)
          except CatchableError:
            # A deflate failure corrupts the stateful pmd stream (context
            # takeover carries state across messages), so every later message
            # would be undecodable. Close with 1011 rather than dropping
            # silently or emitting a frame the peer can't decode (R13).
            ws.close(1011)
            return
          wsOut(c, w)[].appendFrame(op, comp, rsv1 = true)
          w.flush(ws.core, c, w)
          if ws.core.hooks.flushHook != nil:
            ws.core.hooks.flushHook(ws.core.loopPtr, ws.fd, ws.gen)
          return
      wsOut(c, w)[].appendFrame(op, data)
      w.flush(ws.core, c, w)
      if ws.core.hooks.flushHook != nil:
        ws.core.hooks.flushHook(ws.core.loopPtr, ws.fd, ws.gen)
  except Exception:
    discard

proc send*(ws: WebSocket, data: openArray[char], kind = WsKind.Text) {.raises: [].} =
  ## Send a message. Safe from any thread; a no-op if the connection is
  ## gone. Text is not validated here (send what you mean).
  sendFrame(ws, (if kind == WsKind.Binary: opBinary else: opText), data)

proc ping*(ws: WebSocket, data: openArray[char] = "") {.raises: [].} =
  ## Send a ping; the peer should answer with a pong. A control frame's payload
  ## is capped at 125 bytes (RFC 6455 5.5), so a longer one is truncated.
  if data.len > 125: sendFrame(ws, opPing, data.toOpenArray(0, 124))
  else: sendFrame(ws, opPing, data)

proc close*(ws: WebSocket, code: uint16 = 1000, reason = "") {.gcsafe, raises: [].} =
  ## Start the closing handshake: queue a close frame and close the transport
  ## (the connection for HTTP/1.1, the stream for HTTP/2) once it flushes.
  ## Safe from any thread.
  try:
    withWsConn(ws, c, w,
      (var frame = "";
       frame.appendClose(code, reason);
       push(ws.core.outbox, OutMsg(kind: omWsClose, fd: ws.fd, gen: ws.gen,
                                   stream: ws.stream, data: frame)))):
      if w.closeSent: return
      w.closeSent = true
      wsOut(c, w)[].appendClose(code, reason)
      w.wantClose = true
      w.flush(ws.core, c, w)
      if ws.core.hooks.flushHook != nil:
        ws.core.hooks.flushHook(ws.core.loopPtr, ws.fd, ws.gen)
  except Exception:
    discard

proc `onMessage=`*(ws: WebSocket, cb: WsMessageCb) =
  ## Loop-thread only (set it from the accept handler). Off-loop it is a no-op:
  ## resolving and mutating the WsConn ref from a worker would race the loop's
  ## non-atomic ORC refcount. Cross-thread output uses send/close, which route
  ## through the outbox.
  withWsConn(ws, _, w):
    w.onMessage = cb

proc `onClose=`*(ws: WebSocket, cb: WsCloseCb) =
  ## Loop-thread only (see onMessage=).
  withWsConn(ws, _, w):
    w.onClose = cb

proc `onDrain=`*(ws: WebSocket, cb: WsDrainCb) =
  ## Set a callback fired (on the loop thread) when the write backlog drains
  ## back to zero after send() was throttled by a slow peer. Pair it with
  ## `bufferedAmount` to stop sending while the backlog is high and resume
  ## from here. No-op if the connection is gone. Loop-thread only (see
  ## onMessage=).
  withWsConn(ws, _, w):
    w.onDrain = cb

proc bufferedAmount*(ws: WebSocket): int =
  ## Bytes queued by send() but not yet written to the peer. Grows when the
  ## peer stops reading and drains as it catches up; poll it to throttle a
  ## slow consumer (browser WebSocket.bufferedAmount). For HTTP/2 and HTTP/3
  ## this is the stream's send backlog. 0 if the WebSocket is gone. Loop-thread
  ## snapshot: read it from a handler callback (onMessage/onDrain), not
  ## another thread; off-loop sends queue on the outbox and are not counted
  ## until the loop picks them up.
  withWsConn(ws, c, w):
    result = if ws.fd >= 0 and ws.stream == 0: c.pendingOut else: w.h2Pending

proc isAlive*(ws: WebSocket): bool =
  ## Loop-thread only; off-loop it conservatively reports false rather than
  ## resolving the WsConn ref across threads.
  withWsConn(ws, _, w):
    result = true

proc subprotocol*(ws: WebSocket): string =
  ## The negotiated subprotocol, or "" if none was agreed.
  let (_, w) = wsConnOf(ws)
  if w != nil: w.subprotocol else: ""
