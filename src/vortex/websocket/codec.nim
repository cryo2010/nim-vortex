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
import ./sha1
when defined(wsDeflate):
  import ./deflate

type
  WsKind* = enum
    wsText, wsBinary

  WebSocket* = object
    ## Handle to an upgraded connection: the same four words as Request,
    ## copyable and safe to move across threads. `stream` is always 0
    ## (WebSockets are HTTP/1.1 only for now).
    core*: ptr LoopCore
    fd*: int32
    gen*: uint32
    stream*: uint32

  WsMessageCb* = proc (ws: WebSocket, data: string,
                       kind: WsKind) {.closure, gcsafe.}
  WsCloseCb* = proc (ws: WebSocket, code: uint16,
                     reason: string) {.closure, gcsafe.}
  WsDrainCb* = proc (ws: WebSocket) {.closure, gcsafe.}

  WsConn* = ref object of RootObj
    ## Stored in `Connection.ws`. Loop-thread only, so the callbacks may be
    ## capturing closures (unlike `blocking:`).
    onMessage*: WsMessageCb
    onClose*: WsCloseCb
    onDrain*: WsDrainCb       ## fired when the write backlog empties
    backedUp: bool           ## the socket refused bytes; onDrain owes a call
    frag: string             ## reassembly buffer for a fragmented message
    fragOp: WsOpcode         ## opcode of the message being assembled
    fragging: bool
    maxMessage: int
    closeSent: bool          ## a close frame has been queued
    closeNotified: bool      ## onClose has been delivered
    subprotocol: string      ## negotiated Sec-WebSocket-Protocol ("" = none)
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
  if core.wsPingInterval > 0:
    c.dlKind = dkWsPing
    c.deadline = core.nowSec + int64(core.wsPingInterval)
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
            if n in 8 .. 15: srvWin = n else: ok = false
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

# --- handshake --------------------------------------------------------------

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

  let w = WsConn(maxMessage: maxMessage)
  let chosen = negotiateProtocol(protocolsOffer, serverProtocols)
  if chosen.len > 0:
    w.subprotocol = chosen
    c.wbuf.add "Sec-WebSocket-Protocol: "
    c.wbuf.add chosen
    c.wbuf.add "\r\n"
  when defined(wsDeflate):
    if core.wsCompression and extensionsOffer.len > 0:
      let neg = negotiatePmd(extensionsOffer)
      if neg.accept:
        w.deflate = initDeflator(neg.serverWindow, neg.serverNoCtx)
        w.inflate = initInflator(neg.clientNoCtx)
        if w.deflate.inited and w.inflate.inited:
          w.pmd = true
          c.wbuf.add "Sec-WebSocket-Extensions: "
          c.wbuf.add neg.respHeader
          c.wbuf.add "\r\n"
        else:
          w.deflate.close(); w.inflate.close()
  c.wbuf.add "\r\n"
  c.responded = true
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
    w.onClose(WebSocket(core: core, fd: c.fd, gen: c.gen), code, reason)

proc failClose(core: ptr LoopCore, c: ptr Connection, w: WsConn,
               code: uint16) =
  ## Queue a close frame with `code`, deliver onClose, and close the TCP
  ## connection once the frame has flushed.
  if not w.closeSent:
    w.closeSent = true
    c.wbuf.appendClose(code)
  notifyClose(core, c, w, code, "")
  c.closeAfterFlush = true

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
    let kind = if op == opBinary: wsBinary else: wsText
    w.onMessage(WebSocket(core: core, fd: c.fd, gen: c.gen), payload, kind)
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
  case fr.opcode
  of opPing:
    c.wbuf.appendFrame(opPong, fr.payload)
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
      c.wbuf.appendClose(code)             # echo the (valid) code back
    notifyClose(core, c, w, code, reason)
    c.closeAfterFlush = true
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

proc wsInput*(core: ptr LoopCore, c: ptr Connection) =
  ## Parse and dispatch every complete frame in the receive buffer, then
  ## compact. Loop thread only; called from the event loop's processInput.
  let w = WsConn(c.ws)
  var pos = 0
  var open = true
  while open:
    var fr: WsFrame
    case parseFrame(c.rbuf, c.rlen, pos, w.maxMessage, fr)
    of wpNeedMore:
      break
    of wpError:
      failClose(core, c, w, 1002)
      open = false
    of wpFrame:
      open = handleFrame(core, c, w, fr)
      # A ws.blocking dispatch pinned the connection: stop here and leave the
      # remaining frames buffered so they run one message at a time, in order.
      if c.pinned > 0: break
  if pos > 0:
    if pos >= c.rlen:
      c.rlen = 0
    else:
      moveMem(addr c.rbuf[0], addr c.rbuf[pos], c.rlen - pos)
      c.rlen -= pos
    # An inbound frame (pong or data) means the peer is alive: restart the
    # idle timer, which also cancels a pending pong deadline.
    if c.ws != nil and not c.closeAfterFlush:
      armWsPing(core, c)

proc wsClosed*(core: ptr LoopCore, c: ptr Connection) =
  ## Called by the loop when the connection is torn down: deliver onClose
  ## (abnormal 1006) if the peer never sent a close frame, and free the
  ## zlib state.
  if c.ws == nil: return
  let w = WsConn(c.ws)
  notifyClose(core, c, w, 1006, "")
  when defined(wsDeflate):
    if w.pmd:
      w.deflate.close()
      w.inflate.close()
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
      w.onDrain(WebSocket(core: core, fd: c.fd, gen: c.gen))

# --- public send/close API --------------------------------------------------

proc sendFrame(ws: WebSocket, op: WsOpcode,
               data: openArray[char]) {.raises: [].} =
  # Declared {.raises: [].} (the flushHook proc pointer otherwise gives an
  # Exception effect) so send/close compose inside chronos {.async.}
  # bodies, which only permit CatchableError. A send is best-effort: a
  # failure just means the connection is going away.
  try:
    if currentThreadId() != ws.core.threadId:
      var frame = ""
      frame.appendFrame(op, data)
      push(ws.core.outbox,
           OutMsg(kind: omWs, fd: ws.fd, gen: ws.gen, data: frame))
      return
    let c = conn(ws.core, ws.fd, ws.gen)
    if c == nil or c.ws == nil: return
    when defined(wsDeflate):
      let w = WsConn(c.ws)
      # Compress data messages when permessage-deflate is negotiated; control
      # frames and empty messages go out uncompressed. (Off-loop sends above
      # are always uncompressed: the deflate stream is loop-thread state.)
      if w.pmd and (op == opText or op == opBinary) and data.len > 0:
        let comp = w.deflate.compress(data)
        c.wbuf.appendFrame(op, comp, rsv1 = true)
        if ws.core.flushHook != nil:
          ws.core.flushHook(ws.core.loopPtr, ws.fd, ws.gen)
        return
    c.wbuf.appendFrame(op, data)
    if ws.core.flushHook != nil:
      ws.core.flushHook(ws.core.loopPtr, ws.fd, ws.gen)
  except Exception:
    discard

proc send*(ws: WebSocket, data: openArray[char], kind = wsText) {.raises: [].} =
  ## Send a message. Safe from any thread; a no-op if the connection is
  ## gone. Text is not validated here (send what you mean).
  sendFrame(ws, (if kind == wsBinary: opBinary else: opText), data)

proc ping*(ws: WebSocket, data: openArray[char] = "") {.raises: [].} =
  ## Send a ping; the peer should answer with a pong.
  sendFrame(ws, opPing, data)

proc close*(ws: WebSocket, code: uint16 = 1000, reason = "") {.raises: [].} =
  ## Start the closing handshake: queue a close frame and close the TCP
  ## connection once it flushes. Safe from any thread.
  try:
    if currentThreadId() != ws.core.threadId:
      var frame = ""
      frame.appendClose(code, reason)
      push(ws.core.outbox,
           OutMsg(kind: omWs, fd: ws.fd, gen: ws.gen, data: frame))
      return
    let c = conn(ws.core, ws.fd, ws.gen)
    if c == nil or c.ws == nil: return
    let w = WsConn(c.ws)
    if w.closeSent: return
    w.closeSent = true
    c.wbuf.appendClose(code, reason)
    c.closeAfterFlush = true
    if ws.core.flushHook != nil:
      ws.core.flushHook(ws.core.loopPtr, ws.fd, ws.gen)
  except Exception:
    discard

proc `onMessage=`*(ws: WebSocket, cb: WsMessageCb) =
  let c = conn(ws.core, ws.fd, ws.gen)
  if c != nil and c.ws != nil: WsConn(c.ws).onMessage = cb

proc `onClose=`*(ws: WebSocket, cb: WsCloseCb) =
  let c = conn(ws.core, ws.fd, ws.gen)
  if c != nil and c.ws != nil: WsConn(c.ws).onClose = cb

proc `onDrain=`*(ws: WebSocket, cb: WsDrainCb) =
  ## Set a callback fired (on the loop thread) when the write backlog drains
  ## back to zero after send() was throttled by a slow peer. Pair it with
  ## `bufferedAmount` to stop sending while the backlog is high and resume
  ## from here. No-op if the connection is gone.
  let c = conn(ws.core, ws.fd, ws.gen)
  if c != nil and c.ws != nil: WsConn(c.ws).onDrain = cb

proc bufferedAmount*(ws: WebSocket): int =
  ## Bytes queued by send() but not yet written to the socket. Grows when
  ## the peer stops reading and drains as the kernel accepts bytes; poll it
  ## to throttle a slow consumer (browser WebSocket.bufferedAmount). 0 if the
  ## connection is gone. Loop-thread snapshot: read it from a handler
  ## callback (onMessage/onDrain), not another thread. Off-loop sends queue
  ## on the outbox and are not counted until the loop picks them up.
  let c = conn(ws.core, ws.fd, ws.gen)
  if c != nil and c.ws != nil: c.pendingOut else: 0

proc isAlive*(ws: WebSocket): bool =
  let c = conn(ws.core, ws.fd, ws.gen)
  c != nil and c.ws != nil

proc subprotocol*(ws: WebSocket): string =
  ## The negotiated subprotocol, or "" if none was agreed.
  let c = conn(ws.core, ws.fd, ws.gen)
  if c != nil and c.ws != nil: WsConn(c.ws).subprotocol else: ""
