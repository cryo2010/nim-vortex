## WebSocket protocol layer (RFC 6455): the handshake, the per-connection
## state that hangs off `Connection.ws`, the inbound frame pump, and the
## public `WebSocket` handle with its send/close/callback API.
##
## Everything here runs on the connection's owning loop thread, except
## `send`/`close`, which detect an off-loop caller and route the frame
## through the loop's outbox (as `res.send` does for HTTP responses), so a
## worker or timer holding a `WebSocket` handle can push safely.

import std/[base64, unicode]
import ../connection
import ./frames
import ./sha1

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

  WsConn* = ref object of RootObj
    ## Stored in `Connection.ws`. Loop-thread only, so the callbacks may be
    ## capturing closures (unlike `blocking:`).
    onMessage*: WsMessageCb
    onClose*: WsCloseCb
    frag: string             ## reassembly buffer for a fragmented message
    fragOp: WsOpcode         ## opcode of the message being assembled
    fragging: bool
    maxMessage: int
    closeSent: bool          ## a close frame has been queued
    closeNotified: bool      ## onClose has been delivered

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

# --- handshake --------------------------------------------------------------

proc wsAccept*(core: ptr LoopCore, c: ptr Connection, clientKey: string,
               maxMessage: int): WsConn =
  ## Write the 101 handshake into the connection's write buffer and switch
  ## it into WebSocket mode. Loop thread only. A dedicated serializer is
  ## needed because appendResponse always emits Content-Length, which a
  ## 101 upgrade must not carry.
  c.wbuf.add "HTTP/1.1 101 Switching Protocols\r\n"
  if core.serverHeader.len > 0:
    c.wbuf.add "Server: "
    c.wbuf.add core.serverHeader
    c.wbuf.add "\r\n"
  c.wbuf.add "Upgrade: websocket\r\n"
  c.wbuf.add "Connection: Upgrade\r\n"
  c.wbuf.add "Sec-WebSocket-Accept: "
  c.wbuf.add acceptKey(clientKey)
  c.wbuf.add "\r\n\r\n"
  c.responded = true

  let w = WsConn(maxMessage: maxMessage)
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

proc dispatchMessage(core: ptr LoopCore, c: ptr Connection, w: WsConn,
                     op: WsOpcode, data: string): bool =
  ## Deliver a complete message. Returns false if the connection is now
  ## closing (invalid UTF-8 in a text message).
  if op == opText and validateUtf8(data) != -1:
    failClose(core, c, w, 1007)          # not valid UTF-8
    return false
  if w.onMessage != nil:
    let kind = if op == opBinary: wsBinary else: wsText
    w.onMessage(WebSocket(core: core, fd: c.fd, gen: c.gen), data, kind)
  true

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
    var code = 1000'u16
    var reason = ""
    if fr.payload.len >= 2:
      code = (uint16(uint8(fr.payload[0])) shl 8) or uint16(uint8(fr.payload[1]))
      if fr.payload.len > 2: reason = fr.payload[2 .. ^1]
    if not w.closeSent:
      w.closeSent = true
      c.wbuf.appendClose(code, reason)     # echo the close
    notifyClose(core, c, w, code, reason)
    c.closeAfterFlush = true
    false
  of opText, opBinary:
    if w.fragging:
      failClose(core, c, w, 1002)          # data frame mid-fragment
      return false
    if fr.fin:
      dispatchMessage(core, c, w, fr.opcode, fr.payload)
    else:
      w.fragging = true
      w.fragOp = fr.opcode
      w.frag = fr.payload
      true
  of opContinuation:
    if not w.fragging:
      failClose(core, c, w, 1002)          # continuation with nothing open
      return false
    if w.frag.len + fr.payload.len > w.maxMessage:
      failClose(core, c, w, 1009)          # message too big
      return false
    w.frag.add fr.payload
    if fr.fin:
      w.fragging = false
      let op = w.fragOp
      let msg = move w.frag
      w.frag = ""
      dispatchMessage(core, c, w, op, msg)
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
  ## (abnormal 1006) if the peer never sent a close frame.
  if c.ws == nil: return
  let w = WsConn(c.ws)
  notifyClose(core, c, w, 1006, "")
  c.ws = nil

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

proc isAlive*(ws: WebSocket): bool =
  let c = conn(ws.core, ws.fd, ws.gen)
  c != nil and c.ws != nil
