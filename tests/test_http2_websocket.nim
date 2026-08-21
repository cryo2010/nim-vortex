## HTTP/2 Extended CONNECT WebSockets (RFC 8441), frame level. Drives the
## server with the raw h2 test client: an Extended CONNECT opens a WebSocket
## on a stream, then DATA frames carry WebSocket framing both ways.

import std/[unittest, net, httpcore, os, atomics, tables, strutils]
import vortex/[settings, request, server]
import vortex/http2/frames
import ./h2client
when defined(wsDeflate):
  import vortex/websocket/deflate

var concurrent: Atomic[int]
var maxConcurrent: Atomic[int]

proc handler(req: Request, res: Response) {.gcsafe.} =
  if req.isWebSocketUpgrade:
    let ws = req.acceptWebSocket(["chat", "json"])
    ws.onMessage = proc(ws: WebSocket, data: string, kind: WsKind) {.gcsafe.} =
      if data == "proto?":
        ws.send(ws.subprotocol)
      elif data == "blockme":
        ws.blocking(data):
          let now = concurrent.fetchAdd(1) + 1
          var m = maxConcurrent.load
          while now > m and not maxConcurrent.compareExchange(m, now): discard
          sleep(40)
          ws.send("b:" & msg)
          discard concurrent.fetchSub(1)
      else:
        ws.send(data, kind)                    # echo, same kind
  else:
    res.send(Http200, "not ws")

var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, workerThreads = 4)).start(0)
let port = srv.port

# --- WebSocket framing over DATA --------------------------------------------

proc wsClient(op: uint8, payload: string, fin = true): string =
  ## A masked client WebSocket frame (RFC 6455) to place in a DATA payload.
  result = newStringOfCap(payload.len + 6)
  result.add char((if fin: 0x80'u8 else: 0'u8) or op)
  check payload.len < 126
  result.add char(0x80 or payload.len)         # mask bit + 7-bit length
  let mask = [0x21'u8, 0x43, 0x65, 0x87]
  for b in mask: result.add char(b)
  for i in 0 ..< payload.len:
    result.add char(uint8(payload[i]) xor mask[i and 3])

type WsMsg = tuple[op: int, fin: bool, payload: string]

proc parseWs(buf: string): (seq[WsMsg], int) =
  ## Parse complete server (unmasked) WebSocket frames from `buf`; return the
  ## frames and the number of bytes consumed.
  var pos = 0
  while pos + 2 <= buf.len:
    let b0 = uint8(buf[pos])
    let b1 = uint8(buf[pos + 1])
    check (b1 and 0x80) == 0                 # server frames are unmasked
    var ln = int(b1 and 0x7f)
    var hdr = 2
    if ln == 126:
      if pos + 4 > buf.len: break
      ln = (int(uint8(buf[pos + 2])) shl 8) or int(uint8(buf[pos + 3]))
      hdr = 4
    if pos + hdr + ln > buf.len: break
    result[0].add (int(b0 and 0x0f), (b0 and 0x80) != 0,
                   buf[pos + hdr ..< pos + hdr + ln])
    pos += hdr + ln
  result[1] = pos

proc dataOn(frames: seq[Frame], sid: uint32): string =
  for f in frames:
    if f.typ == uint8(ftData) and f.streamId == sid: result.add f.payload

proc endStreamOn(frames: seq[Frame], sid: uint32): bool =
  for f in frames:
    if f.typ == uint8(ftData) and f.streamId == sid and
        (f.flags and flagEndStream) != 0: return true

var streamAcc: Table[uint32, string]     # per-stream DATA payloads, one conn

proc recvWs(c: var H2TestConn, sid: uint32, count: int): seq[WsMsg] =
  ## Read until at least `count` WebSocket frames are parsed on `sid`. DATA
  ## for every stream is retained (a batch may interleave streams), so a
  ## later read on another stream still sees its bytes.
  var tries = 0
  while parseWs(streamAcc.getOrDefault(sid))[0].len < count and tries < 30:
    inc tries
    let frames = c.readFrames(1000, until = proc(fr: seq[Frame]): bool =
      for f in fr:
        if f.typ == uint8(ftData) and f.streamId == sid: return true
      false)
    for f in frames:
      if f.typ == uint8(ftData):
        streamAcc.mgetOrPut(f.streamId, "").add f.payload
    if frames.len == 0: break
  parseWs(streamAcc.getOrDefault(sid))[0]

proc openWs(c: var H2TestConn, sid: uint32,
            extra: openArray[(string, string)] = []): string =
  ## Send an Extended CONNECT and return the negotiated :status.
  if sid == 1: streamAcc.clear()          # every test opens stream 1 first
  var hdrs = @[(":method", "CONNECT"), (":protocol", "websocket"),
               (":scheme", "http"), (":path", "/"), (":authority", "x"),
               ("sec-websocket-version", "13")]
  for e in extra: hdrs.add e
  var f = ""
  f.addExtendedConnect(sid, hdrs)
  c.sendRaw(f)
  let frames = c.readFrames(1500, until = proc(fr: seq[Frame]): bool =
    for x in fr:
      if x.typ == uint8(ftHeaders) and x.streamId == sid: return true
    false)
  for x in frames:
    if x.typ == uint8(ftHeaders) and x.streamId == sid:
      for (n, v) in decodeHeaders(x.payload):
        if n == ":status": result = v

const opText = 0x1
const opBinary = 0x2
const opClose = 0x8
const opPing = 0x9
const opPong = 0xA

suite "HTTP/2 Extended CONNECT WebSockets (RFC 8441)":
  test "server advertises SETTINGS_ENABLE_CONNECT_PROTOCOL":
    var c = newH2TestConn(port)
    let frames = c.readFrames(1000, until = proc(fr: seq[Frame]): bool =
      fr.count(ftSettings) >= 1)
    var enabled = false
    for f in frames:
      if f.typ == uint8(ftSettings) and (f.flags and flagAck) == 0:
        var i = 0
        while i + 6 <= f.payload.len:
          if get16(f.payload, i) == setEnableConnectProtocol and
              get32(f.payload, i + 2) == 1: enabled = true
          i += 6
    check enabled
    c.close()

  test "handshake, text echo, binary echo":
    var c = newH2TestConn(port)
    check c.openWs(1) == "200"
    var f = ""
    f.addData(1, wsClient(opText, "hello"))
    f.addData(1, wsClient(opBinary, "raw"))
    c.sendRaw(f)
    let msgs = c.recvWs(1, 2)
    check msgs.len >= 2
    check msgs[0] == (opText, true, "hello")
    check msgs[1] == (opBinary, true, "raw")
    c.close()

  test "subprotocol negotiated on the stream":
    var c = newH2TestConn(port)
    check c.openWs(1, [("sec-websocket-protocol", "json, chat")]) == "200"
    c.sendRaw(block: (var f = ""; f.addData(1, wsClient(opText, "proto?")); f))
    let msgs = c.recvWs(1, 1)
    check msgs[0].payload == "chat"
    c.close()

  test "ping is answered with a pong":
    var c = newH2TestConn(port)
    check c.openWs(1) == "200"
    c.sendRaw(block: (var f = ""; f.addData(1, wsClient(opPing, "hi")); f))
    let msgs = c.recvWs(1, 1)
    check msgs[0].op == opPong
    check msgs[0].payload == "hi"
    c.close()

  test "fragmented message is reassembled":
    var c = newH2TestConn(port)
    check c.openWs(1) == "200"
    var f = ""
    f.addData(1, wsClient(opText, "Hel", fin = false))
    f.addData(1, wsClient(0x0, "lo!"))          # continuation, FIN
    c.sendRaw(f)
    let msgs = c.recvWs(1, 1)
    check msgs[0] == (opText, true, "Hello!")
    c.close()

  test "close handshake ends the stream":
    var c = newH2TestConn(port)
    check c.openWs(1) == "200"
    # close frame: 2-byte code 1000
    c.sendRaw(block: (var f = "";
      f.addData(1, wsClient(opClose, "\x03\xe8")); f))
    var acc = ""
    var sawClose = false
    var ended = false
    for _ in 0 ..< 20:
      let frames = c.readFrames(1000, until = proc(fr: seq[Frame]): bool =
        for x in fr:
          if x.typ == uint8(ftData) and x.streamId == 1: return true
        false)
      acc.add dataOn(frames, 1)
      if endStreamOn(frames, 1): ended = true
      for m in parseWs(acc)[0]:
        if m.op == opClose: sawClose = true
      if (sawClose and ended) or frames.len == 0: break
    check sawClose
    check ended
    c.close()

  test "two streams multiplex independent WebSockets":
    var c = newH2TestConn(port)
    check c.openWs(1) == "200"
    check c.openWs(3) == "200"
    var f = ""
    f.addData(1, wsClient(opText, "one"))
    f.addData(3, wsClient(opText, "three"))
    c.sendRaw(f)
    check c.recvWs(1, 1)[0].payload == "one"
    check c.recvWs(3, 1)[0].payload == "three"
    c.close()

  test "ws.blocking serializes one stream, in order":
    maxConcurrent.store(0)
    var c = newH2TestConn(port)
    check c.openWs(1) == "200"
    var f = ""
    for i in 0 ..< 4: f.addData(1, wsClient(opText, "blockme"))
    c.sendRaw(f)
    let msgs = c.recvWs(1, 4)
    check msgs.len >= 4
    for i in 0 ..< 4: check msgs[i].payload == "b:blockme"
    check maxConcurrent.load == 1               # per-stream pin held
    c.close()

  when defined(wsDeflate):
    test "permessage-deflate negotiated and round-trips over HTTP/2":
      streamAcc.clear()
      var c = newH2TestConn(port)
      var hdrs = @[(":method", "CONNECT"), (":protocol", "websocket"),
                   (":scheme", "http"), (":path", "/"), (":authority", "x"),
                   ("sec-websocket-version", "13"),
                   ("sec-websocket-extensions", "permessage-deflate")]
      var f = ""
      f.addExtendedConnect(1, hdrs)
      c.sendRaw(f)
      let hs = c.readFrames(1500, until = proc(fr: seq[Frame]): bool =
        for x in fr:
          if x.typ == uint8(ftHeaders) and x.streamId == 1: return true
        false)
      var ext = ""
      for x in hs:
        if x.typ == uint8(ftHeaders) and x.streamId == 1:
          for (n, v) in decodeHeaders(x.payload):
            if n == "sec-websocket-extensions": ext = v
      check "permessage-deflate" in ext
      # Client sends an uncompressed frame; the server compresses the echo.
      c.sendRaw(block: (var d = ""; d.addData(1, wsClient(opText, "hello")); d))
      var acc = ""
      for _ in 0 ..< 20:
        let fr = c.readFrames(1000, until = proc(fr: seq[Frame]): bool =
          for x in fr:
            if x.typ == uint8(ftData) and x.streamId == 1: return true
          false)
        acc.add dataOn(fr, 1)
        if acc.len >= 2 or fr.len == 0: break
      let b0 = uint8(acc[0])
      let ln = int(uint8(acc[1]) and 0x7f)
      check (b0 and 0x40) != 0                  # RSV1: the echo was compressed
      var inf = initInflator(false)
      let r = inf.decompress(acc[2 ..< 2 + ln], 1 shl 20)
      inf.close()
      check r.status == dsOk
      check r.data == "hello"
      c.close()

srv.close()
echo "server shut down cleanly"
