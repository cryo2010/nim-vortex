import std/[unittest, net, httpcore, base64, strutils, posix, os]
import std/httpclient except Response
import vortex/[settings, request, server]
import vortex/websocket/sha1
import ./helper

# --- echo server ------------------------------------------------------------

var bgThread: Thread[WebSocket]

proc bgSend(ws: WebSocket) {.thread.} =
  ## Off-loop sender: exercises the outbox path for cross-thread ws.send.
  sleep(60)
  ws.send("from-thread")

proc handler(req: Request, res: Response) {.gcsafe.} =
  if req.isWebSocketUpgrade:
    let ws = req.acceptWebSocket()
    ws.onMessage = proc(ws: WebSocket, data: string, kind: WsKind) {.gcsafe.} =
      if data == "spawn":
        createThread(bgThread, bgSend, ws)      # send from a different thread
      elif data == "block":
        ws.blocking(data):                      # run on the worker pool
          sleep(20)                             # pretend to do blocking work
          ws.send("blocked:" & msg)
      else:
        ws.send(data, kind)                     # echo, same kind
    ws.onClose = proc(ws: WebSocket, code: uint16, reason: string) {.gcsafe.} =
      discard
  else:
    res.send(Http200, "not a websocket")

var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, maxWsMessageSize = 1024)).start(0)
let port = srv.port

# --- minimal raw client -----------------------------------------------------

const acceptMagic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

proc expectedAccept(key: string): string =
  encode(sha1(key & acceptMagic))

proc recvN(s: Socket, n: int): string =
  result = newString(n)
  var got = 0
  while got < n:
    let k = recv(s.getFd, addr result[got], n - got, cint(0))
    if k <= 0: raise newException(IOError, "short read")
    got += k

proc recvFrame(s: Socket): tuple[fin: bool, op: int, payload: string] =
  ## Read one server (unmasked) frame.
  let h = recvN(s, 2)
  let b0 = uint8(h[0]); let b1 = uint8(h[1])
  check (b1 and 0x80) == 0
  var length = int(b1 and 0x7f)
  if length == 126:
    let e = recvN(s, 2)
    length = (int(uint8(e[0])) shl 8) or int(uint8(e[1]))
  elif length == 127:
    let e = recvN(s, 8)
    length = 0
    for i in 0 ..< 8: length = (length shl 8) or int(uint8(e[i]))
  let payload = if length > 0: recvN(s, length) else: ""
  ((b0 and 0x80) != 0, int(b0 and 0x0f), payload)

proc sendFrame(s: Socket, op: int, payload: string, fin = true) =
  ## Build a masked client frame.
  var f = ""
  f.add char((if fin: 0x80 else: 0) or op)
  let n = payload.len
  if n <= 125:
    f.add char(0x80 or n)
  elif n <= 0xffff:
    f.add char(0x80 or 126)
    f.add char(char((n shr 8) and 0xff)); f.add char(char(n and 0xff))
  else:
    f.add char(0x80 or 127)
    for i in countdown(7, 0): f.add char(char((n shr (i*8)) and 0xff))
  let mask = [0x12'u8, 0x34, 0x56, 0x78]
  for m in mask: f.add char(m)
  for i in 0 ..< n: f.add char(uint8(payload[i]) xor mask[i and 3])
  s.send(f)

proc openWs(key = "dGhlIHNhbXBsZSBub25jZQ=="): Socket =
  result = newSocket(buffered = false)
  result.connect("127.0.0.1", port)
  result.send("GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n" &
              "Connection: Upgrade\r\nSec-WebSocket-Key: " & key & "\r\n" &
              "Sec-WebSocket-Version: 13\r\n\r\n")
  result.setRecvTimeout(2000)
  let resp = result.recvAvailable(2000)
  check "101 Switching Protocols" in resp
  check ("Sec-WebSocket-Accept: " & expectedAccept(key)) in resp

suite "websocket server":
  test "handshake completes with the right accept key":
    let s = openWs()                 # openWs asserts 101 + accept
    defer: s.close()
    check s != nil

  test "non-upgrade request is served normally":
    var client = newHttpClient()
    defer: client.close()
    check client.getContent("http://127.0.0.1:" & $port & "/") ==
      "not a websocket"

  test "echoes a text message":
    let s = openWs()
    defer: s.close()
    s.sendFrame(0x1, "hello")
    let f = s.recvFrame()
    check f.op == 0x1
    check f.fin
    check f.payload == "hello"

  test "echoes a binary message":
    let s = openWs()
    defer: s.close()
    s.sendFrame(0x2, "\x00\x01\x02\xff")
    let f = s.recvFrame()
    check f.op == 0x2
    check f.payload == "\x00\x01\x02\xff"

  test "reassembles a fragmented message":
    let s = openWs()
    defer: s.close()
    s.sendFrame(0x1, "Hello, ", fin = false)   # text, not final
    s.sendFrame(0x0, "world", fin = true)      # continuation, final
    let f = s.recvFrame()
    check f.op == 0x1
    check f.payload == "Hello, world"

  test "answers a ping with a matching pong":
    let s = openWs()
    defer: s.close()
    s.sendFrame(0x9, "ping-payload")           # ping
    let f = s.recvFrame()
    check f.op == 0xA                           # pong
    check f.payload == "ping-payload"

  test "control frame interleaved between fragments":
    let s = openWs()
    defer: s.close()
    s.sendFrame(0x1, "frag1", fin = false)
    s.sendFrame(0x9, "mid")                     # ping mid-message
    check s.recvFrame().op == 0xA               # pong first
    s.sendFrame(0x0, "frag2", fin = true)
    let f = s.recvFrame()
    check f.op == 0x1
    check f.payload == "frag1frag2"

  test "close handshake: server echoes close and drops the connection":
    let s = openWs()
    defer: s.close()
    # client close with code 1000
    s.sendFrame(0x8, "\x03\xe8")                # 0x03e8 = 1000
    let f = s.recvFrame()
    check f.op == 0x8
    check f.payload.len >= 2
    let code = (uint16(uint8(f.payload[0])) shl 8) or uint16(uint8(f.payload[1]))
    check code == 1000
    check s.waitForClose()

  test "ws.blocking runs the body on the worker pool":
    let s = openWs()
    defer: s.close()
    s.sendFrame(0x1, "block")
    let f = s.recvFrame()
    check f.op == 0x1
    check f.payload == "blocked:block"

  test "send from another thread reaches the client (outbox path)":
    let s = openWs()
    defer: s.close()
    s.sendFrame(0x1, "spawn")
    let f = s.recvFrame()
    check f.op == 0x1
    check f.payload == "from-thread"
    joinThread(bgThread)

  test "oversized message closes with 1009":
    let s = openWs()
    defer: s.close()
    # two 600-byte fragments = 1200 > maxWsMessageSize (1024)
    s.sendFrame(0x1, repeat('a', 600), fin = false)
    s.sendFrame(0x0, repeat('a', 600), fin = true)
    let f = s.recvFrame()
    check f.op == 0x8
    let code = (uint16(uint8(f.payload[0])) shl 8) or uint16(uint8(f.payload[1]))
    check code == 1009
    check s.waitForClose()

srv.close()
echo "server shut down cleanly"
