import std/[unittest, net, httpcore, posix, strutils]
import vortex/[settings, request, server]
import ./helper

proc handler(req: Request, res: Response) {.gcsafe.} =
  if req.isWebSocketUpgrade:
    let ws = req.acceptWebSocket()
    ws.onMessage = proc(ws: WebSocket, data: string, kind: WsKind) {.gcsafe.} =
      ws.send(data, kind)
  else:
    res.send(Http200, "http", "text/plain")

# Fast keepalive so the test runs in a few seconds.
var srv = start(RequestHandler(handler),
                initSettings(port = Port(0), numThreads = 1,
                             wsPingInterval = 1, wsPongTimeout = 1))
let port = srv.port

proc readFrame(s: Socket): tuple[ok: bool, op: int, payload: string] =
  ## Read one server frame; ok = false on EOF/timeout.
  var h = newString(2)
  var got = 0
  while got < 2:
    let k = recv(s.getFd, addr h[got], 2 - got, cint(0))
    if k <= 0: return (false, 0, "")
    got += k
  let op = int(uint8(h[0])) and 0x0f
  let ln = int(uint8(h[1]) and 0x7f)          # control frames are <= 125
  var payload = newString(ln)
  got = 0
  while got < ln:
    let k = recv(s.getFd, addr payload[got], ln - got, cint(0))
    if k <= 0: return (false, 0, "")
    got += k
  (true, op, payload)

proc sendPong(s: Socket, payload = "") =
  var f = "\x8a" & char(0x80 or payload.len)  # fin+pong, masked
  let m = [0x11'u8, 0x22, 0x33, 0x44]
  for x in m: f.add char(x)
  for i in 0 ..< payload.len: f.add char(uint8(payload[i]) xor m[i and 3])
  s.send(f)

proc openWs(): Socket =
  result = newSocket(buffered = false)
  result.connect("127.0.0.1", port)
  result.send("GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n" &
              "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" &
              "Sec-WebSocket-Version: 13\r\n\r\n")
  result.setRecvTimeout(5000)
  var hdr = ""
  var one = newString(1)
  while not hdr.endsWith("\r\n\r\n"):
    let k = recv(result.getFd, addr one[0], 1, cint(0))
    if k <= 0: break
    hdr.add one[0]
  doAssert "101" in hdr, hdr

suite "websocket idle ping/timeout":
  test "server pings an idle connection":
    let s = openWs()
    defer: s.close()
    let f = s.readFrame()                      # nothing sent: expect a ping
    check f.ok
    check f.op == 0x9                          # ping opcode

  test "an unanswered ping closes the connection":
    let s = openWs()
    defer: s.close()
    check s.readFrame().op == 0x9              # ping arrives
    # Do not pong: the pong deadline elapses and the server drops us.
    let f = s.readFrame()
    check not f.ok                             # EOF

  test "answering the ping keeps the connection alive":
    let s = openWs()
    defer: s.close()
    check s.readFrame().op == 0x9              # first ping
    s.sendPong()                               # reply -> idle timer resets
    let f = s.readFrame()                      # alive: another ping, not EOF
    check f.ok
    check f.op == 0x9

  test "a data message resets the idle timer (no premature close)":
    let s = openWs()
    defer: s.close()
    check s.readFrame().op == 0x9
    s.sendPong()
    # Send a data frame; server echoes it and the connection stays up.
    var d = "\x81\x83"                          # fin+text, masked, len 3
    let m = [0x11'u8, 0x22, 0x33, 0x44]
    for x in m: d.add char(x)
    for i, ch in "abc": d.add char(uint8(ch) xor m[i and 3])
    s.send(d)
    let f = s.readFrame()
    check f.ok
    check (f.op == 0x1 and f.payload == "abc") or f.op == 0x9  # echo or next ping

srv.close()
echo "server shut down cleanly"
