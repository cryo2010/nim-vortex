import std/[unittest, net, httpcore, posix, strutils, os]
import vortex/[settings, request, server]
import ./helper

# The handler answers "buf?" with the current bufferedAmount, and on "flood"
# it pushes a large burst the client is slow to read, then reports the peak
# backlog once onDrain fires (the backlog having emptied).
const FloodFrames = 512
const FloodPayload = 16384        # 512 * 16 KiB = 8 MiB, well past any socket buffer

proc handler(req: Request, res: Response) {.gcsafe.} =
  if req.isWebSocketUpgrade:
    let ws = req.acceptWebSocket()
    ws.onMessage = proc(ws: WebSocket, data: string, kind: WsKind) {.gcsafe.} =
      if data == "buf?":
        ws.send($ws.bufferedAmount)            # 0 while idle
      elif data == "flood":
        let blob = repeat('x', FloodPayload)
        for i in 0 ..< FloodFrames:
          ws.send(blob)
        # The client has not started reading, so the socket buffer is full
        # and most of the burst is parked in the write buffer.
        let peak = ws.bufferedAmount
        ws.onDrain = proc(ws: WebSocket) {.gcsafe.} =
          ws.send("drained:" & $peak)          # backlog is empty here
  else:
    res.send(Http200, "http")

var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1)).start(0)
let port = srv.port

proc recvN(s: Socket, n: int): string =
  result = newString(n)
  var got = 0
  while got < n:
    let k = recv(s.getFd, addr result[got], n - got, cint(0))
    if k <= 0: raise newException(IOError, "short read")
    got += k

proc recvText(s: Socket): string =
  let h = recvN(s, 2)
  doAssert (int(uint8(h[0])) and 0x0f) == 0x1        # text frame
  var ln = int(uint8(h[1]) and 0x7f)
  if ln == 126:
    let e = recvN(s, 2); ln = (int(uint8(e[0])) shl 8) or int(uint8(e[1]))
  if ln > 0: recvN(s, ln) else: ""

proc sendText(s: Socket, p: string) =
  var f = "\x81" & char(0x80 or p.len)
  let m = [0x21'u8, 0x43, 0x65, 0x87]
  for x in m: f.add char(x)
  for i in 0 ..< p.len: f.add char(uint8(p[i]) xor m[i and 3])
  s.send(f)

proc openWs(): Socket =
  result = newSocket(buffered = false)
  result.connect("127.0.0.1", port)
  result.send("GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n" &
              "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" &
              "Sec-WebSocket-Version: 13\r\n\r\n")
  result.setRecvTimeout(8000)
  var hdr = ""
  var one = newString(1)
  while not hdr.endsWith("\r\n\r\n"):
    let k = recv(result.getFd, addr one[0], 1, cint(0))
    if k <= 0: break
    hdr.add one[0]
  doAssert "101" in hdr, hdr

suite "websocket backpressure introspection":
  test "bufferedAmount is zero on an idle connection":
    let s = openWs()
    defer: s.close()
    s.sendText("buf?")
    check s.recvText() == "0"

  test "backlog builds under a slow reader and onDrain fires on drain":
    let s = openWs()
    defer: s.close()
    s.sendText("flood")
    # Stay silent long enough for the server's burst to fill the socket
    # buffer and back up (peak > 0); reading concurrently would let the
    # kernel drain it as fast as it is produced and no backlog would form.
    sleep(300)
    var frames = 0
    var peak = -1
    while true:
      let m = s.recvText()
      if m.startsWith("drained:"):
        peak = parseInt(m["drained:".len .. ^1])
        break
      inc frames
      check m.len == FloodPayload
    check frames == FloodFrames                        # every message delivered
    check peak > 0                                      # the write buffer backed up

srv.close()
echo "server shut down cleanly"
