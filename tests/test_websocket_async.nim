import std/[unittest, net, httpcore, posix, strutils]
import vortex/[settings, request, server]
import vortex/asyncdispatch
import ./helper

proc handler(req: Request, res: Response) {.gcsafe.} =
  if req.isWebSocketUpgrade:
    let ws = req.acceptWebSocket()
    ws.onMessage = proc(ws: WebSocket, data: string, kind: WsKind) {.gcsafe.} =
      if data == "boom":
        ws.doAsync:
          await sleepAsync(10)
          raise newException(ValueError, "kaboom")   # -> close 1011
      else:
        ws.doAsync:
          await sleepAsync(15)                        # loop keeps serving
          ws.send("async: " & data)
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

proc recvFrame(s: Socket): tuple[op: int, payload: string] =
  let h = recvN(s, 2)
  var ln = int(uint8(h[1]) and 0x7f)
  if ln == 126:
    let e = recvN(s, 2); ln = (int(uint8(e[0])) shl 8) or int(uint8(e[1]))
  ((int(uint8(h[0])) and 0x0f), (if ln > 0: recvN(s, ln) else: ""))

proc sendText(s: Socket, p: string) =
  var f = "\x81" & char(0x80 or p.len)
  let m = [0x11'u8, 0x22, 0x33, 0x44]
  for x in m: f.add char(x)
  for i in 0 ..< p.len: f.add char(uint8(p[i]) xor m[i and 3])
  s.send(f)

proc openWs(): Socket =
  result = newSocket(buffered = false)
  result.connect("127.0.0.1", port)
  result.send("GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n" &
              "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" &
              "Sec-WebSocket-Version: 13\r\n\r\n")
  result.setRecvTimeout(2000)
  var hdr = ""
  var one = newString(1)
  while not hdr.endsWith("\r\n\r\n"):
    let k = recv(result.getFd, addr one[0], 1, cint(0))
    if k <= 0: break
    hdr.add one[0]
  doAssert "101" in hdr, hdr

suite "websocket ws.doAsync (asyncdispatch adapter)":
  test "await inside a message handler, then reply":
    let s = openWs()
    defer: s.close()
    sendText(s, "hi42")
    let f = s.recvFrame()
    check f.op == 0x1
    check f.payload == "async: hi42"

  test "two awaiting messages both get answered":
    let s = openWs()
    defer: s.close()
    sendText(s, "one")
    sendText(s, "two")
    var got: seq[string]
    got.add s.recvFrame().payload
    got.add s.recvFrame().payload
    check "async: one" in got
    check "async: two" in got

  test "uncaught exception in the async body closes with 1011":
    let s = openWs()
    defer: s.close()
    sendText(s, "boom")
    let f = s.recvFrame()
    check f.op == 0x8                          # close
    let code = (uint16(uint8(f.payload[0])) shl 8) or uint16(uint8(f.payload[1]))
    check code == 1011

srv.close()
echo "server shut down cleanly"
