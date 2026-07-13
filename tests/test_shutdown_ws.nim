## On graceful shutdown, an open HTTP/1.1 WebSocket receives a server-initiated
## close frame with code 1001 (going away).

import std/[unittest, net, posix, strutils, httpcore, os]
import vortex/[settings, request, server]
import ./helper

proc handler(req: Request, res: Response) {.gcsafe.} =
  let ws = req.acceptWebSocket()
  ws.onMessage = proc(ws: WebSocket, data: string, kind: WsKind) {.gcsafe.} =
    ws.send(data)

var srv = start(RequestHandler(handler),
                initSettings(port = Port(0), numThreads = 1, shutdownGrace = 5))
let port = srv.port

proc openWs(): Socket =
  result = newSocket(buffered = false)
  result.connect("127.0.0.1", port)
  result.send("GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n" &
              "Connection: Upgrade\r\n" &
              "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" &
              "Sec-WebSocket-Version: 13\r\n\r\n")
  result.setRecvTimeout(4000)
  var hdr = ""
  var one = newString(1)
  while not hdr.endsWith("\r\n\r\n"):
    let k = recv(result.getFd, addr one[0], 1, cint(0))
    if k <= 0: break
    hdr.add one[0]
  doAssert "101" in hdr, hdr

proc recvN(s: Socket, n: int): string =
  result = newString(n)
  var got = 0
  while got < n:
    let k = recv(s.getFd, addr result[got], n - got, cint(0))
    if k <= 0: raise newException(IOError, "short read")
    got += k

suite "graceful shutdown: WebSocket":
  test "an open WebSocket gets a 1001 going-away close":
    let s = openWs()
    sleep(100)                             # ensure the upgrade settled
    requestShutdown()                      # begin graceful drain
    # Read the server's close frame: 0x88 (FIN|close), then len, then 2-byte code.
    let h = s.recvN(2)
    check (uint8(h[0]) and 0x0f) == 0x08   # close opcode
    let ln = int(uint8(h[1]) and 0x7f)
    check ln >= 2
    let payload = s.recvN(ln)
    let code = (uint16(uint8(payload[0])) shl 8) or uint16(uint8(payload[1]))
    check code == 1001
    s.close()
    srv.waitFor()                          # the loop drains and exits

echo "server shut down cleanly"
