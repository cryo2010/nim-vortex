import std/[unittest, net, httpcore, posix, strutils]
import vortex/[settings, request, server]
import ./helper

proc handler(req: Request, res: Response) {.gcsafe.} =
  if req.isWebSocketUpgrade:
    # Server supports "chat" then "json" (server preference order).
    let ws = req.acceptWebSocket(["chat", "json"])
    ws.onMessage = proc(ws: WebSocket, data: string, kind: WsKind) {.gcsafe.} =
      if data == "proto?": ws.send(ws.subprotocol)   # report the negotiated one
      else: ws.send(data, kind)
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

proc openWs(protocolOffer = ""): tuple[s: Socket, resp: string] =
  result.s = newSocket(buffered = false)
  result.s.connect("127.0.0.1", port)
  var req = "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n" &
            "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" &
            "Sec-WebSocket-Version: 13\r\n"
  if protocolOffer.len > 0:
    req.add "Sec-WebSocket-Protocol: " & protocolOffer & "\r\n"
  req.add "\r\n"
  result.s.send(req)
  result.s.setRecvTimeout(2000)
  var hdr = ""
  var one = newString(1)
  while not hdr.endsWith("\r\n\r\n"):
    let k = recv(result.s.getFd, addr one[0], 1, cint(0))
    if k <= 0: break
    hdr.add one[0]
  doAssert "101" in hdr, hdr
  result.resp = hdr

suite "websocket subprotocol negotiation":
  test "server preference picks the first supported protocol":
    # Client offers json first, but the server prefers chat.
    let (s, resp) = openWs("json, chat")
    defer: s.close()
    check "Sec-WebSocket-Protocol: chat" in resp
    s.sendText("proto?")
    check s.recvText() == "chat"

  test "second-choice protocol is negotiated when the first is not offered":
    let (s, resp) = openWs("json")
    defer: s.close()
    check "Sec-WebSocket-Protocol: json" in resp
    s.sendText("proto?")
    check s.recvText() == "json"

  test "no matching protocol: header omitted, subprotocol empty":
    let (s, resp) = openWs("mqtt, stomp")
    defer: s.close()
    check "Sec-WebSocket-Protocol" notin resp
    s.sendText("proto?")
    check s.recvText() == ""

  test "no offer at all: header omitted, handshake still succeeds":
    let (s, resp) = openWs("")
    defer: s.close()
    check "Sec-WebSocket-Protocol" notin resp
    s.sendText("hello")
    check s.recvText() == "hello"                    # echo still works

srv.close()
echo "server shut down cleanly"
