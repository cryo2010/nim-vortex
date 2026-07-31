## ws.messages async iterator sugar (asyncdispatch adapter), driven from a plain
## `{.async.}` handler registered with `router.ws`. Raw frames so the wire is
## checked exactly.

import std/[unittest, net, posix, strutils]
import vortex/[settings, request, server, router]
import vortex/adapters/asyncdispatch
import ./helper

proc chat(req: Request, res: Response) {.async.} =
  let ws = req.acceptWebSocket()
  ws.messages(msg):                  # loop over messages until the peer closes
    ws.send("echo: " & msg)

proc boom(req: Request, res: Response) {.async.} =
  let ws = req.acceptWebSocket()
  ws.messages(msg):
    raise newException(ValueError, "kaboom")   # -> WS close 1011, not HTTP 500

var r = newRouter()
r.ws("/chat", chat)
r.ws("/boom", boom)
var srv = start(r.toHandler, initSettings(port = Port(0), numThreads = 1))
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

proc openWs(path: string): Socket =
  result = newSocket(buffered = false)
  result.connect("127.0.0.1", port)
  result.send("GET " & path & " HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n" &
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

suite "websocket ws.messages (plain async handler via router.ws)":
  test "iterates messages and echoes each in order":
    let s = openWs("/chat")
    defer: s.close()
    sendText(s, "one")
    check s.recvFrame().payload == "echo: one"
    sendText(s, "two")
    check s.recvFrame().payload == "echo: two"

  test "the loop ends on peer close; the server keeps serving":
    let s1 = openWs("/chat")
    sendText(s1, "a")
    check s1.recvFrame().payload == "echo: a"
    s1.close()
    let s2 = openWs("/chat")
    defer: s2.close()
    sendText(s2, "b")
    check s2.recvFrame().payload == "echo: b"

  test "an exception in the loop closes the socket with 1011 (not HTTP 500)":
    let s = openWs("/boom")
    defer: s.close()
    sendText(s, "trigger")
    let f = s.recvFrame()
    check f.op == 0x8                          # WS close frame, not HTTP bytes
    let code = (uint16(uint8(f.payload[0])) shl 8) or uint16(uint8(f.payload[1]))
    check code == 1011

srv.close()
echo "ws.messages ok"
