## Regression coverage for the conformance fixes the Autobahn run drove:
## strict UTF-8 validation, close-frame validation, and a WebSocket
## receive buffer bounded by maxWsMessageSize (not the HTTP body limit).

import std/[unittest, net, httpcore, posix, strutils]
import vortex/[settings, request, server]
import ./helper

proc handler(req: Request, res: Response) {.gcsafe.} =
  if req.isWebSocketUpgrade:
    let ws = req.acceptWebSocket()
    ws.onMessage = proc(ws: WebSocket, data: string, kind: WsKind) {.gcsafe.} =
      ws.send(data, kind)
  else:
    res.send(Http200, "http")

# Small HTTP body limit but a larger WebSocket message limit: a message
# between the two must still be accepted (the buffer cap is WS-specific).
var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, maxBodySize = 32 * 1024, maxWsMessageSize = 512 * 1024)).start(0)
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
  elif ln == 127:
    let e = recvN(s, 8)
    ln = 0
    for i in 0 ..< 8: ln = (ln shl 8) or int(uint8(e[i]))
  ((int(uint8(h[0])) and 0x0f), (if ln > 0: recvN(s, ln) else: ""))

proc sendFrame(s: Socket, op: int, payload: string) =
  var f = ""
  f.add char(0x80 or op)                    # fin + opcode
  let n = payload.len
  if n <= 125:
    f.add char(0x80 or n)
  elif n <= 0xffff:
    f.add char(0x80 or 126)
    f.add char(char((n shr 8) and 0xff)); f.add char(char(n and 0xff))
  else:
    f.add char(0x80 or 127)
    for i in countdown(7, 0): f.add char(char((n shr (i*8)) and 0xff))
  let m = [0x37'u8, 0xfa, 0x21, 0x3d]
  for x in m: f.add char(x)
  for i in 0 ..< n: f.add char(uint8(payload[i]) xor m[i and 3])
  s.send(f)

proc closeCode(payload: string): int =
  (int(uint8(payload[0])) shl 8) or int(uint8(payload[1]))

proc openWs(): Socket =
  result = newSocket(buffered = false)
  result.connect("127.0.0.1", port)
  result.send("GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n" &
              "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" &
              "Sec-WebSocket-Version: 13\r\n\r\n")
  result.setRecvTimeout(3000)
  var hdr = ""
  var one = newString(1)
  while not hdr.endsWith("\r\n\r\n"):
    let k = recv(result.getFd, addr one[0], 1, cint(0))
    if k <= 0: break
    hdr.add one[0]
  check "101" in hdr

suite "websocket conformance":
  test "valid multi-byte UTF-8 text is echoed":
    let s = openWs()
    defer: s.close()
    let msg = "caf\xc3\xa9 \xe6\x97\xa5\xe6\x9c\xac \xf0\x9f\x98\x80"  # café 日本 emoji
    s.sendFrame(0x1, msg)
    let f = s.recvFrame()
    check f.op == 0x1
    check f.payload == msg

  test "invalid UTF-8 text closes with 1007":
    let s = openWs()
    defer: s.close()
    s.sendFrame(0x1, "\xc3\x28")             # bad 2-byte sequence
    let f = s.recvFrame()
    check f.op == 0x8
    check f.payload.closeCode == 1007

  test "overlong UTF-8 encoding closes with 1007":
    let s = openWs()
    defer: s.close()
    s.sendFrame(0x1, "\xc0\xaf")             # overlong '/'
    let f = s.recvFrame()
    check f.op == 0x8
    check f.payload.closeCode == 1007

  test "one-byte close payload is rejected with 1002":
    let s = openWs()
    defer: s.close()
    s.sendFrame(0x8, "\x03")                 # length-1 close payload
    let f = s.recvFrame()
    check f.op == 0x8
    check f.payload.closeCode == 1002

  test "invalid close code is rejected with 1002":
    let s = openWs()
    defer: s.close()
    s.sendFrame(0x8, "\x03\xed")             # 1005 (reserved, not allowed)
    let f = s.recvFrame()
    check f.op == 0x8
    check f.payload.closeCode == 1002

  test "valid close is echoed":
    let s = openWs()
    defer: s.close()
    s.sendFrame(0x8, "\x03\xe8")             # 1000
    let f = s.recvFrame()
    check f.op == 0x8
    check f.payload.closeCode == 1000

  test "message larger than maxBodySize but within maxWsMessageSize":
    let s = openWs()
    defer: s.close()
    let big = repeat('x', 200 * 1024)        # 200 KiB > 32 KiB body limit
    s.sendFrame(0x2, big)
    let f = s.recvFrame()
    check f.op == 0x2
    check f.payload.len == big.len
    check f.payload == big

srv.close()
echo "server shut down cleanly"
