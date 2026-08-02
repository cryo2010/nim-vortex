## permessage-deflate (RFC 7692) over a live server. Built with
## -d:wsDeflate; the client side compresses/decompresses with the same
## deflate module the server uses.

import std/[unittest, net, httpcore, posix, strutils]
import vortex/[settings, request, server]
import vortex/websocket/deflate
import ./helper

proc handler(req: Request, res: Response) {.gcsafe.} =
  if req.isWebSocketUpgrade:
    let ws = req.acceptWebSocket()
    ws.onMessage = proc(ws: WebSocket, data: string, kind: WsKind) {.gcsafe.} =
      ws.send(data, kind)                     # echo (server compresses it back)
  else:
    res.send(Http200, "http", "text/plain")

# Small message cap so a bomb hits the limit quickly.
var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, maxWsMessageSize = 8 * 1024)).start(0)
let port = srv.port

# --- raw client with its own deflate context (matches server negotiation) ---

proc recvN(s: Socket, n: int): string =
  result = newString(n)
  var got = 0
  while got < n:
    let k = recv(s.getFd, addr result[got], n - got, cint(0))
    if k <= 0: raise newException(IOError, "short read")
    got += k

proc recvFrame(s: Socket): tuple[op: int, rsv1: bool, payload: string] =
  let h = recvN(s, 2)
  let rsv1 = (uint8(h[0]) and 0x40) != 0
  var ln = int(uint8(h[1]) and 0x7f)
  if ln == 126:
    let e = recvN(s, 2); ln = (int(uint8(e[0])) shl 8) or int(uint8(e[1]))
  elif ln == 127:
    let e = recvN(s, 8)
    ln = 0
    for i in 0 ..< 8: ln = (ln shl 8) or int(uint8(e[i]))
  ((int(uint8(h[0])) and 0x0f), rsv1, (if ln > 0: recvN(s, ln) else: ""))

proc sendMasked(s: Socket, op: int, payload: string, rsv1: bool) =
  var f = ""
  f.add char(0x80 or (if rsv1: 0x40 else: 0) or op)
  let n = payload.len
  if n <= 125:
    f.add char(0x80 or n)
  elif n <= 0xffff:
    f.add char(0x80 or 126)
    f.add char(char((n shr 8) and 0xff)); f.add char(char(n and 0xff))
  else:
    f.add char(0x80 or 127)
    for i in countdown(7, 0): f.add char(char((n shr (i*8)) and 0xff))
  let m = [0xa1'u8, 0xb2, 0xc3, 0xd4]
  for x in m: f.add char(x)
  for i in 0 ..< n: f.add char(uint8(payload[i]) xor m[i and 3])
  s.send(f)

type Client = object
  s: Socket
  cdef: Deflator
  cinf: Inflator

proc openWs(): Client =
  result.s = newSocket(buffered = false)
  result.s.connect("127.0.0.1", port)
  result.s.send("GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n" &
    "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" &
    "Sec-WebSocket-Version: 13\r\n" &
    "Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n")
  result.s.setRecvTimeout(3000)
  var hdr = ""
  var one = newString(1)
  while not hdr.endsWith("\r\n\r\n"):
    let k = recv(result.s.getFd, addr one[0], 1, cint(0))
    if k <= 0: break
    hdr.add one[0]
  doAssert "101" in hdr, hdr
  doAssert "permessage-deflate" in hdr.toLowerAscii, "no extension: " & hdr
  result.cdef = initDeflator(15, false)       # context takeover, like the server
  result.cinf = initInflator(false)

proc sendText(c: var Client, msg: string) =
  c.s.sendMasked(0x1, c.cdef.compress(msg), rsv1 = true)

proc recvText(c: var Client): string =
  let f = c.s.recvFrame()
  doAssert f.op == 0x1
  if f.rsv1:
    let r = c.cinf.decompress(f.payload, 1 shl 20)
    doAssert r.status == dsOk
    return r.data
  f.payload

suite "permessage-deflate":
  test "handshake negotiates the extension":
    var c = openWs()                 # openWs asserts the response header
    defer: c.s.close()
    check c.cdef.inited and c.cinf.inited

  test "compressed text message round-trips (echo is compressed)":
    var c = openWs()
    defer: c.s.close()
    let msg = "the quick brown fox " & repeat("jumps ", 20)
    c.sendText(msg)
    let f = c.s.recvFrame()
    check f.op == 0x1
    check f.rsv1                     # server compressed the echo
    let r = c.cinf.decompress(f.payload, 1 shl 20)
    check r.status == dsOk
    check r.data == msg

  test "context takeover across two messages":
    var c = openWs()
    defer: c.s.close()
    c.sendText("hello hello hello hello")
    check c.recvText() == "hello hello hello hello"
    c.sendText("hello hello hello world")
    check c.recvText() == "hello hello hello world"

  test "an uncompressed frame is still accepted":
    var c = openWs()
    defer: c.s.close()
    c.s.sendMasked(0x1, "plain text", rsv1 = false)   # RSV1 = 0
    check c.recvText() == "plain text"

  test "decompression bomb is bounded (close 1009)":
    var c = openWs()
    defer: c.s.close()
    # ~1 MiB of one byte compresses tiny but inflates past the 8 KiB cap.
    c.s.sendMasked(0x1, c.cdef.compress(repeat('z', 1_000_000)), rsv1 = true)
    let f = c.s.recvFrame()
    check f.op == 0x8                # close
    let code = (uint16(uint8(f.payload[0])) shl 8) or uint16(uint8(f.payload[1]))
    check code == 1009

srv.close()
echo "server shut down cleanly"
