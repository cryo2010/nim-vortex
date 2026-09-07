## permessage-deflate (RFC 7692) over a live server. Built with
## -d:wsDeflate; the client side compresses/decompresses with the same
## deflate module the server uses.

import std/[unittest, net, httpcore, strutils]
import vortex/[settings, request, server]
import vortex/websocket/deflate
import ./helper
import ./wsclient

proc handler(req: Request, res: Response) {.gcsafe.} =
  if req.isWebSocketUpgrade:
    let ws = req.acceptWebSocket()
    ws.onMessage = proc(ws: WebSocket, data: string, kind: WsKind) {.gcsafe.} =
      ws.send(data, kind)                     # echo (server compresses it back)
  else:
    res.send(Http200, "http")

type Client = object
  s: Socket
  cdef: Deflator
  cinf: Inflator

# Small message cap so a bomb hits the limit quickly.
withServer(RequestHandler(handler),
           initVortexConfig(numThreads = 1, maxWsMessageSize = 8 * 1024), srv):
  let port = srv.port

  proc open(): Client =
    let (sock, hdr) = openWs(port, timeoutMs = 3000,
      extraHeaders = "Sec-WebSocket-Extensions: permessage-deflate\r\n")
    doAssert "permessage-deflate" in hdr.toLowerAscii, "no extension: " & hdr
    result.s = sock
    result.cdef = initDeflator(15, false)       # context takeover, like the server
    result.cinf = initInflator(false)

  proc sendText(c: var Client, msg: string) =
    c.s.sendFrame(0x1, c.cdef.compress(msg), rsv1 = true)

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
      var c = open()                   # open asserts the response header
      defer: c.s.close()
      check c.cdef.inited and c.cinf.inited

    test "compressed text message round-trips (echo is compressed)":
      var c = open()
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
      var c = open()
      defer: c.s.close()
      c.sendText("hello hello hello hello")
      check c.recvText() == "hello hello hello hello"
      c.sendText("hello hello hello world")
      check c.recvText() == "hello hello hello world"

    test "an uncompressed frame is still accepted":
      var c = open()
      defer: c.s.close()
      c.s.sendFrame(0x1, "plain text", rsv1 = false)   # RSV1 = 0
      check c.recvText() == "plain text"

    test "decompression bomb is bounded (close 1009)":
      var c = open()
      defer: c.s.close()
      # ~1 MiB of one byte compresses tiny but inflates past the 8 KiB cap.
      c.s.sendFrame(0x1, c.cdef.compress(repeat('z', 1_000_000)), rsv1 = true)
      let f = c.s.recvFrame()
      check f.op == 0x8                # close
      let code = (uint16(uint8(f.payload[0])) shl 8) or uint16(uint8(f.payload[1]))
      check code == 1009

echo "server shut down cleanly"
