## Regression coverage for the conformance fixes the Autobahn run drove:
## strict UTF-8 validation, close-frame validation, and a WebSocket
## receive buffer bounded by maxWsMessageSize (not the HTTP body limit).

import std/[unittest, net, httpcore, strutils]
import vortex/[settings, request, server]
import ./helper
import ./wsclient

proc handler(req: Request, res: Response) {.gcsafe.} =
  if req.isWebSocketUpgrade:
    let ws = req.acceptWebSocket()
    ws.onMessage = proc(ws: WebSocket, data: string, kind: WsKind) {.gcsafe.} =
      ws.send(data, kind)
  else:
    res.send(Http200, "http")

proc closeCode(payload: string): int =
  (int(uint8(payload[0])) shl 8) or int(uint8(payload[1]))

# Small HTTP body limit but a larger WebSocket message limit: a message
# between the two must still be accepted (the buffer cap is WS-specific).
withServer(RequestHandler(handler),
           initVortexConfig(numThreads = 1, maxBodySize = 32 * 1024,
                            maxWsMessageSize = 512 * 1024), srv):
  let port = srv.port
  proc open(): Socket = openWs(port, timeoutMs = 3000).sock

  suite "websocket conformance":
    test "valid multi-byte UTF-8 text is echoed":
      let s = open()
      defer: s.close()
      let msg = "caf\xc3\xa9 \xe6\x97\xa5\xe6\x9c\xac \xf0\x9f\x98\x80"  # café 日本 emoji
      s.sendFrame(0x1, msg)
      let f = s.recvFrame()
      check f.op == 0x1
      check f.payload == msg

    test "invalid UTF-8 text closes with 1007":
      let s = open()
      defer: s.close()
      s.sendFrame(0x1, "\xc3\x28")             # bad 2-byte sequence
      let f = s.recvFrame()
      check f.op == 0x8
      check f.payload.closeCode == 1007

    test "overlong UTF-8 encoding closes with 1007":
      let s = open()
      defer: s.close()
      s.sendFrame(0x1, "\xc0\xaf")             # overlong '/'
      let f = s.recvFrame()
      check f.op == 0x8
      check f.payload.closeCode == 1007

    test "one-byte close payload is rejected with 1002":
      let s = open()
      defer: s.close()
      s.sendFrame(0x8, "\x03")                 # length-1 close payload
      let f = s.recvFrame()
      check f.op == 0x8
      check f.payload.closeCode == 1002

    test "invalid close code is rejected with 1002":
      let s = open()
      defer: s.close()
      s.sendFrame(0x8, "\x03\xed")             # 1005 (reserved, not allowed)
      let f = s.recvFrame()
      check f.op == 0x8
      check f.payload.closeCode == 1002

    test "valid close is echoed":
      let s = open()
      defer: s.close()
      s.sendFrame(0x8, "\x03\xe8")             # 1000
      let f = s.recvFrame()
      check f.op == 0x8
      check f.payload.closeCode == 1000

    test "message larger than maxBodySize but within maxWsMessageSize":
      let s = open()
      defer: s.close()
      let big = repeat('x', 200 * 1024)        # 200 KiB > 32 KiB body limit
      s.sendFrame(0x2, big)
      let f = s.recvFrame()
      check f.op == 0x2
      check f.payload.len == big.len
      check f.payload == big

echo "server shut down cleanly"
