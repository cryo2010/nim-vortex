import std/[unittest, net, httpcore]
import vortex/[settings, request, server]
import vortex/asyncdispatch
import ./helper
import ./wsclient

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

withServer(RequestHandler(handler), initVortexConfig(numThreads = 1), srv):
  let port = srv.port

  suite "websocket ws.doAsync (asyncdispatch adapter)":
    test "await inside a message handler, then reply":
      let s = openWs(port).sock
      defer: s.close()
      sendText(s, "hi42")
      let f = s.recvFrame()
      check f.op == 0x1
      check f.payload == "async: hi42"

    test "two awaiting messages both get answered":
      let s = openWs(port).sock
      defer: s.close()
      sendText(s, "one")
      sendText(s, "two")
      var got: seq[string]
      got.add s.recvFrame().payload
      got.add s.recvFrame().payload
      check "async: one" in got
      check "async: two" in got

    test "uncaught exception in the async body closes with 1011":
      let s = openWs(port).sock
      defer: s.close()
      sendText(s, "boom")
      let f = s.recvFrame()
      check f.op == 0x8                          # close
      let code = (uint16(uint8(f.payload[0])) shl 8) or uint16(uint8(f.payload[1]))
      check code == 1011

echo "server shut down cleanly"
