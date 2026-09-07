## ws.messages async iterator sugar (asyncdispatch adapter), driven from a plain
## `{.async.}` handler registered with `router.ws`. Raw frames so the wire is
## checked exactly.

import std/[unittest, net]
import vortex/[settings, request, server, routing]
import vortex/asyncdispatch
import ./helper
import ./wsclient

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

withServer(r.toHandler, initVortexConfig(numThreads = 1), srv):
  let port = srv.port

  suite "websocket ws.messages (plain async handler via router.ws)":
    test "iterates messages and echoes each in order":
      let s = openWs(port, "/chat").sock
      defer: s.close()
      sendText(s, "one")
      check s.recvFrame().payload == "echo: one"
      sendText(s, "two")
      check s.recvFrame().payload == "echo: two"

    test "the loop ends on peer close; the server keeps serving":
      let s1 = openWs(port, "/chat").sock
      sendText(s1, "a")
      check s1.recvFrame().payload == "echo: a"
      s1.close()
      let s2 = openWs(port, "/chat").sock
      defer: s2.close()
      sendText(s2, "b")
      check s2.recvFrame().payload == "echo: b"

    test "an exception in the loop closes the socket with 1011 (not HTTP 500)":
      let s = openWs(port, "/boom").sock
      defer: s.close()
      sendText(s, "trigger")
      let f = s.recvFrame()
      check f.op == 0x8                          # WS close frame, not HTTP bytes
      let code = (uint16(uint8(f.payload[0])) shl 8) or uint16(uint8(f.payload[1]))
      check code == 1011

echo "ws.messages ok"
