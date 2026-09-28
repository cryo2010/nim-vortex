import std/[unittest, net, httpcore, strutils]
import vortex/[settings, request, server]
import ./helper
import ./wsclient

# Off-loop probe for the subprotocol accessor: only the length crosses the
# thread boundary, so the probe itself never copies a string between threads.
var offLoopThread: Thread[WebSocket]
var offLoopProtoLen = -1

proc readProtoOffLoop(ws: WebSocket) {.thread.} =
  offLoopProtoLen = ws.subprotocol.len

proc handler(req: Request, res: Response) {.gcsafe.} =
  if req.isWebSocketUpgrade:
    # Server supports "chat" then "json" (server preference order).
    let ws = req.acceptWebSocket(["chat", "json"])
    ws.onMessage = proc(ws: WebSocket, data: string, kind: WsKind) {.gcsafe.} =
      if data == "proto?": ws.send(ws.subprotocol)   # report the negotiated one
      elif data == "proto-offloop?":
        # Read it from a non-loop thread: the accessor must refuse rather
        # than resolve the WsConn ref there.
        offLoopProtoLen = -1
        createThread(offLoopThread, readProtoOffLoop, ws)
        joinThread(offLoopThread)
        ws.send($offLoopProtoLen)
      else: ws.send(data, kind)
  else:
    res.send(Http200, "http")

proc recvText(s: Socket): string =
  let f = s.recvFrame()
  check f.op == 0x1                                 # text frame
  f.payload

withServer(RequestHandler(handler), initVortexConfig(numThreads = 1), srv):
  let port = srv.port

  proc openOffer(protocolOffer: string): tuple[s: Socket, resp: string] =
    let extra =
      if protocolOffer.len > 0:
        "Sec-WebSocket-Protocol: " & protocolOffer & "\r\n"
      else: ""
    let (sock, resp) = openWs(port, extraHeaders = extra)
    (sock, resp)

  suite "websocket subprotocol negotiation":
    test "server preference picks the first supported protocol":
      # Client offers json first, but the server prefers chat.
      let (s, resp) = openOffer("json, chat")
      defer: s.close()
      check "Sec-WebSocket-Protocol: chat" in resp
      s.sendText("proto?")
      check s.recvText() == "chat"

    test "second-choice protocol is negotiated when the first is not offered":
      let (s, resp) = openOffer("json")
      defer: s.close()
      check "Sec-WebSocket-Protocol: json" in resp
      s.sendText("proto?")
      check s.recvText() == "json"

    test "no matching protocol: header omitted, subprotocol empty":
      let (s, resp) = openOffer("mqtt, stomp")
      defer: s.close()
      check "Sec-WebSocket-Protocol" notin resp
      s.sendText("proto?")
      check s.recvText() == ""

    test "subprotocol is loop-thread only: off-loop it reports empty":
      let (s, resp) = openOffer("chat")
      defer: s.close()
      check "Sec-WebSocket-Protocol: chat" in resp
      s.sendText("proto?")
      check s.recvText() == "chat"            # the loop thread sees the value
      s.sendText("proto-offloop?")
      check s.recvText() == "0"               # a worker gets "", not the ref

    test "no offer at all: header omitted, handshake still succeeds":
      let (s, resp) = openOffer("")
      defer: s.close()
      check "Sec-WebSocket-Protocol" notin resp
      s.sendText("hello")
      check s.recvText() == "hello"                    # echo still works

echo "server shut down cleanly"
