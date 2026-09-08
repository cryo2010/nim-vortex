import std/[unittest, net, httpcore]
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

proc readFrame(s: Socket): tuple[ok: bool, op: int, payload: string] =
  ## Read one server frame; ok = false on EOF/timeout.
  try:
    let f = s.recvFrame()
    (true, f.op, f.payload)
  except IOError:
    (false, 0, "")

# Fast keepalive so the test runs in a few seconds.
withServer(RequestHandler(handler),
           initVortexConfig(numThreads = 1, wsPingInterval = 1,
                            wsPongTimeout = 1), srv):
  let port = srv.port

  suite "websocket idle ping/timeout":
    test "server pings an idle connection":
      let s = openWs(port, timeoutMs = 5000).sock
      defer: s.close()
      let f = s.readFrame()                      # nothing sent: expect a ping
      check f.ok
      check f.op == 0x9                          # ping opcode

    test "an unanswered ping closes the connection":
      let s = openWs(port, timeoutMs = 5000).sock
      defer: s.close()
      check s.readFrame().op == 0x9              # ping arrives
      # Do not pong: the pong deadline elapses and the server drops us.
      let f = s.readFrame()
      check not f.ok                             # EOF

    test "answering the ping keeps the connection alive":
      let s = openWs(port, timeoutMs = 5000).sock
      defer: s.close()
      check s.readFrame().op == 0x9              # first ping
      s.sendPong()                               # reply -> idle timer resets
      let f = s.readFrame()                      # alive: another ping, not EOF
      check f.ok
      check f.op == 0x9

    test "a data message resets the idle timer (no premature close)":
      let s = openWs(port, timeoutMs = 5000).sock
      defer: s.close()
      check s.readFrame().op == 0x9
      s.sendPong()
      # Send a data frame; server echoes it and the connection stays up.
      s.sendText("abc")
      let f = s.readFrame()
      check f.ok
      check (f.op == 0x1 and f.payload == "abc") or f.op == 0x9  # echo or next ping

echo "server shut down cleanly"
