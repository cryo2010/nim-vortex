import std/[unittest, net, httpcore, strutils, os]
import vortex/[settings, request, server]
import ./helper
import ./wsclient

# The handler answers "buf?" with the current bufferedAmount, and on "flood"
# it pushes a large burst the client is slow to read, then reports the peak
# backlog once onDrain fires (the backlog having emptied).
const FloodFrames = 512
const FloodPayload = 16384        # 512 * 16 KiB = 8 MiB, well past any socket buffer

proc handler(req: Request, res: Response) {.gcsafe.} =
  if req.isWebSocketUpgrade:
    let ws = req.acceptWebSocket()
    ws.onMessage = proc(ws: WebSocket, data: string, kind: WsKind) {.gcsafe.} =
      if data == "buf?":
        ws.send($ws.bufferedAmount)            # 0 while idle
      elif data == "flood":
        let blob = repeat('x', FloodPayload)
        for i in 0 ..< FloodFrames:
          ws.send(blob)
        # The client has not started reading, so the socket buffer is full
        # and most of the burst is parked in the write buffer.
        let peak = ws.bufferedAmount
        ws.onDrain = proc(ws: WebSocket) {.gcsafe.} =
          ws.send("drained:" & $peak)          # backlog is empty here
  else:
    res.send(Http200, "http")

proc recvText(s: Socket): string =
  let f = s.recvFrame()
  check f.op == 0x1                                 # text frame
  f.payload

withServer(RequestHandler(handler), initVortexConfig(numThreads = 1), srv):
  let port = srv.port

  suite "websocket backpressure introspection":
    test "bufferedAmount is zero on an idle connection":
      let s = openWs(port, timeoutMs = 8000).sock
      defer: s.close()
      s.sendText("buf?")
      check s.recvText() == "0"

    test "backlog builds under a slow reader and onDrain fires on drain":
      let s = openWs(port, timeoutMs = 8000).sock
      defer: s.close()
      s.sendText("flood")
      # Stay silent long enough for the server's burst to fill the socket
      # buffer and back up (peak > 0); reading concurrently would let the
      # kernel drain it as fast as it is produced and no backlog would form.
      sleep(300)
      var frames = 0
      var peak = -1
      while true:
        let m = s.recvText()
        if m.startsWith("drained:"):
          peak = parseInt(m["drained:".len .. ^1])
          break
        inc frames
        check m.len == FloodPayload
      check frames == FloodFrames                        # every message delivered
      check peak > 0                                      # the write buffer backed up

echo "server shut down cleanly"
