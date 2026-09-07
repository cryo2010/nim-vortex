## Per-connection backpressure for ws.blocking: messages from one connection
## must be handled one at a time (the connection is pinned while the worker
## runs), even with several worker threads available. Without pinning the
## rapid burst below would fan out across workers and overlap.

import std/[unittest, net, httpcore, os, atomics]
import vortex/[settings, request, server]
import ./helper
import ./wsclient

var concurrent: Atomic[int]      # bodies currently running
var maxConcurrent: Atomic[int]   # high-water mark observed

proc handler(req: Request, res: Response) {.gcsafe.} =
  if req.isWebSocketUpgrade:
    let ws = req.acceptWebSocket()
    ws.onMessage = proc(ws: WebSocket, data: string, kind: WsKind) {.gcsafe.} =
      ws.blocking(data):
        let now = concurrent.fetchAdd(1) + 1
        var m = maxConcurrent.load
        while now > m and not maxConcurrent.compareExchange(m, now): discard
        sleep(40)                          # overlap window if run concurrently
        ws.send(msg)                        # echo, in order
        discard concurrent.fetchSub(1)
  else:
    res.send(Http200, "http")

proc recvText(s: Socket): string =
  let f = s.recvFrame()
  check f.op == 0x1                                 # text frame
  f.payload

# Several workers so concurrency is possible; a single loop thread owns the
# one test connection.
withServer(RequestHandler(handler),
           initVortexConfig(numThreads = 1, workerThreads = 4), srv):
  let port = srv.port

  suite "websocket ws.blocking backpressure":
    test "messages on one connection are processed one at a time, in order":
      let s = openWs(port, timeoutMs = 5000).sock
      defer: s.close()
      const n = 5
      for i in 0 ..< n:                       # fire the whole burst up front
        s.sendText("m" & $i)
      for i in 0 ..< n:                        # replies come back in send order
        check s.recvText() == "m" & $i
      check maxConcurrent.load == 1           # never overlapped: pinned/serialized

echo "server shut down cleanly"
