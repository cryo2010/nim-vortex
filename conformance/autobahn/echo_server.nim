## WebSocket echo server under test for the Autobahn|Testsuite. The
## fuzzingclient connects to it, runs every case, and grades the replies.
## Echoing text as text and binary as binary is exactly what the suite
## expects of a server under test.

import std/os
import vortex

proc handler(req: Request, res: Response) {.gcsafe.} =
  if req.isWebSocketUpgrade:
    let ws = req.acceptWebSocket()
    ws.onMessage = proc(ws: WebSocket, data: string, kind: WsKind) {.gcsafe.} =
      ws.send(data, kind)               # echo, preserving the message kind
  else:
    res.send(Http200, "autobahn echo server")

when isMainModule:
  # A large message cap so the 9.* limit/performance cases (payloads up to
  # 16 MiB) pass. start() binds before returning, so the "listening" log
  # line is a reliable readiness signal for run.sh.
  var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, maxWsMessageSize = 64 * 1024 * 1024)).start(9001)
  echo "listening on ", int(srv.port)
  while true: sleep(3600 * 1000)
