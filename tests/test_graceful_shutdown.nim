## Graceful-drain shutdown: requestShutdown() stops accepting, lets in-flight
## requests finish (up to shutdownGrace), then exits. An idle keep-alive
## connection is closed promptly; a request already being handled still gets
## its full response.

import std/[unittest, net, strutils, httpcore, os]
import vortex/[settings, request, server]
import ./helper

proc handler(req: Request, res: Response) {.gcsafe.} =
  case req.path
  of "/slow":
    req.blocking:                          # in-flight work on the worker pool
      sleep(300)
      res.send(Http200, "done after drain", "text/plain")
  else:
    res.send(Http200, "ok", "text/plain")

var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, workerThreads = 2, shutdownGrace = 5)).start(0)
let port = srv.port

proc connectSock(): Socket =
  result = newSocket(buffered = false)
  result.connect("127.0.0.1", port)
  result.setRecvTimeout(4000)

suite "graceful shutdown":
  test "an in-flight request completes, then the server exits":
    # Warm up so the port is definitely serving.
    block:
      let w = connectSock()
      w.send("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
      check "200" in w.recvUntilClose()
      w.close()

    # Start a slow request, then ask the server to shut down while it runs.
    let s = connectSock()
    s.send("GET /slow HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    sleep(100)                             # let it reach the worker
    requestShutdown()                      # begin graceful drain
    let resp = s.recvUntilClose()          # the in-flight response must arrive
    s.close()
    check "done after drain" in resp

    # After the drain, new connections are refused (listener closed) ...
    var refused = false
    for i in 0 ..< 20:
      try:
        let n = newSocket(buffered = false)
        n.connect("127.0.0.1", port)
        n.send("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        if n.recvUntilClose().len == 0: refused = true
        n.close()
      except OSError:
        refused = true
      if refused: break
      sleep(50)
    check refused

    # ... and the loop threads exit (drain finished within the grace window).
    srv.waitFor()

echo "server shut down cleanly"
