import std/[unittest, net, httpcore, strutils, os, times]
import std/httpclient except Response
import vortex/[settings, request, server]
import ./helper

proc handler(req: Request, res: Response) {.gcsafe.} =
  case req.path
  of "/":
    res.send(Http200, "fast", "text/plain")
  of "/slow":
    req.blocking:
      sleep(300)                       # blocking is legal here
      res.send(Http200, "slow done", "text/plain")
  of "/slowboom":
    req.blocking:
      sleep(50)
      raise newException(ValueError, "worker exploded")
  of "/echo-slow":
    req.blocking:
      sleep(50)
      res.send(Http200, req.body, req.header("Content-Type"))
  else:
    res.send(Http404)

var srv = start(RequestHandler(handler),
                initSettings(port = Port(0), numThreads = 2,
                             workerThreads = 4, keepAliveTimeout = 5))
let base = "http://127.0.0.1:" & $srv.port

proc fetch(path: string): string =
  var client = newHttpClient()
  defer: client.close()
  client.getContent(base & path)

suite "worker pool / blocking":
  test "blocking route responds":
    check fetch("/slow") == "slow done"

  test "worker can read request data":
    var client = newHttpClient()
    defer: client.close()
    client.headers = newHttpHeaders({"Content-Type": "text/plain"})
    check client.post(base & "/echo-slow", body = "payload!").body == "payload!"

  test "fast requests unaffected by a saturated blocking route":
    # Saturate more than the whole pool with in-flight slow requests...
    var slowSocks: seq[Socket]
    for i in 0 ..< 6:
      let s = newSocket(buffered = false)
      s.connect("127.0.0.1", srv.port)
      s.send("GET /slow HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
      slowSocks.add s
    sleep(50)                          # let them reach the workers
    # ...fast inline requests must still fly.
    let t0 = epochTime()
    for i in 0 ..< 20:
      check fetch("/") == "fast"
    let fastElapsed = epochTime() - t0
    check fastElapsed < 0.25           # would be seconds if queued behind /slow
    # All slow responses eventually arrive intact.
    for s in slowSocks:
      let resp = s.recvUntilClose(2000)
      s.close()
      check resp.endsWith("slow done")

  test "exception in worker gives 500":
    var client = newHttpClient()
    defer: client.close()
    check client.get(base & "/slowboom").code == Http500

  test "keep-alive works across a blocking response":
    var client = newHttpClient()
    defer: client.close()
    check client.getContent(base & "/slow") == "slow done"
    check client.getContent(base & "/") == "fast"
    check client.getContent(base & "/slow") == "slow done"

  test "pipelined: blocking then fast, answered in order":
    let resp = rawExchange(srv.port,
      "GET /slow HTTP/1.1\r\nHost: x\r\n\r\n" &
      "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    check resp.count("HTTP/1.1 200") == 2
    check resp.find("slow done") < resp.find("fast")

  test "client disconnect while blocked doesn't break the server":
    block:
      let s = newSocket(buffered = false)
      s.connect("127.0.0.1", srv.port)
      s.send("GET /slow HTTP/1.1\r\nHost: x\r\n\r\n")
      s.close()                        # vanish mid-task
    sleep(400)                         # let the worker finish + unpin
    check fetch("/") == "fast"         # server alive and well
    check fetch("/slow") == "slow done"

srv.close()
echo "server shut down cleanly"
