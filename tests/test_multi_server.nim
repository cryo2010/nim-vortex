## Multiple Server instances in one process must be independent: stopping or
## starting one must not stop the other or make a waitFor hang (regression for
## the former single process-global stop flag).

import std/[unittest, net, httpcore]
import std/httpclient except Response
import vortex/[settings, request, server]

proc handler(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "ok")

proc get(port: Port): string =
  var c = newHttpClient()
  defer: c.close()
  try: c.getContent("http://127.0.0.1:" & $port & "/")
  except CatchableError: "ERR"

suite "multiple servers are independent":
  test "closing one server leaves the other serving":
    let a = newVortex(RequestHandler(handler),
                      initVortexConfig(numThreads = 1)).start(0)
    let b = newVortex(RequestHandler(handler),
                      initVortexConfig(numThreads = 1)).start(0)
    check get(a.port) == "ok"
    check get(b.port) == "ok"
    a.close()                      # must stop only a
    check get(b.port) == "ok"      # b keeps serving
    b.close()

  test "starting a new server does not prevent stopping an old one":
    let a = newVortex(RequestHandler(handler),
                      initVortexConfig(numThreads = 1)).start(0)
    check get(a.port) == "ok"
    # A second start (which resets its own flag) used to clear the shared flag
    # and could make a.close() block forever. It must not.
    let b = newVortex(RequestHandler(handler),
                      initVortexConfig(numThreads = 1)).start(0)
    a.close()                      # returns promptly
    check get(b.port) == "ok"
    b.close()

suite "config validation":
  test "keyFile without certFile is rejected (would serve plaintext)":
    expect CatchableError:
      let s = newVortex(RequestHandler(handler),
                        initVortexConfig(keyFile = "/x/key.pem")).start(0)
      s.close()

  test "negative limits are rejected":
    expect CatchableError:
      let s = newVortex(RequestHandler(handler),
                        initVortexConfig(maxBodySize = -1)).start(0)
      s.close()

echo "multi-server ok"
