## SEC1: req.remoteAddress (peer IP from accept) and req.forwardedFor
## (X-Forwarded-For parsing) for access logging / rate limiting / audit.

import std/[unittest, net, httpcore, strutils]
import std/httpclient except Response
import vortex/[settings, request, server]

proc handler(req: Request, res: Response) {.gcsafe.} =
  case req.path
  of "/ip":
    res.send(Http200, req.remoteAddress)
  of "/xff":
    res.send(Http200, req.forwardedFor.join("|"))
  else:
    res.send(Http404)

var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1)).start(0)
let base = "http://127.0.0.1:" & $srv.port

suite "remote address (SEC1)":
  test "remoteAddress is the loopback peer IP":
    var c = newHttpClient()
    defer: c.close()
    check c.getContent(base & "/ip") == "127.0.0.1"

  test "forwardedFor parses the X-Forwarded-For chain":
    var c = newHttpClient()
    c.headers = newHttpHeaders({"X-Forwarded-For": "203.0.113.7, 198.51.100.2"})
    defer: c.close()
    check c.getContent(base & "/xff") == "203.0.113.7|198.51.100.2"

  test "forwardedFor is empty without the header":
    var c = newHttpClient()
    defer: c.close()
    check c.getContent(base & "/xff") == ""

srv.close()
echo "remote address ok"
