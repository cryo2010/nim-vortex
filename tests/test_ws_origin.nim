## SEC4: WebSocket Origin allowlisting (OWASP WebSocket Security / CSWSH).
## The Origin check is plain header logic, so it's exercised over HTTP without
## the WebSocket handshake plumbing.

import std/[unittest, net, httpcore]
import std/httpclient except Response
import vortex/[settings, request, server]

const allow = ["https://good.example", "https://also-good.example"]

proc handler(req: Request, res: Response) {.gcsafe.} =
  case req.path
  of "/strict":  res.send(Http200, $req.originAllowed(allow), "text/plain")
  of "/lenient": res.send(Http200, $req.originAllowed(allow, allowMissing = true),
                          "text/plain")
  of "/origin":  res.send(Http200, req.origin, "text/plain")
  else: res.send(Http404)

var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1)).start(0)
let base = "http://127.0.0.1:" & $srv.port

proc get(path, origin: string): string =
  var c = newHttpClient()
  defer: c.close()
  if origin.len > 0: c.headers = newHttpHeaders({"Origin": origin})
  c.getContent(base & path)

suite "websocket origin allowlist (SEC4)":
  test "allowed origin passes":
    check get("/strict", "https://good.example") == "true"
    check get("/strict", "https://also-good.example") == "true"

  test "disallowed origin is rejected":
    check get("/strict", "https://evil.example") == "false"

  test "missing origin: strict rejects, lenient allows":
    check get("/strict", "") == "false"
    check get("/lenient", "") == "true"

  test "origin accessor reflects the header":
    check get("/origin", "https://good.example") == "https://good.example"

srv.close()
echo "ws origin ok"
