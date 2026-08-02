## settings.securityHeaders: auto-inject the OWASP baseline on every response,
## skipping any header the handler already set. Raw sockets so header reads are
## exact.

import std/[unittest, net, httpcore, strutils]
import vortex/[settings, request, server]

proc handler(req: Request, res: Response) {.gcsafe.} =
  case req.path
  of "/plain":
    res.send(Http200, "ok", "text/plain")
  of "/override":                       # handler sets its own X-Frame-Options
    res.send(Http200, "ok", "text/plain", @[("X-Frame-Options", "SAMEORIGIN")])
  of "/stream":
    res.sendHead(Http200, "text/plain")
    discard res.write("chunk")
    res.finish()
  else:
    res.send(Http404)

var onSrv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, securityHeaders = true)).start(0)
var offSrv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1)).start(0)

proc raw(port: Port, path: string): string =
  let s = newSocket()
  defer: s.close()
  s.connect("127.0.0.1", port)
  s.send("GET " & path & " HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n")
  var chunk = s.recv(65536, timeout = 2000)
  while chunk.len > 0:
    result.add chunk
    chunk = s.recv(65536, timeout = 2000)

suite "security headers toggle":
  test "baseline is injected when the toggle is on":
    let r = raw(onSrv.port, "/plain")
    check r.find("X-Content-Type-Options: nosniff") >= 0
    check r.find("X-Frame-Options: DENY") >= 0
    check r.find("Referrer-Policy: no-referrer") >= 0
    check r.find("Strict-Transport-Security") < 0   # plaintext server: no HSTS

  test "nothing injected when the toggle is off":
    let r = raw(offSrv.port, "/plain")
    check r.find("X-Content-Type-Options") < 0
    check r.find("X-Frame-Options") < 0

  test "a handler-set header overrides the baseline (no duplicate)":
    let r = raw(onSrv.port, "/override")
    check r.find("X-Frame-Options: SAMEORIGIN") >= 0
    check r.find("X-Frame-Options: DENY") < 0

  test "streaming responses get the baseline too":
    let r = raw(onSrv.port, "/stream")
    check r.find("X-Content-Type-Options: nosniff") >= 0

onSrv.close()
offSrv.close()
echo "security headers toggle ok"
