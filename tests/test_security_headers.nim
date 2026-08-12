## SEC2: securityHeaders() OWASP baseline + req.isSecure gating.

import std/[unittest, net, httpcore]
import std/httpclient except Response
import vortex/[settings, request, server]

proc handler(req: Request, res: Response) {.gcsafe.} =
  case req.path
  of "/secure":
    # Emitted end to end; header serialization itself is covered elsewhere.
    res.send(Http200, "ok",
             securityHeaders(hsts = req.isSecure) & @[("Content-Type", "application/json")])
  of "/insecure-flag":
    res.send(Http200, if req.isSecure: "tls" else: "plain")
  else:
    res.send(Http404)

var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1)).start(0)
let base = "http://127.0.0.1:" & $srv.port

suite "security headers (SEC2)":
  test "baseline set, HSTS omitted by default":
    let h = securityHeaders()          # hsts defaults false
    check ("X-Content-Type-Options", "nosniff") in h
    check ("X-Frame-Options", "DENY") in h
    check ("Content-Security-Policy",
           "default-src 'none'; frame-ancestors 'none'") in h
    check ("Referrer-Policy", "no-referrer") in h
    var hasHsts = false
    for (k, _) in h:
      if k == "Strict-Transport-Security": hasHsts = true
    check not hasHsts

  test "HSTS is built when enabled":
    let h = securityHeaders(hsts = true, hstsMaxAge = 100, hstsPreload = true)
    var sts = ""
    for (k, v) in h:
      if k == "Strict-Transport-Security": sts = v
    check sts == "max-age=100; includeSubDomains; preload"

  test "the baseline serves end to end (200)":
    var c = newHttpClient()
    defer: c.close()
    check c.get(base & "/secure").code == Http200

  test "req.isSecure is false over plain HTTP":
    var c = newHttpClient()
    defer: c.close()
    check c.getContent(base & "/insecure-flag") == "plain"

srv.close()
echo "security headers ok"
