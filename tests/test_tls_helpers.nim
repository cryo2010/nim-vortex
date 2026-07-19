## SEC5: TLS deployment helpers -- res.redirect (plaintext->HTTPS pattern),
## secure setCookie, and req.host.

import std/[unittest, net, httpcore]
import std/httpclient except Response
import vortex/[settings, request, server]

proc handler(req: Request, res: Response) {.gcsafe.} =
  case req.path
  of "/to-https":
    res.redirect("https://" & req.host & req.url.path, permanent = true)
  of "/host":
    res.send(Http200, req.host, "text/plain")
  of "/set":
    res.send(Http200, "ok", "text/plain", @[setCookie("sid", "abc", maxAge = 3600)])
  else:
    res.send(Http404)

var srv = start(RequestHandler(handler),
                initSettings(port = Port(0), numThreads = 1))
let base = "http://127.0.0.1:" & $srv.port

suite "tls deployment helpers (SEC5)":
  test "redirect sends 301 with Location":
    var c = newHttpClient(maxRedirects = 0)
    defer: c.close()
    let resp = c.get(base & "/to-https")
    check resp.code == Http301
    check resp.headers.hasKey("location")
    check resp.headers["location", 0] == "https://127.0.0.1:" & $srv.port & "/to-https"

  test "setCookie has secure defaults":
    let (k, v) = setCookie("sid", "abc", maxAge = 3600)
    check k == "Set-Cookie"
    check v == "sid=abc; Path=/; Max-Age=3600; Secure; HttpOnly; SameSite=Lax"

  test "setCookie session cookie omits Max-Age; secure=false drops Secure":
    let (_, v) = setCookie("t", "1", secure = false)
    check v == "t=1; Path=/; HttpOnly; SameSite=Lax"

  test "req.host reflects the Host header":
    check newHttpClient().getContent(base & "/host") == "127.0.0.1:" & $srv.port

srv.close()
echo "tls helpers ok"
