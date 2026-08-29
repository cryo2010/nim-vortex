## res.headers: pending response headers set from middleware or a handler,
## merged into the eventual send (the send call's headers win per name).

import std/[unittest, net, strutils, osproc, tables]
import std/httpclient except Response
import vortex/[settings, request, server, routing]

proc poweredBy(next: RequestHandler): RequestHandler =
  # middleware sets a header before the handler runs (the primary use case)
  let inner = next
  proc(req: Request, res: Response) {.gcsafe.} =
    res.headers["X-Powered-By"] = "vortex"
    inner(req, res)

proc plain(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "hi")                       # keeps text/plain + X-Powered-By

proc html(req: Request, res: Response) {.gcsafe.} =
  res.headers["Content-Type"] = "text/html"     # overrides the auto text/plain
  res.send(Http200, "<p>hi</p>")

proc override(req: Request, res: Response) {.gcsafe.} =
  # handler's send arg wins over the middleware's pending value
  res.send(Http200, "hi", @[("X-Powered-By", "handler")])

proc cookies(req: Request, res: Response) {.gcsafe.} =
  res.headers.add("Set-Cookie", "a=1")          # duplicates preserved
  res.headers.add("Set-Cookie", "b=2")
  res.send(Http200, "ok")

proc echoReq(req: Request, res: Response) {.gcsafe.} =
  # req.headers[name] matches the res.headers[name] shape (read-only,
  # case-insensitive); "has" via `in`.
  let present = if "x-custom" in req.headers: "yes" else: "no"
  res.send(Http200, req.headers["X-Custom"] & "|" & present)

proc r301(req: Request, res: Response) {.gcsafe.} = res.redirect("/dest", permanent = true)
proc r302(req: Request, res: Response) {.gcsafe.} = res.redirect("/dest")
proc r307(req: Request, res: Response) {.gcsafe.} = res.redirect("/dest", preserveMethod = true)
proc r308(req: Request, res: Response) {.gcsafe.} =
  res.redirect("/dest", permanent = true, preserveMethod = true)

var rt = newRouter()
rt.use(poweredBy)
rt.get("/plain", plain)
rt.get("/html", html)
rt.get("/override", override)
rt.get("/cookies", cookies)
rt.get("/echo-req", echoReq)
rt.get("/r301", r301)
rt.get("/r302", r302)
rt.get("/r307", r307)
rt.get("/r308", r308)

var srv = newVortex(rt.toHandler, initVortexConfig(numThreads = 1)).start(0)
let base = "http://127.0.0.1:" & $srv.port

suite "res.headers":
  test "middleware-set header rides along with the response":
    var c = newHttpClient()
    defer: c.close()
    let r = c.get(base & "/plain")
    check r.headers["x-powered-by"] == "vortex"
    check "text/plain" in r.headers["content-type"]   # auto CT still applied

  test "res.headers Content-Type overrides the auto default (no duplicate)":
    var c = newHttpClient()
    defer: c.close()
    let r = c.get(base & "/html")
    check "text/html" in r.headers["content-type"]
    check "text/plain" notin r.headers["content-type"]
    check r.headers.table["content-type"].len == 1    # exactly one CT header

  test "send-call headers override pending res.headers per name":
    var c = newHttpClient()
    defer: c.close()
    check c.get(base & "/override").headers["x-powered-by"] == "handler"

  test "add keeps duplicate headers (two Set-Cookie)":
    var c = newHttpClient()
    defer: c.close()
    check c.get(base & "/cookies").headers.table["set-cookie"].len == 2

  test "req.headers[name] reads request headers, case-insensitively":
    var c = newHttpClient()
    defer: c.close()
    c.headers = newHttpHeaders({"X-Custom": "hello"})
    check c.getContent(base & "/echo-req") == "hello|yes"

  test "req.headers[name] is '' and not-present when the header is absent":
    var c = newHttpClient()
    defer: c.close()
    check c.getContent(base & "/echo-req") == "|no"

  test "res.headers works over HTTP/2 (h2c)":
    let (output, rc) = execCmdEx(
      "curl -s -D - -o /dev/null --http2-prior-knowledge " & base & "/plain")
    check rc == 0
    check "x-powered-by: vortex" in output.toLowerAscii

suite "redirect status codes":
  test "302 default (temporary, may downgrade to GET)":
    var c = newHttpClient(maxRedirects = 0)
    defer: c.close()
    let r = c.get(base & "/r302")
    check r.status.startsWith("302")
    check r.headers["location"] == "/dest"
  test "301 with permanent":
    var c = newHttpClient(maxRedirects = 0)
    defer: c.close()
    check c.get(base & "/r301").status.startsWith("301")
  test "307 with preserveMethod (keeps method + body)":
    var c = newHttpClient(maxRedirects = 0)
    defer: c.close()
    check c.get(base & "/r307").status.startsWith("307")
  test "308 with permanent + preserveMethod":
    var c = newHttpClient(maxRedirects = 0)
    defer: c.close()
    check c.get(base & "/r308").status.startsWith("308")

srv.close()
echo "res.headers ok"
