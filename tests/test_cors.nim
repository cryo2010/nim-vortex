## CORS middleware: Access-Control-* headers on allowed cross-origin requests,
## preflight (OPTIONS + Access-Control-Request-Method) answered with 204, and an
## allowlist that rejects other origins.

import std/[unittest, net, tables, httpcore, strutils]
import std/httpclient except Response
import vortex/[settings, request, server, routing, cors]

proc hello(req: Request, res: Response) {.gcsafe.} = res.send(Http200, "hi")

var rt = newRouter()
rt.use(cors())                                   # permissive default (origins *)
rt.get("/", hello)
var srv = newVortex(rt.toHandler, initVortexConfig(numThreads = 1)).start(0)
let base = "http://127.0.0.1:" & $srv.port

var rt2 = newRouter()
rt2.use(cors(initCorsOptions(origins = @["https://ok.example"],
                             allowCredentials = true, maxAge = 600)))
rt2.get("/", hello)
var srv2 = newVortex(rt2.toHandler, initVortexConfig(numThreads = 1)).start(0)
let base2 = "http://127.0.0.1:" & $srv2.port

suite "CORS (wildcard default)":
  test "a simple request gets Access-Control-Allow-Origin: *":
    var c = newHttpClient(); defer: c.close()
    c.headers = newHttpHeaders({"Origin": "https://any.example"})
    let r = c.get(base & "/")
    check r.body == "hi"
    check r.headers["access-control-allow-origin"] == "*"

  test "a preflight is answered 204 with methods and echoed headers":
    var c = newHttpClient(); defer: c.close()
    c.headers = newHttpHeaders({
      "Origin": "https://any.example",
      "Access-Control-Request-Method": "POST",
      "Access-Control-Request-Headers": "X-Custom"})
    let r = c.request(base & "/", HttpOptions)
    check r.code == Http204
    check "POST" in $r.headers["access-control-allow-methods"]
    check "X-Custom" in $r.headers["access-control-allow-headers"]

  test "a request with no Origin is untouched":
    var c = newHttpClient(); defer: c.close()
    let r = c.get(base & "/")
    check r.body == "hi"
    check "access-control-allow-origin" notin r.headers.table

suite "CORS (allowlist + credentials)":
  test "an allowed origin is echoed with credentials":
    var c = newHttpClient(); defer: c.close()
    c.headers = newHttpHeaders({"Origin": "https://ok.example"})
    let r = c.get(base2 & "/")
    check r.headers["access-control-allow-origin"] == "https://ok.example"
    check r.headers["access-control-allow-credentials"] == "true"

  test "a disallowed origin gets no CORS headers but is still served":
    var c = newHttpClient(); defer: c.close()
    c.headers = newHttpHeaders({"Origin": "https://evil.example"})
    let r = c.get(base2 & "/")
    check r.body == "hi"
    check "access-control-allow-origin" notin r.headers.table

  test "a preflight from a disallowed origin is 403":
    var c = newHttpClient(); defer: c.close()
    c.headers = newHttpHeaders({
      "Origin": "https://evil.example",
      "Access-Control-Request-Method": "POST"})
    check c.request(base2 & "/", HttpOptions).code == Http403

  test "preflight advertises Max-Age":
    var c = newHttpClient(); defer: c.close()
    c.headers = newHttpHeaders({
      "Origin": "https://ok.example",
      "Access-Control-Request-Method": "GET"})
    check c.request(base2 & "/", HttpOptions).headers["access-control-max-age"] == "600"

srv.close()
srv2.close()
echo "cors ok"
