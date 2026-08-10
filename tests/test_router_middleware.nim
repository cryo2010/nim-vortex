## router.use middleware: ordering/nesting, short-circuit, and that middleware
## wraps unmatched (404) routes too.

import std/[unittest, net, httpcore]
import std/httpclient except Response
import vortex/[settings, request, server, routing]

# Single-threaded server + one request at a time, so a plain global trace is
# race-free here (the loop thread is the only writer).
var trace: seq[string]

proc traceMw(tag: string): Middleware =
  proc(next: RequestHandler): RequestHandler =
    let inner = next
    proc(req: Request, res: Response) {.gcsafe.} =
      {.cast(gcsafe).}: trace.add tag & "-in"
      inner(req, res)
      {.cast(gcsafe).}: trace.add tag & "-out"

proc requireKey(next: RequestHandler): RequestHandler =
  let inner = next
  proc(req: Request, res: Response) {.gcsafe.} =
    if req.header("x-key") == "letmein":
      inner(req, res)
    else:
      res.send(Http403, "forbidden", "text/plain")   # short-circuit: skip inner

proc hOk(req: Request, res: Response) {.gcsafe.} =
  {.cast(gcsafe).}: trace.add "handler"
  res.send(Http200, "ok", "text/plain")

proc req(port: Port, path: string, headers: seq[(string, string)] = @[]):
    tuple[code: int, body: string] =
  var c = newHttpClient()
  defer: c.close()
  for (k, v) in headers: c.headers[k] = v
  let r = c.get("http://127.0.0.1:" & $port & path)
  (r.code.int, r.body)

suite "router.use ordering and nesting":
  var rt = newRouter()
  rt.use(traceMw("a"))
  rt.use(traceMw("b"))
  rt.get("/", hOk)
  let srv = newVortex(rt.toHandler, initVortexConfig(numThreads = 1)).start(0)
  let port = srv.port

  test "middleware run outer-to-inner, unwind inner-to-outer":
    trace = @[]
    let (code, body) = req(port, "/")
    check code == 200
    check body == "ok"
    # first-registered (a) is outermost; unwinds last.
    check trace == @["a-in", "b-in", "handler", "b-out", "a-out"]

  test "middleware also wraps an unmatched (404) route":
    trace = @[]
    let (code, _) = req(port, "/nope")
    check code == 404
    check trace == @["a-in", "b-in", "b-out", "a-out"]   # handler never ran

  srv.close()

suite "router.use short-circuit":
  var rt = newRouter()
  rt.use(requireKey)
  rt.get("/secret", hOk)
  let srv = newVortex(rt.toHandler, initVortexConfig(numThreads = 1)).start(0)
  let port = srv.port

  test "request without the key is blocked before the handler":
    trace = @[]
    let (code, body) = req(port, "/secret")
    check code == 403
    check body == "forbidden"
    check trace.len == 0          # handler never reached

  test "request with the key reaches the handler":
    trace = @[]
    let (code, body) = req(port, "/secret", @[("x-key", "letmein")])
    check code == 200
    check body == "ok"
    check trace == @["handler"]

  srv.close()

echo "router middleware ok"
