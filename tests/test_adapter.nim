import std/[unittest, net, httpclient, httpcore, strutils, os, osproc, times]
import vortex/[settings, request, server, router]
import ./helper
import vortex/adapters/asyncdispatch as nhsasync

proc hRoot(req: Request, params: PathParams) {.async.} =
  # No await at all: completes synchronously through the async path.
  req.respond(Http200, "sync-in-async", "text/plain")

proc hDelay(req: Request, params: PathParams) {.async.} =
  await sleepAsync(150)                 # loop keeps serving meanwhile
  req.respond(Http200, "slept", "text/plain")

proc hCapture(req: Request, params: PathParams) {.async.} =
  # Captures work: the future never leaves the loop thread.
  let who = params.param("name")
  await sleepAsync(20)
  req.respond(Http200, "hello " & who, "text/plain")

proc hFanIn(req: Request, params: PathParams) {.async.} =
  var total = 0
  for i in 1 .. 3:
    await sleepAsync(10)
    total += i
  req.respond(Http200, $total, "text/plain")

proc hBoom(req: Request, params: PathParams) {.async.} =
  await sleepAsync(10)
  raise newException(ValueError, "async exploded")

proc hBoomSync(req: Request, params: PathParams) {.async.} =
  # Fails before any await: the future completes (failed) synchronously,
  # exercising the finished-future fast path in the adapter.
  raise newException(ValueError, "sync exploded")

proc hBlockingInside(req: Request, params: PathParams) {.async.} =
  await sleepAsync(10)
  req.blocking:                          # sync escape inside async
    sleep(50)
    req.respond(Http200, "worker done", "text/plain")

var appRouter = newRouter()
appRouter.get("/", hRoot)
appRouter.get("/delay", hDelay)
appRouter.get("/hello/:name", hCapture)
appRouter.get("/fan", hFanIn)
appRouter.get("/boom", hBoom)
appRouter.get("/boomsync", hBoomSync)
appRouter.get("/worker", hBlockingInside)

var srv = start(appRouter.toHandler,
                initSettings(port = Port(0), numThreads = 1,
                             workerThreads = 2))
let base = "http://127.0.0.1:" & $srv.port

proc fetch(path: string): string =
  var client = newHttpClient()
  defer: client.close()
  client.getContent(base & path)

suite "asyncdispatch adapter":
  test "async handler without await":
    check fetch("/") == "sync-in-async"

  test "deferred response after sleepAsync":
    check fetch("/delay") == "slept"

  test "captures in async body":
    check fetch("/hello/craig") == "hello craig"

  test "multiple sequential awaits":
    check fetch("/fan") == "6"

  test "keep-alive works across deferred responses":
    var client = newHttpClient()
    defer: client.close()
    check client.getContent(base & "/delay") == "slept"
    check client.getContent(base & "/") == "sync-in-async"
    check client.getContent(base & "/delay") == "slept"

  test "concurrent delays overlap (loop is not blocked)":
    # Two /delay requests on separate connections should complete in
    # ~150ms total, not ~300ms: the loop must keep serving during await.
    var socks: seq[Socket]
    let t0 = epochTime()
    for i in 0 ..< 2:
      let s = newSocket(buffered = false)
      s.connect("127.0.0.1", srv.port)
      s.send("GET /delay HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
      socks.add s
    for s in socks:
      let resp = s.recvUntilClose(2000)
      s.close()
      check resp.endsWith("slept")
    let elapsed = epochTime() - t0
    check elapsed < 0.28

  test "exception in async body gives 500":
    var client = newHttpClient()
    defer: client.close()
    check client.get(base & "/boom").code == Http500

  test "exception before first await gives 500 (fast path)":
    var client = newHttpClient()
    defer: client.close()
    check client.get(base & "/boomsync").code == Http500

  test "blocking: works inside an async handler":
    check fetch("/worker") == "worker done"

  test "async handler over HTTP/2":
    let (output, rc) = execCmdEx(
      "curl -s --http2-prior-knowledge -w '|%{http_version}' " &
      base & "/delay")
    check rc == 0
    check output.strip() == "slept|2"

srv.close()
echo "server shut down cleanly"
