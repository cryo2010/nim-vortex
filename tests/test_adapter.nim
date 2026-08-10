import std/[unittest, net, httpcore, strutils, os, osproc, times]
import std/httpclient except Response
import vortex/[settings, request, server, routing]
import ./helper
import vortex/asyncdispatch as nhsasync

proc hRoot(req: Request, res: Response) {.async.} =
  # No await at all: completes synchronously through the async path.
  res.send(Http200, "sync-in-async", "text/plain")

proc hDelay(req: Request, res: Response) {.async.} =
  await sleepAsync(150)                 # loop keeps serving meanwhile
  res.send(Http200, "slept", "text/plain")

proc hCapture(req: Request, res: Response) {.async.} =
  # Captures work: the future never leaves the loop thread.
  let who = req.param("name")
  await sleepAsync(20)
  res.send(Http200, "hello " & who, "text/plain")

proc hFanIn(req: Request, res: Response) {.async.} =
  var total = 0
  for i in 1 .. 3:
    await sleepAsync(10)
    total += i
  res.send(Http200, $total, "text/plain")

proc hBoom(req: Request, res: Response) {.async.} =
  await sleepAsync(10)
  raise newException(ValueError, "async exploded")

proc hBoomSync(req: Request, res: Response) {.async.} =
  # Fails before any await: the future completes (failed) synchronously,
  # exercising the finished-future fast path in the adapter.
  raise newException(ValueError, "sync exploded")

proc hBlockingInside(req: Request, res: Response) {.async.} =
  await sleepAsync(10)
  req.blocking:                          # sync escape inside async
    sleep(50)
    res.send(Http200, "worker done", "text/plain")

const streamChunk = "0123456789abcdef".repeat(1024)   # 16 KiB
const streamCount = 100                                # 1.6 MiB, > respHighWater

proc hStream(req: Request, res: Response) {.async.} =
  # await res.write writes and awaits the drain under backpressure automatically.
  res.stream(Http200, "application/octet-stream"):
    for i in 0 ..< streamCount:
      await res.write(streamChunk)

proc hUpload(req: Request, res: Response) {.async.} =
  # Consume the whole body; no explicit response -> auto-200 on block exit.
  req.stream(chunk):
    discard chunk
    await sleepAsync(0)                   # a real suspend mid-stream

proc hUploadReject(req: Request, res: Response) {.async.} =
  # Respond from inside the block: this overrides the auto-200.
  req.stream(chunk):
    if "BAD" in chunk:
      res.send(Http400, "bad chunk", "text/plain")
      return
  # a clean, unanswered exit still auto-200s (good body case)

proc hUploadBoom(req: Request, res: Response) {.async.} =
  req.stream(chunk):
    discard chunk
    raise newException(ValueError, "save failed")   # -> 500, never 200

var appRouter = newRouter()
appRouter.get("/", hRoot)
appRouter.get("/delay", hDelay)
appRouter.get("/hello/:name", hCapture)
appRouter.get("/fan", hFanIn)
appRouter.get("/boom", hBoom)
appRouter.get("/boomsync", hBoomSync)
appRouter.get("/worker", hBlockingInside)
appRouter.get("/stream", hStream)
appRouter.stream(HttpPost, "/upload", hUpload)
appRouter.stream(HttpPost, "/upload-reject", hUploadReject)
appRouter.stream(HttpPost, "/upload-boom", hUploadBoom)

var srv = newVortex(appRouter.toHandler,
                    initVortexConfig(numThreads = 1, workerThreads = 2),
                    appRouter.streamPredicate).start(0)
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

  test "res.stream + await res.write streams with backpressure, body intact":
    let body = fetch("/stream")
    check body.len == streamChunk.len * streamCount
    check body == streamChunk.repeat(streamCount)

  test "upload: req.stream auto-200 on clean exit":
    var client = newHttpClient()
    defer: client.close()
    let r = client.post(base & "/upload", "hello world")
    check r.code == Http200
    check r.body == ""

  test "upload: a response from inside the block overrides the auto-200":
    var client = newHttpClient()
    defer: client.close()
    check client.post(base & "/upload-reject", "BAD").code == Http400
    check client.post(base & "/upload-reject", "fine").code == Http200   # auto-200

  test "upload: a raise in the block gives 500, never 200":
    var client = newHttpClient()
    defer: client.close()
    check client.post(base & "/upload-boom", "x").code == Http500

  test "async handler over HTTP/2":
    let (output, rc) = execCmdEx(
      "curl -s --http2-prior-knowledge -w '|%{http_version}' " &
      base & "/delay")
    check rc == 0
    check output.strip() == "slept|2"

srv.close()
echo "server shut down cleanly"
