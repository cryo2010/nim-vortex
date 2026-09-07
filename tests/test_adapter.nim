# Async-adapter conformance suite, shared by both backends (template method
# via a backend define): a plain build tests vortex/asyncdispatch (the default
# suite's tests/test_*.nim glob picks it up); compiling with -d:vortexChronos
# tests vortex/chronos (`nimble testchronos`; chronos is an opt-in dependency,
# so that build stays out of the default suite). The adapters share
# src/vortex/adapters/adapterimpl.nim, but the backend primitives
# (onCompleted, pump, pendingOps) differ, so the full scenario matrix runs
# against each backend.
import std/[unittest, net, httpcore, strutils, os, osproc, posix]
import std/httpclient except Response
import std/times except milliseconds        # chronos exports its own
import vortex/[settings, server, routing]   # not `request`: its (sync) blocking
import ./helper                              # macro would clash with the async
import ./wsclient
when defined(vortexChronos):
  import vortex/chronos as nhsasync          # adapter's; Request/Response via facade
  const suiteName = "chronos adapter"
  # chronos's sleepAsync takes a Duration; asyncdispatch's takes plain ms.
  template sleepMs(n: int): untyped = sleepAsync(n.milliseconds)
else:
  import vortex/asyncdispatch as nhsasync    # adapter's; Request/Response via facade
  const suiteName = "asyncdispatch adapter"
  template sleepMs(n: int): untyped = sleepAsync(n)

proc hRoot(req: Request, res: Response) {.async.} =
  # No await at all: completes synchronously through the async path.
  res.send(Http200, "sync-in-async")

proc hDelay(req: Request, res: Response) {.async.} =
  await sleepMs(150)                    # loop keeps serving meanwhile
  res.send(Http200, "slept")

proc hCapture(req: Request, res: Response) {.async.} =
  # Captures work: the future never leaves the loop thread.
  let who = req.param("name")
  await sleepMs(20)
  res.send(Http200, "hello " & who)

proc hFanIn(req: Request, res: Response) {.async.} =
  var total = 0
  for i in 1 .. 3:
    await sleepMs(10)
    total += i
  res.send(Http200, $total)

proc hBoom(req: Request, res: Response) {.async.} =
  await sleepMs(10)
  raise newException(ValueError, "async exploded")

proc hBoomSync(req: Request, res: Response) {.async.} =
  # Fails before any await: the future completes (failed) synchronously,
  # exercising the finished-future fast path in the adapter.
  raise newException(ValueError, "sync exploded")

proc hBlockingInside(req: Request, res: Response) {.async.} =
  await sleepMs(10)
  req.blocking:                          # sync escape inside async
    sleep(50)
    res.send(Http200, "worker done")

proc hBlockingValue(req: Request, res: Response) {.async.} =
  let name = req.param("name")
  let n = 3
  let data = req.blocking(name, n):      # awaitable: values moved in, result back
    sleep(20)
    name & ":" & $(n * 2)
  res.send(Http200, data)                # loop-side send after the await

const streamChunk = "0123456789abcdef".repeat(1024)   # 16 KiB
const streamCount = 100                                # 1.6 MiB, > respHighWater

proc hStream(req: Request, res: Response) {.async.} =
  # await res.write writes and awaits the drain under backpressure automatically.
  res.stream(Http200, "application/octet-stream"):
    for i in 0 ..< streamCount:
      await res.write(streamChunk)

proc hStreamRaw(req: Request, res: Response) {.async.} =
  # Manual outbound streaming with awaitable backpressure (write + await drain).
  res.sendHead(Http200, "text/plain")
  for i in 0 ..< 50:
    await res.write("chunk")
  res.finish()

proc hStreamEmit(req: Request, res: Response) {.async.} =
  # res.stream block form with the awaitable write (built-in backpressure).
  res.stream(Http200, "text/plain"):
    for i in 0 ..< 50: await res.write("chunk")

proc hUpload(req: Request, res: Response) {.async.} =
  # Consume the whole body; no explicit response -> auto-200 on block exit.
  req.stream(chunk):
    discard chunk
    await sleepMs(0)                      # a real suspend mid-stream

proc hUploadReject(req: Request, res: Response) {.async.} =
  # Respond from inside the block: this overrides the auto-200.
  req.stream(chunk):
    if "BAD" in chunk:
      res.send(Http400, "bad chunk")
      return
  # a clean, unanswered exit still auto-200s (good body case)

proc hUploadBoom(req: Request, res: Response) {.async.} =
  req.stream(chunk):
    discard chunk
    raise newException(ValueError, "save failed")   # -> 500, never 200

proc hUploadRead(req: Request, res: Response) {.async.} =
  # Pull-based body streaming: await req.read() until "".
  var total = 0
  while true:
    let chunk = await req.read()
    if chunk.len == 0: break
    total += chunk.len
  res.send(Http200, "got " & $total)

proc hWs(req: Request, res: Response) {.gcsafe.} =
  let ws = req.acceptWebSocket()
  ws.onMessage = proc(ws: WebSocket, data: string, kind: WsKind) {.gcsafe.} =
    ws.doAsync:
      await sleepMs(15)                   # adapter await, loop keeps serving
      ws.send("async: " & data)

proc hWsMsg(req: Request, res: Response) {.async.} =
  let ws = req.acceptWebSocket()
  ws.messages(msg):                          # async iterator over messages
    ws.send("echo: " & msg)

var appRouter = newRouter()
appRouter.get("/ws", hWs)
appRouter.ws("/wsmsg", hWsMsg)
appRouter.get("/", hRoot)
appRouter.get("/delay", hDelay)
appRouter.get("/hello/:name", hCapture)
appRouter.get("/fan", hFanIn)
appRouter.get("/boom", hBoom)
appRouter.get("/boomsync", hBoomSync)
appRouter.get("/worker", hBlockingInside)
appRouter.get("/worker-value/:name", hBlockingValue)
appRouter.get("/stream", hStream)
appRouter.get("/streamraw", hStreamRaw)
appRouter.get("/streamemit", hStreamEmit)
appRouter.post("/upload", hUpload, streaming = true)
appRouter.post("/upload-reject", hUploadReject, streaming = true)
appRouter.post("/upload-boom", hUploadBoom, streaming = true)
appRouter.post("/upload-read", hUploadRead, streaming = true)

withServer(appRouter.toHandler,
           initVortexConfig(numThreads = 1, workerThreads = 2),
           appRouter.streamPredicate, srv):
  let base = "http://127.0.0.1:" & $srv.port

  proc fetch(path: string): string =
    var client = newHttpClient()
    defer: client.close()
    client.getContent(base & path)

  suite suiteName:
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

    test "awaitable req.blocking moves values in and returns the result":
      check fetch("/worker-value/ada") == "ada:6"

    test "res.stream + await res.write streams with backpressure, body intact":
      let body = fetch("/stream")
      check body.len == streamChunk.len * streamCount
      check body == streamChunk.repeat(streamCount)

    test "sendHead/write/finish + await res.write streams an outbound body":
      check fetch("/streamraw") == "chunk".repeat(50)

    test "res.stream(emit) block form streams an outbound body":
      check fetch("/streamemit") == "chunk".repeat(50)

    test "await req.read() streams a request body":
      let body = "z".repeat(200 * 1024)
      let s = newSocket(buffered = false)
      defer: s.close()
      s.connect("127.0.0.1", srv.port)
      s.send("POST /upload-read HTTP/1.1\r\nHost: x\r\nConnection: close\r\n" &
             "Content-Length: " & $body.len & "\r\n\r\n")
      var off = 0
      while off < body.len:
        let n = min(16 * 1024, body.len - off)
        s.send(body[off ..< off + n]); inc off, n
      s.setRecvTimeout(4000)
      var resp: string
      var buf = newString(65536)
      while true:
        let k = recv(s.getFd, addr buf[0], buf.len, cint(0))
        if k <= 0: break
        resp.add buf[0 ..< k]
      check resp.endsWith("got " & $body.len)

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

    test "ws.doAsync: await inside a websocket message handler":
      let s = openWs(srv.port, "/ws").sock
      defer: s.close()
      s.sendText("howdy")
      let r = s.recvFrame()
      check r.op == 0x1
      check r.payload == "async: howdy"

    test "ws.messages: async iterator loop echoes each message":
      let s = openWs(srv.port, "/wsmsg").sock
      defer: s.close()
      s.sendText("one")
      check s.recvFrame().payload == "echo: one"
      s.sendText("two")
      check s.recvFrame().payload == "echo: two"

    test "newVortex overload accepts a bare async handler (no toHandler)":
      proc bare(req: Request, res: Response) {.async.} =
        res.send(Http200, "bare-async")
      let s = newVortex(bare).start(0)
      defer: s.close()
      var client = newHttpClient()
      defer: client.close()
      check client.getContent("http://127.0.0.1:" & $s.port & "/") == "bare-async"

echo "server shut down cleanly"
