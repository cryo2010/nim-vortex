import std/[unittest, net, httpcore, strutils, os, osproc, posix]
import std/httpclient except Response
import std/times except milliseconds
import vortex/[settings, request, server, router]
import ./helper
import vortex/adapters/chronos as nhschronos

proc hRoot(req: Request, res: Response) {.async.} =
  # No await at all: completes synchronously through the async path.
  res.send(Http200, "sync-in-async", "text/plain")

proc hDelay(req: Request, res: Response) {.async.} =
  await sleepAsync(150.milliseconds)      # loop keeps serving meanwhile
  res.send(Http200, "slept", "text/plain")

proc hCapture(req: Request, res: Response) {.async.} =
  # Captures work: the future never leaves the loop thread.
  let who = req.param("name")
  await sleepAsync(20.milliseconds)
  res.send(Http200, "hello " & who, "text/plain")

proc hFanIn(req: Request, res: Response) {.async.} =
  var total = 0
  for i in 1 .. 3:
    await sleepAsync(10.milliseconds)
    total += i
  res.send(Http200, $total, "text/plain")

proc hUpload(req: Request, res: Response) {.async.} =
  # Pull-based body streaming: await req.read() until "".
  var total = 0
  while true:
    let chunk = await req.read()
    if chunk.len == 0: break
    total += chunk.len
  res.send(Http200, "got " & $total, "text/plain")

proc hStream(req: Request, res: Response) {.async.} =
  # Outbound streaming with awaitable backpressure.
  res.sendHead(Http200, "text/plain")
  for i in 0 ..< 50:
    if not res.write("chunk"):
      await res.drained()
  res.finish()

proc hStreamEmit(req: Request, res: Response) {.async.} =
  # res.stream(..., emit): the block form with auto-draining emit.
  res.stream(Http200, "text/plain", emit):
    for i in 0 ..< 50: emit("chunk")

proc hBoom(req: Request, res: Response) {.async.} =
  await sleepAsync(10.milliseconds)
  raise newException(ValueError, "async exploded")

proc hBoomSync(req: Request, res: Response) {.async.} =
  # Fails before any await: the future completes (failed) synchronously,
  # exercising the finished-future fast path in the adapter.
  raise newException(ValueError, "sync exploded")

proc hBlockingInside(req: Request, res: Response) {.async.} =
  await sleepAsync(10.milliseconds)
  req.blocking:                            # sync escape inside async
    sleep(50)
    res.send(Http200, "worker done", "text/plain")

proc hWs(req: Request, res: Response) {.gcsafe.} =
  let ws = req.acceptWebSocket()
  ws.onMessage = proc(ws: WebSocket, data: string, kind: WsKind) {.gcsafe.} =
    ws.doAsync:
      await sleepAsync(15.milliseconds)     # chronos await, loop keeps serving
      ws.send("async: " & data)

var appRouter = newRouter()
appRouter.get("/ws", hWs)
appRouter.get("/", hRoot)
appRouter.get("/delay", hDelay)
appRouter.get("/hello/:name", hCapture)
appRouter.get("/fan", hFanIn)
appRouter.get("/boom", hBoom)
appRouter.get("/boomsync", hBoomSync)
appRouter.get("/worker", hBlockingInside)
appRouter.stream(HttpPost, "/upload", hUpload)
appRouter.get("/stream", hStream)
appRouter.get("/streamemit", hStreamEmit)

var srv = start(appRouter.toHandler,
                initSettings(port = Port(0), numThreads = 1,
                             workerThreads = 2),
                appRouter.streamPredicate)
let base = "http://127.0.0.1:" & $srv.port

proc fetch(path: string): string =
  var client = newHttpClient()
  defer: client.close()
  client.getContent(base & path)

proc wsRecvN(s: Socket, n: int): string =
  result = newString(n)
  var got = 0
  while got < n:
    let k = recv(s.getFd, addr result[got], n - got, cint(0))
    if k <= 0: raise newException(IOError, "short read")
    got += k

proc wsRecvFrame(s: Socket): tuple[op: int, payload: string] =
  let h = wsRecvN(s, 2)
  var ln = int(uint8(h[1]) and 0x7f)
  if ln == 126:
    let e = wsRecvN(s, 2); ln = (int(uint8(e[0])) shl 8) or int(uint8(e[1]))
  ((int(uint8(h[0])) and 0x0f), (if ln > 0: wsRecvN(s, ln) else: ""))

proc openWsChat(): Socket =
  result = newSocket(buffered = false)
  result.connect("127.0.0.1", srv.port)
  result.send("GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n" &
              "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" &
              "Sec-WebSocket-Version: 13\r\n\r\n")
  result.setRecvTimeout(2000)
  var hdr = ""
  var one = newString(1)
  while not hdr.endsWith("\r\n\r\n"):
    let k = recv(result.getFd, addr one[0], 1, cint(0))
    if k <= 0: break
    hdr.add one[0]
  doAssert "101" in hdr, hdr

suite "chronos adapter":
  test "async handler without await":
    check fetch("/") == "sync-in-async"

  test "deferred response after sleepAsync":
    check fetch("/delay") == "slept"

  test "captures in async body":
    check fetch("/hello/craig") == "hello craig"

  test "multiple sequential awaits":
    check fetch("/fan") == "6"

  test "await res.drained() streams an outbound body":
    check fetch("/stream") == "chunk".repeat(50)

  test "res.stream(emit) block form streams an outbound body":
    check fetch("/streamemit") == "chunk".repeat(50)

  test "await req.read() streams a request body":
    let body = "z".repeat(200 * 1024)
    let s = newSocket(buffered = false)
    defer: s.close()
    s.connect("127.0.0.1", srv.port)
    s.send("POST /upload HTTP/1.1\r\nHost: x\r\nConnection: close\r\n" &
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

  test "ws.doAsync: await inside a websocket message handler":
    let s = openWsChat()
    defer: s.close()
    var f = "\x81\x85"                        # fin+text, masked, len 5
    let mask = [0x11'u8, 0x22, 0x33, 0x44]
    for m in mask: f.add char(m)
    let msg = "howdy"
    for i in 0 ..< msg.len: f.add char(uint8(msg[i]) xor mask[i and 3])
    s.send(f)
    let r = s.wsRecvFrame()
    check r.op == 0x1
    check r.payload == "async: howdy"

srv.close()
echo "server shut down cleanly"
