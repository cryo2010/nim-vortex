# Async-adapter conformance suite, shared by both backends (template method
# via a backend define): a plain build tests vortex/asyncdispatch (the default
# suite's tests/test_*.nim glob picks it up); compiling with -d:vortexChronos
# tests vortex/chronos (`nimble testchronos`; chronos is an opt-in dependency,
# so that build stays out of the default suite). The adapters share
# src/vortex/adapters/adapterimpl.nim, but the backend primitives
# (onCompleted, pump, pendingOps) differ, so the full scenario matrix runs
# against each backend.
import std/[unittest, net, httpcore, strutils, os, osproc, posix, atomics]
import std/httpclient except Response
import std/times except milliseconds        # chronos exports its own
import vortex/[settings, server, routing]   # not `request`: its (sync) blocking
import ./helper                              # macro would clash with the async
import ./h2client
import ./wsclient
import vortex/http2/frames
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

var staleAsyncBuffered: Atomic[int]     # bufferedAmount through the kept handle
var staleAsyncDrained: Atomic[int]      # its `await res.drained()` completed
var staleAsyncWrite: Atomic[int]        # 1 = its write reported success

proc hStaleKeep(req: Request, res: Response) {.async.} =
  ## Request N of a keep-alive pair (#407): answer at once, then keep running
  ## past the request boundary holding `res`, while N+1 streams on the same
  ## connection. Every call through the kept handle must miss N+1: before the
  ## h1 request serial `drained` read N+1's backlog (and could replace its drain
  ## callback), the write spliced into N+1's chunked body, the finish ended it,
  ## and this future's completion kick resumed N+1 as "left mid-stream" and
  ## closed the connection under it.
  res.send(Http200, "kept")
  await sleepMs(100)                     # the connection moves on to N+1
  staleAsyncBuffered.store(res.bufferedAmount)
  await res.drained()                    # must complete, not park or hijack
  staleAsyncDrained.store(1)
  if res.write("STALE".toOpenArray(0, 4)): staleAsyncWrite.store(1)
  res.finish()

proc hStaleVictim(req: Request, res: Response) {.async.} =
  ## Request N+1: a streamed body that stays open across the kept handle's use.
  res.sendHead(Http200, "text/plain")
  discard res.write("part1|".toOpenArray(0, 5))
  await sleepMs(300)
  discard res.write("part2".toOpenArray(0, 4))
  res.finish()

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

proc hWsIdle(req: Request, res: Response) {.async.} =
  # Like hWsMsg, but the reply suspends on the async runtime again after the
  # message wakes the parked receive -- the ordering the idle-socket test below
  # pins down.
  let ws = req.acceptWebSocket()
  ws.messages(msg):
    await sleepMs(10)
    ws.send("slept: " & msg)

# --- a coroutine parked on a drain while another task ends the response (#408)
#
# The producer fills the stream until `write` reports backpressure against a
# peer that reads nothing (HTTP/1.1: a client that never recv()s; HTTP/2: a
# 16 KiB stream window it never credits; HTTP/3: curl --limit-rate), then parks
# in `await res.drained()` (or `await res.write`, which awaits it after a
# false verdict) while a second task ends the response. finish/abort used to
# drop the drain callback, the only thing that completes that Future, so the
# coroutine stayed parked until the connection died: the HTTP/1.1 write
# timeout (30 s), or for an idle-looking h2 connection, longer still.

var parkResumeMs, parkWasParked, parkWriteAfter, parkDrainedAgain,
    parkEnded, parkResponded, parkBytes, parkDone: Atomic[int]

proc resetPark() =
  for a in [addr parkResumeMs, addr parkWasParked, addr parkWriteAfter,
            addr parkDrainedAgain, addr parkEnded, addr parkResponded,
            addr parkBytes, addr parkDone]:
    a[].store(-1)

const
  parkChunk = 64 * 1024
  parkEndAfterMs = 100      ## the second task ends the response this late
  parkDeclared = 1 shl 30   ## the "short" route declares far more than it sends

proc hParked(req: Request, res: Response) {.async.} =
  ## /park/<how>/<kind>: how = drained | write, kind = abort | finish | short
  ## (finish under a missed Content-Length, the internal abort) | trailers.
  let how = req.param("how")
  let kind = req.param("kind")
  if kind == "short":
    res.sendHead(Http200, "application/octet-stream", contentLength = parkDeclared)
  else:
    res.sendHead(Http200, "application/octet-stream")
  var chunk = newString(parkChunk)
  for i in 0 ..< chunk.len: chunk[i] = char(byte(i mod 251))
  var sent = 0
  let r = res
  let endAt = new(float)               # when the second task ended it
  proc ender() {.async.} =
    await sleepMs(parkEndAfterMs)
    endAt[] = epochTime()
    if kind == "abort": r.abort()
    else:
      if kind == "trailers": r.trailers["x-done"] = "1"
      r.finish()
  let endFut = ender()                 # a second task on the same response
  var waitStart = 0.0
  # Fill until the verdict says backpressure and park; a genuine drain (the
  # kernel's send buffer can still grow on HTTP/1.1) just goes round again, so
  # the wait that counts is the one the end of the response resumes.
  while sent < 512 * 1024 * 1024:
    while sent < 512 * 1024 * 1024:
      sent += chunk.len
      if not res.write(chunk.toOpenArray(0, chunk.high)): break
    waitStart = epochTime()
    if how == "write":
      sent += chunk.len
      await res.write(chunk)           # write + await drained() on the false
    else:
      await res.drained()
    if res.ended: break
  let resumedAt = epochTime()
  # Parked before the end, and resumed after it, within the bound below.
  parkWasParked.store(if endAt[] > 0 and waitStart < endAt[]: 1 else: 0)
  parkResumeMs.store(int((resumedAt - endAt[]) * 1000))
  parkWriteAfter.store(
    if res.write(chunk.toOpenArray(0, 15)): 1 else: 0)  # must refuse, no-op
  # A new drained() on the ended response completes, but on a later loop turn
  # (not inside the call), so a loop that ignores the verdict still yields.
  let again = res.drained()
  let againSync = again.finished
  await again
  parkDrainedAgain.store(if againSync: 0 else: 1)
  parkEnded.store(if res.ended: 1 else: 0)
  parkResponded.store(if res.responded: 1 else: 0)
  parkBytes.store(sent)
  await endFut
  parkDone.store(1)

proc waitPark(ms = 5000): bool =
  ## The parked coroutine ran to its end (it resumed and recorded its checks).
  let deadline = epochTime() + ms / 1000
  while epochTime() < deadline:
    if parkDone.load() == 1: return true
    sleep(10)
  false

template checkResumedOnEnd() =
  ## The parked coroutine resumed because the response ended, promptly (not on
  ## a connection timeout), and then saw a dead response.
  check waitPark()
  check parkWasParked.load() == 1        # waiting when the other task ended it
  check parkResumeMs.load() >= 0
  check parkResumeMs.load() < 2000       # prompt: the h1 write timeout is 30 s
  check parkWriteAfter.load() == 0       # write returns false on it
  check parkDrainedAgain.load() == 1     # a new drained() completes, next turn
  check parkEnded.load() == 1
  check parkResponded.load() == 1


# --- a drain wait parked before the head, answered by a buffered send (#408) --
#
# On HTTP/1.1 `bufferedAmount` is the connection's pending output, so behind an
# earlier pipelined response that is still queued `await res.drained()` parks
# before any head. Another task then answers with a buffered `res.send`; that
# went straight to the keep-alive reset, which dropped the drain callback with
# the rest of the request state, so the wait stayed parked for good.

const preBigLen = 16 * 1024 * 1024       ## the queued response ahead of /pre

proc preBigByte(i: int): char = char(byte((i * 7 + 3) mod 251))

var preBuffered, preResolved, preResolveMs, preEnded, preWrite: Atomic[int]

proc hPreBig(req: Request, res: Response) {.async.} =
  var body = newString(preBigLen)
  for i in 0 ..< body.len: body[i] = preBigByte(i)
  res.send(Http200, body)

proc hPreParked(req: Request, res: Response) {.async.} =
  let r = res
  let sentAt = new(float)
  proc answer() {.async.} =
    await sleepMs(50)
    sentAt[] = epochTime()
    r.send(Http200, "pre")             # a buffered send from a second task
  let other = answer()
  preBuffered.store(res.bufferedAmount)
  await res.drained()                  # parks: /big is still queued
  preResolveMs.store(int((epochTime() - sentAt[]) * 1000))
  preResolved.store(1)
  preEnded.store(if res.ended: 1 else: 0)
  preWrite.store(if res.write("late".toOpenArray(0, 3)): 1 else: 0)
  await other

# --- a producer that ignores write's verdict after another task ends it -------
#
# `drained()` on an ended response used to complete inside the call, and an
# `await` on a completed Future never yields, so `while true: await
# res.write(...)` ignoring the verdict froze the loop thread once a second task
# aborted the response. It now completes on the next loop turn: each turn of
# such a loop yields, and other connections are served meanwhile.

const runawayCap = 1000                  ## producer turns before it gives up

var runawayIter, runawayEnded, runawayWrite, runawayDone, pingAtIter: Atomic[int]

proc hRunaway(req: Request, res: Response) {.async.} =
  res.sendHead(Http200, "application/octet-stream")
  let chunk = repeat('r', 64 * 1024)
  let r = res
  proc ender() {.async.} =
    await sleepMs(100)
    r.abort()
  let endFut = ender()
  for i in 0 ..< runawayCap:
    runawayIter.store(i + 1)
    await res.write(chunk)             # verdict ignored on purpose
  runawayEnded.store(if res.ended: 1 else: 0)
  runawayWrite.store(if res.write(chunk.toOpenArray(0, 15)): 1 else: 0)
  await endFut
  runawayDone.store(1)

proc hPing(req: Request, res: Response) {.async.} =
  pingAtIter.store(runawayIter.load())
  res.send(Http200, "pong")

var appRouter = newRouter()
appRouter.get("/pre-big", hPreBig)
appRouter.get("/pre-parked", hPreParked)
appRouter.get("/runaway", hRunaway)
appRouter.get("/ping", hPing)
appRouter.get("/park/:how/:kind", hParked)
appRouter.get("/ws", hWs)
appRouter.ws("/wsmsg", hWsMsg)
appRouter.ws("/wsidle", hWsIdle)
appRouter.get("/", hRoot)
appRouter.get("/delay", hDelay)
appRouter.get("/hello/:name", hCapture)
appRouter.get("/fan", hFanIn)
appRouter.get("/stale-keep", hStaleKeep)
appRouter.get("/stale-victim", hStaleVictim)
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

    test "router.ws also serves the h2 Extended CONNECT leg (#400)":
      # Same route, the other spelling of the handshake: `:method CONNECT` plus
      # `:protocol websocket` (RFC 8441), with WebSocket framing inside DATA.
      var c = newH2TestConn(srv.port)
      defer: c.close()
      check c.extendedConnect(1, "/wsmsg") == "200"
      c.sendData(1, buildFrame(0x1, "over-h2"))
      let msgs = parseFrames(c.streamData(1, firstWsFrame))[0]
      check msgs.len >= 1
      check msgs[0].op == 0x1
      check msgs[0].payload == "echo: over-h2"

    test "an idle awaited WebSocket still wakes promptly once the loop sleeps":
      # A parked `ws.messages` receive can only be completed by a core callback
      # on the loop thread, so the pump stops spinning and lets the loop block on
      # its selector -- up to its full 1 s idle wait -- while every socket is
      # quiet. Go quiet long enough to be inside that wait, then require a
      # message to still round-trip promptly, including the reply's own
      # runtime-driven await after the resume: that suspension is the one a wrong
      # early exit would strand until the next timeout, so a round trip slower
      # than the idle wait is the failure signature.
      let s = openWs(srv.port, "/wsidle").sock
      defer: s.close()
      sleep(1200)                        # longer than the loop's idle wait
      let t0 = epochTime()
      s.sendText("after-idle")
      check s.recvFrame().payload == "slept: after-idle"
      check epochTime() - t0 < 0.5       # woken by the socket, not by a timeout
      s.sendText("again")
      check s.recvFrame().payload == "slept: again"

    test "a coroutine holding res across the keep-alive boundary misses the next request (#407)":
      staleAsyncBuffered.store(-1)
      staleAsyncDrained.store(0)
      staleAsyncWrite.store(0)
      let s = connectTimeout(srv.port)
      defer: s.close()
      s.send("GET /stale-keep HTTP/1.1\r\nHost: x\r\n\r\n")
      let a = s.readHttpResponse()
      check a.ok and a.body == "kept"
      s.send("GET /stale-victim HTTP/1.1\r\nHost: x\r\n\r\n")
      let b = s.readHttpResponse()
      check b.ok
      check b.body == "part1|part2"
      check staleAsyncDrained.load == 1  # drained() resolved on the dead handle
      check staleAsyncBuffered.load == 0
      check staleAsyncWrite.load == 0
      s.send("GET / HTTP/1.1\r\nHost: x\r\n\r\n")   # still in sync, not closed
      let c = s.readHttpResponse()
      check c.ok and c.body == "sync-in-async"

    # --- #408: a parked drain wait resumes when another task ends the response

    proc h1Parked(path: string): string =
      ## Request `path` over HTTP/1.1 and read nothing until the handler's
      ## parked coroutine has resumed; then read the whole response to close.
      let s = newSocket(buffered = false)
      defer: s.close()
      var rcv = cint(4096)               # keep the kernel's share small
      discard setsockopt(s.getFd, SOL_SOCKET, SO_RCVBUF, addr rcv,
                         SockLen(sizeof(rcv)))
      s.connect("127.0.0.1", srv.port)
      s.send("GET " & path & " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
      discard waitPark()                 # checked by the test, below
      s.recvUntilClose(3000)

    proc h2Parked(path: string): seq[Frame] =
      ## Request `path` over h2c with a 16 KiB stream window and credit nothing
      ## until the parked coroutine has resumed; then open the window and
      ## collect stream 1 to its END_STREAM or RST_STREAM.
      var c = newH2TestConn(srv.port)
      defer: c.close()
      var req = ""
      var settings = ""
      settings.addSetting(setInitialWindowSize, uint32(16 * 1024))
      req.addFrameHeader(settings.len, ftSettings, 0, 0)
      req.add settings
      req.addRequest(1, {":method": "GET", ":scheme": "http",
                         ":path": path, ":authority": "localhost"})
      c.sendRaw(req)
      discard waitPark()                 # checked by the test, below
      var wu = ""
      wu.addWindowUpdate(0, 1 shl 30)
      wu.addWindowUpdate(1, 1 shl 30)
      discard c.rawSend(wu)
      c.readFrames(3000, until = proc(f: seq[Frame]): bool =
        for x in f:
          if x.streamId == 1 and (x.typ == uint8(ftRstStream) or
              (x.flags and flagEndStream) != 0): return true
        false)

    proc h2DataBytes(frames: seq[Frame]): int =
      for f in frames:
        if f.typ == uint8(ftData) and f.streamId == 1: result += f.payload.len

    proc h2Ended(frames: seq[Frame]): bool =
      for f in frames:
        if f.streamId == 1 and (f.flags and flagEndStream) != 0: return true

    for how in ["drained", "write"]:
      let waitDesc = if how == "write": "await res.write" else: "await res.drained()"

      test "h1: " & waitDesc & " parked on a stalled peer resumes on abort() (#408)":
        resetPark()
        let resp = h1Parked("/park/" & how & "/abort")
        checkResumedOnEnd()
        check resp.startsWith("HTTP/1.1 200")
        check not resp.endsWith("0\r\n\r\n")    # closed with no last-chunk

      test "h1: " & waitDesc & " parked on a stalled peer resumes on finish() (#408)":
        resetPark()
        let resp = h1Parked("/park/" & how & "/finish")
        checkResumedOnEnd()
        check resp.endsWith("\r\n0\r\n\r\n")    # a clean chunked end

      test "h1: " & waitDesc & " resumes on a finish() that misses its Content-Length":
        resetPark()
        let resp = h1Parked("/park/" & how & "/short")
        checkResumedOnEnd()
        check resp.startsWith("HTTP/1.1 200")
        check ("content-length: " & $parkDeclared) in resp.toLowerAscii
        check resp.len < parkDeclared           # cut short, then closed

      test "h1: " & waitDesc & " resumes on a finish() with trailers":
        resetPark()
        let resp = h1Parked("/park/" & how & "/trailers")
        checkResumedOnEnd()
        check resp.toLowerAscii.endsWith("\r\n0\r\nx-done: 1\r\n\r\n")

      test "h2: " & waitDesc & " parked on a closed window resumes on abort() (#408)":
        resetPark()
        let frames = h2Parked("/park/" & how & "/abort")
        checkResumedOnEnd()
        check frames.rstError(1) == int(errInternal)
        check not frames.h2Ended

      test "h2: " & waitDesc & " parked on a closed window resumes on finish() (#408)":
        resetPark()
        let frames = h2Parked("/park/" & how & "/finish")
        checkResumedOnEnd()
        check frames.rstError(1) == -1
        check frames.h2Ended
        check frames.h2DataBytes == parkBytes.load()   # nothing lost, nothing late

      test "h2: " & waitDesc & " resumes on a finish() that misses its Content-Length":
        resetPark()
        let frames = h2Parked("/park/" & how & "/short")
        checkResumedOnEnd()
        check frames.rstError(1) == int(errInternal)  # the #345 abort
        check not frames.h2Ended

      test "h2: " & waitDesc & " resumes on a finish() with trailers":
        resetPark()
        let frames = h2Parked("/park/" & how & "/trailers")
        checkResumedOnEnd()
        check frames.rstError(1) == -1
        check frames.h2DataBytes == parkBytes.load()
        var trailer: seq[(string, string)]
        for f in frames:
          if f.typ == uint8(ftHeaders) and f.streamId == 1 and
              (f.flags and flagEndStream) != 0:
            trailer = decodeHeaders(f.payload)
        check ("x-done", "1") in trailer

    proc splitPipelined(raw: string): seq[tuple[head, body: string]] =
      ## Cut a stream of Content-Length responses into (head, body) pairs.
      var pos = 0
      while pos < raw.len:
        let he = raw.find("\r\n\r\n", pos)
        if he < 0: break
        let head = raw[pos ..< he]
        var clen = 0
        for line in head.split("\r\n"):
          if line.toLowerAscii.startsWith("content-length:"):
            clen = parseInt(line.split(':', 1)[1].strip)
        let bodyStart = he + 4
        if bodyStart + clen > raw.len: break
        result.add (head, raw[bodyStart ..< bodyStart + clen])
        pos = bodyStart + clen

    test "h1: a drain wait parked before the head resumes when a buffered send answers it (#408)":
      for a in [addr preBuffered, addr preResolved, addr preResolveMs,
                addr preEnded, addr preWrite]:
        a[].store(-1)
      let s = newSocket(buffered = false)
      defer: s.close()
      var rcv = cint(4096)               # keep /pre-big queued in the server
      discard setsockopt(s.getFd, SOL_SOCKET, SO_RCVBUF, addr rcv,
                         SockLen(sizeof(rcv)))
      s.connect("127.0.0.1", srv.port)
      s.send("GET /pre-big HTTP/1.1\r\nHost: x\r\n\r\n" &
             "GET /pre-parked HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
      # Read nothing until the wait has resumed (or clearly will not): the
      # answer lands 50 ms in, so 1.5 s is ample slack.
      for _ in 0 ..< 150:
        if preResolved.load() == 1: break
        sleep(10)
      check preResolved.load() == 1      # used to stay parked for good
      check preBuffered.load() > 0       # it really parked behind /pre-big
      check preResolveMs.load() >= 0
      check preResolveMs.load() < 500    # resumed by the send, not the close
      check preEnded.load() == 1
      check preWrite.load() == 0         # write refused on the answered request
      let raw = s.recvUntilClose(5000)
      let parts = splitPipelined(raw)
      check parts.len == 2
      if parts.len == 2:
        check parts[0].head.startsWith("HTTP/1.1 200")
        check parts[0].body.len == preBigLen
        var intact = parts[0].body.len == preBigLen
        if intact:
          for i in 0 ..< preBigLen:
            if parts[0].body[i] != preBigByte(i):
              intact = false
              break
        check intact                     # not `check body == ...`: no 16 MiB dump
        check parts[1].head.startsWith("HTTP/1.1 200")
        check parts[1].body == "pre"     # nothing from the late write

    test "h1: a producer ignoring write's verdict after an abort yields to the loop (#408)":
      for a in [addr runawayIter, addr runawayEnded, addr runawayWrite,
                addr runawayDone, addr pingAtIter]:
        a[].store(-1)
      let s = newSocket(buffered = false)
      defer: s.close()
      var rcv = cint(4096)               # a peer that reads nothing: backs up
      discard setsockopt(s.getFd, SOL_SOCKET, SO_RCVBUF, addr rcv,
                         SockLen(sizeof(rcv)))
      s.connect("127.0.0.1", srv.port)
      s.send("GET /runaway HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
      sleep(150)                         # the abort lands at 100 ms
      let p = connectTimeout(srv.port, 3000)
      defer: p.close()
      let t0 = epochTime()
      p.send("GET /ping HTTP/1.1\r\nHost: x\r\n\r\n")
      let pong = p.readHttpResponse()
      let pingMs = int((epochTime() - t0) * 1000)
      check pong.ok and pong.body == "pong"
      check pingMs < 500                 # the loop thread was not frozen
      # Answered while the producer was still looping, not after it gave up.
      check pingAtIter.load() > 0
      check pingAtIter.load() < runawayCap
      for _ in 0 ..< 1500:               # the capped loop runs out, then exits
        if runawayDone.load() == 1: break
        sleep(10)
      check runawayDone.load() == 1
      check runawayIter.load() == runawayCap
      check runawayEnded.load() == 1     # the check a producer must make
      check runawayWrite.load() == 0     # and the verdict it ignored

    test "newVortex overload accepts a bare async handler (no toHandler)":
      proc bare(req: Request, res: Response) {.async.} =
        res.send(Http200, "bare-async")
      let s = newVortex(bare).start(0)
      defer: s.close()
      var client = newHttpClient()
      defer: client.close()
      check client.getContent("http://127.0.0.1:" & $s.port & "/") == "bare-async"

# The same #408 scenario over HTTP/3, against curl reading at a trickle so QUIC
# flow control holds the stream's backlog. Skipped without an HTTP/3 curl. The
# peer-side check is the reset curl reports on abort (and on the short finish);
# a clean finish is checked server-side only, since curl would need minutes to
# read the backlog at that rate.
let h3curlBin = findH3Curl()
if h3curlBin.len == 0:
  echo "SKIP: " & suiteName & " over HTTP/3 (no HTTP/3-capable curl found)"
else:
  let (certFile, keyFile) = makeCertPair("vortex_adapter_h3_")
  withServer(appRouter.toHandler,
             initVortexConfig(numThreads = 1, workerThreads = 2,
                              certFile = certFile, keyFile = keyFile),
             appRouter.streamPredicate, srv3):
    proc h3Parked(path: string): Process =
      ## Start curl on `path` at 16 KiB/s and wait for the parked coroutine.
      result = startProcess(h3curlBin, args = ["-sk", "--http3-only",
        "-m", "30", "--limit-rate", "16K", "-o", "/dev/null",
        "https://localhost:" & $srv3.port & path],
        options = {poStdErrToStdOut})
      discard waitPark()                 # checked by the test, below

    proc curlRc(p: Process, kill: bool): int =
      if kill: p.terminate()
      result = p.waitForExit(15000)
      p.close()

    suite suiteName & " over HTTP/3 (#408)":
      for how in ["drained", "write"]:
        let waitDesc = if how == "write": "await res.write" else: "await res.drained()"

        test "h3: " & waitDesc & " parked on flow control resumes on abort()":
          resetPark()
          let p = h3Parked("/park/" & how & "/abort")
          checkResumedOnEnd()
          check p.curlRc(kill = false) != 0      # curl saw the stream reset

        test "h3: " & waitDesc & " parked on flow control resumes on finish()":
          resetPark()
          let p = h3Parked("/park/" & how & "/finish")
          checkResumedOnEnd()
          discard p.curlRc(kill = true)

        test "h3: " & waitDesc & " resumes on a finish() that misses its Content-Length":
          resetPark()
          let p = h3Parked("/park/" & how & "/short")
          checkResumedOnEnd()
          check p.curlRc(kill = false) != 0      # the #345 reset

        test "h3: " & waitDesc & " resumes on a finish() with trailers":
          resetPark()
          let p = h3Parked("/park/" & how & "/trailers")
          checkResumedOnEnd()
          discard p.curlRc(kill = true)
  removeDir(certFile.parentDir)

echo "server shut down cleanly"
