# Async-adapter conformance suite, shared by both backends (template method
# via a backend define): a plain build tests vortex/asyncdispatch (the default
# suite's tests/test_*.nim glob picks it up); compiling with -d:vortexChronos
# tests vortex/chronos (`nimble testchronos`; chronos is an opt-in dependency,
# so that build stays out of the default suite). The adapters share
# src/vortex/adapters/adapterimpl.nim, but the backend primitives
# (onCompleted, pump, pendingOps) differ, so the full scenario matrix runs
# against each backend.
import std/[unittest, net, httpcore, strutils, os, osproc, posix, atomics,
            monotimes]
import std/httpclient except Response
import std/times except milliseconds        # chronos exports its own
import vortex/[settings, server, routing]   # not `request`: its (sync) blocking
import vortex/staticfiles                    # res.sendFile (fresh-server suite)
import ./helper                              # macro would clash with the async
import ./h2client
import ./wsclient
import vortex/http2/frames
from vortex/connection import conn, totalPins
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


proc hHeadLate(req: Request, res: Response) {.async.} =
  # sendHead with no length after the first await, then an SSE-style loop that
  # keeps the handler future pending. A HEAD must get its head at once, not
  # when the loop ends (#410); a GET streams the ticks as usual.
  let n = parseInt(req.param("n"))
  await sleepMs(20)
  res.sendHead(Http200, "text/plain")
  var i = 0
  while req.isAlive and i < n:
    await sleepMs(100)
    discard res.write("tick")
    inc i
  res.finish()

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

# --- a buffered send from a detached task (#412) ------------------------------
#
# The handler starts a producer it does not await and returns, so the handler's
# future (and with it the adapter's completion kick) completes before the
# producer's buffered `res.send`. That send filled the write buffer and nothing
# flushed it or resumed the pipeline: the response left only when the client's
# next request arrived, and that request was never answered.

template detach(f: untyped) =
  when defined(vortexChronos): asyncSpawn f
  else: asyncCheck f

proc producerBuffered(res: Response) {.async.} =
  await sleepMs(100)
  res.send(Http200, "detached buffered")

proc hDetachedBuf(req: Request, res: Response) {.async.} =
  await sleepMs(10)
  detach producerBuffered(res)          # the handler future completes first

proc hSendThenLinger(req: Request, res: Response) {.async.} =
  # The other order: a buffered send after an await, then the handler keeps
  # running. The send answers the request (and serves a pipelined one) at
  # once; the completion kick that follows holds a stale serial (#407).
  await sleepMs(10)
  res.send(Http200, "answered early")
  await sleepMs(300)

proc hStreamLate(req: Request, res: Response) {.async.} =
  # A streamed body produced after awaits, so sendHead, both writes and finish
  # run from the async pump, after the loop's h3Drive for that iteration.
  await sleepMs(30)
  res.sendHead(Http200, "text/plain")
  discard res.write("late-".toOpenArray(0, 4))
  await sleepMs(30)
  discard res.write("stream".toOpenArray(0, 5))
  res.finish()

proc hBatch(req: Request, res: Response) {.async.} =
  # Many of these on one h2 connection wake in the same pump pass (#412).
  await sleepMs(80)
  res.send(Http200, "batched")

proc hCloseLinger(req: Request, res: Response) {.async.} =
  # Answer, then keep running well past the send: the handler's completion
  # kick lands on a connection the send already moved into its linger close.
  await sleepMs(10)
  res.send(Http200, "linger-close")
  await sleepMs(2500)

proc drainBoom(r: Response) {.gcsafe.} =
  raise newException(ValueError, "drain boom")

proc hRaiseDrain(req: Request, res: Response) {.async.} =
  # The write's flush is held to the pump's end, so the raising callback runs
  # from the loop's release of that hold rather than inside `res.write`.
  await sleepMs(5)
  res.sendHead(Http200, "text/plain")
  res.onDrain drainBoom
  discard res.write("abc".toOpenArray(0, 2))
  await sleepMs(300)
  res.finish()

var drainedAtOnce: Atomic[int]           # 1 = drained() was complete on return

proc hDrainedNow(req: Request, res: Response) {.async.} =
  # A small write on an idle socket, then drained(): the write's flush is held
  # to the pump's end, and drained() must put the bytes out itself rather than
  # park on the drain kick (a loop iteration per chunk).
  await sleepMs(5)
  res.sendHead(Http200, "text/plain")
  let chunk = "d".repeat(1024)
  discard res.write(chunk.toOpenArray(0, chunk.len - 1))
  let f = res.drained()
  drainedAtOnce.store(if f.finished: 1 else: 0)
  await f
  res.finish()

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
appRouter.get("/headlate/:n", hHeadLate)
appRouter.get("/detached-buf", hDetachedBuf)
appRouter.get("/send-linger", hSendThenLinger)
appRouter.get("/streamlate", hStreamLate)
appRouter.get("/batch", hBatch)
appRouter.get("/close-linger", hCloseLinger)
appRouter.get("/raise-drain", hRaiseDrain)
appRouter.get("/drained-now", hDrainedNow)
appRouter.post("/upload", hUpload, streaming = true)
appRouter.post("/upload-reject", hUploadReject, streaming = true)
appRouter.post("/upload-boom", hUploadBoom, streaming = true)
appRouter.post("/upload-read", hUploadRead, streaming = true)

# --- a fresh server: a detach with no await, a saturated pool, shutdown ------
#
# Its own server, so the first request it serves is one whose handler never
# suspends (no earlier handler has installed the adapter's pump on its loop
# thread), with one worker and a one-deep queue so a `blocking:` dispatch can be
# refused, and so the last test can time its shutdown.

proc hNoAwait(req: Request, res: Response) {.async.} =
  # Detach and return without ever suspending: the handler's future is already
  # complete when the adapter sees it (the watch fast path).
  detach producerBuffered(res)

var hogsRunning: Atomic[int]             # bumped by a hog body once dequeued

proc hHog(req: Request, res: Response) {.async.} =
  req.blocking:                          # occupies the single worker (or queues)
    discard hogsRunning.fetchAdd(1)
    sleep(1500)
    res.send(Http200, "hog")

var detFile: string                      # set before the server starts

proc producerFile(res: Response) {.async.} =
  await sleepMs(50)
  {.gcsafe.}:
    res.sendFile(detFile)                # refused by the saturated pool: 503

proc hDetFile(req: Request, res: Response) {.async.} =
  detach producerFile(res)

proc heartbeat() {.async.} =
  while true:
    await sleepMs(10_000)                # an app-owned timer no request waits on

var beatStarted {.threadvar.}: bool

proc hBeat(req: Request, res: Response) {.async.} =
  if not beatStarted:
    beatStarted = true
    detach heartbeat()
  res.send(Http200, "beating")

block:
  let freshRouter = newRouter()
  freshRouter.get("/noawait", hNoAwait)
  freshRouter.get("/hog", hHog)
  freshRouter.get("/det-file", hDetFile)
  freshRouter.get("/beat", hBeat)
  detFile = getTempDir() / ("vortex_adapter_det_" & $getCurrentProcessId())
  writeFile(detFile, "file body")
  var fresh = newVortex(freshRouter.toHandler, initVortexConfig(
    numThreads = 1, workerThreads = 1, maxBlockingQueue = 1)).start(0)
  var closed = false
  defer:
    if not closed: fresh.close()
    removeFile(detFile)

  suite suiteName & " (fresh server)":
    test "a detach from a handler that never suspends is answered (#412)":
      # First request on this server: nothing has installed the pump yet, and
      # the handler's future is complete on return, so the producer's timer was
      # never polled and the request was never answered.
      let s = connectTimeout(fresh.port, 3000)
      defer: s.close()
      let t0 = epochTime()
      s.send("GET /noawait HTTP/1.1\r\nHost: x\r\n\r\n")
      let r = s.readHttpResponse(2000)
      check r.ok and r.body == "detached buffered"
      check epochTime() - t0 < 1.0

    test "a detached sendFile refused by a saturated pool answers 503 at once (#412)":
      # One hog runs, one queues: the pool is at maxBlockingQueue. The 503 for
      # the refused sendFile used to sit in the write buffer: it left with the
      # client's next request, which was never answered.
      # Saturate deterministically. The cap counts tasks not yet started, so
      # three hogs sent at once can see TWO refusals on a loaded runner (the
      # worker has not dequeued the first when the next two arrive) and leave
      # the queue empty. So: one hog, wait until its body is running (queue
      # empty), then two more: one queues, the other is refused at once (its
      # awaitable blocking: body fails with PoolSaturatedError, a 500). From
      # that refusal on, the pool stays full until the running hog finishes.
      var hogs: seq[Socket]
      template sendHog() =
        let h = connectTimeout(fresh.port, 3000)
        h.send("GET /hog HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        hogs.add h
      let before = hogsRunning.load
      sendHog()
      var deadline = epochTime() + 5.0
      while hogsRunning.load == before and epochTime() < deadline: sleep(5)
      check hogsRunning.load == before + 1
      sendHog()
      sendHog()
      var refused = -1
      deadline = epochTime() + 5.0
      while refused < 0 and epochTime() < deadline:
        for i in 1 ..< hogs.len:
          let hr = hogs[i].readHttpResponse(100)
          if hr.ok:
            check hr.head.startsWith("HTTP/1.1 5")
            refused = i
            break
      check refused >= 0
      let s = connectTimeout(fresh.port, 3000)
      defer: s.close()
      s.send("GET /det-file HTTP/1.1\r\nHost: x\r\n\r\n")
      let r = s.readHttpResponse(1500)
      # A 503 means the refusal was answered while the pool was still full
      # (the running hog holds it for 1.5 s); a 200 would mean the sendFile was
      # dispatched after all, and no response is the bug (the 503 waits in the
      # write buffer for the client's next request).
      check r.ok
      check r.head.startsWith("HTTP/1.1 503")
      s.send("GET /noawait HTTP/1.1\r\nHost: x\r\n\r\n")
      let b = s.readHttpResponse(2000)   # the connection moved on
      check b.ok and b.body == "detached buffered"
      for h in hogs:
        discard h.recvUntilClose(4000)
        h.close()

    test "a live app timer does not hold a graceful shutdown (#412)":
      # A detached heartbeat keeps a 10 s timer in the dispatcher for good. The
      # drain used to read the pump's wake cap as pending work and wait out its
      # whole 3 s deadline; nothing the server watches is pending here.
      let s = connectTimeout(fresh.port, 3000)
      s.send("GET /beat HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
      check s.recvUntilClose(2000).endsWith("beating")
      s.close()
      let t0 = epochTime()
      fresh.close()
      closed = true
      check epochTime() - t0 < 1.5        # a stuck drain takes 2 s or more

# --- an awaitable blocking body that raises a Defect (#416) ----------------
#
# Its own server, so the last test can time its shutdown. The awaitable
# trampoline caught only CatchableError: a Defect escaped it, skipping the
# omBlockingDone push, so the awaiting future never completed (no response
# at all), the task's pkAwait pin stayed held, and close() waited out the
# async drain deadline (3 s) for the outstanding result.

proc hDefectValue(req: Request, res: Response) {.async.} =
  let n = 7
  let v = req.blocking(n):
    doAssert n < 0, "defect in a blocking body"
    n
  res.send(Http200, $v)                   # never reached: the await raises

proc hDefectVoid(req: Request, res: Response) {.async.} =
  let n = 1
  req.blocking(n):
    # Raised outright: an out-of-range `s[n]` is undefined under -d:danger
    # (no bounds checks), so it would not raise there.
    if n > 0: raise newException(IndexDefect, "index " & $n & " out of bounds")
    res.send(Http200, "unreachable")

proc hCatchDefect(req: Request, res: Response) {.async.} =
  let n = 7
  try:
    let v = req.blocking(n):
      doAssert n < 0, "caught by the handler"
      n
    res.send(Http200, "no error " & $v)
  except BlockingDefectError as e:
    res.send(Http200, e.msg)

proc hOwnPins(req: Request, res: Response) {.async.} =
  # Loop thread: this connection's pin count once the defect request is done.
  let c = conn(req.core, req.fd, req.gen)
  res.send(Http200, if c == nil: "gone" else: $c.totalPins)

block:
  let defRouter = newRouter()
  defRouter.get("/defect-value", hDefectValue)
  defRouter.get("/defect-void", hDefectVoid)
  defRouter.get("/defect-caught", hCatchDefect)
  defRouter.get("/pins", hOwnPins)
  var dsrv = newVortex(defRouter.toHandler, initVortexConfig(
    numThreads = 1, workerThreads = 1)).start(0)
  var closed = false
  defer:
    if not closed: dsrv.close()

  suite suiteName & " (blocking body Defect, #416)":
    for path in ["/defect-value", "/defect-void"]:
      test "a Defect in an awaitable blocking body answers 500 and unpins (" &
          path & ")":
        let s = connectTimeout(dsrv.port, 3000)
        defer: s.close()
        s.send("GET " & path & " HTTP/1.1\r\nHost: x\r\n\r\n")
        let r = s.readHttpResponse(2000)
        check r.ok
        check r.head.startsWith("HTTP/1.1 500")
        # Same connection: it moved on, and the task's pin is released.
        s.send("GET /pins HTTP/1.1\r\nHost: x\r\n\r\n")
        let p = s.readHttpResponse(2000)
        check p.ok and p.body == "0"

    test "the Defect reaches the handler as a BlockingDefectError":
      let s = connectTimeout(dsrv.port, 3000)
      defer: s.close()
      s.send("GET /defect-caught HTTP/1.1\r\nHost: x\r\n\r\n")
      let r = s.readHttpResponse(2000)
      check r.ok
      check r.body.startsWith("AssertionDefect: ")
      check "caught by the handler" in r.body
      # The trace sits under a "Stack trace:" header, so a one-line log
      # summary (#423) stops before it instead of flattening it.
      check "\nStack trace:\n" in r.body

    test "close() after a Defect in a blocking body does not wait out the drain":
      let s = connectTimeout(dsrv.port, 3000)
      s.send("GET /defect-value HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
      discard s.recvUntilClose(2000)
      s.close()
      let t0 = getMonoTime()
      dsrv.close()
      closed = true
      # The drain deadline is 3 s and the unfixed case took about 18 s; the
      # bound leaves headroom for a loaded host.
      check (getMonoTime() - t0).inMilliseconds < 2500

# --- an idle loop thread with live long timers (#417) -------------------------
#
# A timer nobody waits on (a detached heartbeat, the leftover timer of a
# `withTimeout` whose operation finished early) must cost the loop thread one
# wakeup when it is due, not one every few ms for as long as it lives. The
# asyncdispatch pump answered any such timer with a 5 ms wake cap.

proc loopThreadCpuNs(): int64 =
  var ts: Timespec
  discard clock_gettime(CLOCK_THREAD_CPUTIME_ID, ts)
  int64(ts.tv_sec) * 1_000_000_000 + int64(ts.tv_nsec)

proc hArmTimers(req: Request, res: Response) {.async.} =
  detach heartbeat()                     # a 10 s timer, re-armed for good
  # Finishes after 5 ms; its 30 s timeout timer stays in the dispatcher's heap.
  when defined(vortexChronos):
    discard await withTimeout(sleepMs(5), 30_000.milliseconds)
  else:
    discard await withTimeout(sleepMs(5), 30_000)
  res.send(Http200, "armed")

proc hLoopCpu(req: Request, res: Response) {.async.} =
  res.send(Http200, $loopThreadCpuNs())  # runs on the (only) loop thread

block:
  let idleRouter = newRouter()
  idleRouter.get("/arm", hArmTimers)
  idleRouter.get("/cpu", hLoopCpu)
  var idle = newVortex(idleRouter.toHandler,
                       initVortexConfig(numThreads = 1)).start(0)
  defer: idle.close()

  proc idleGet(path: string): string =
    let s = connectTimeout(idle.port, 3000)
    defer: s.close()
    s.send("GET " & path & " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    let r = s.readHttpResponse(3000)
    doAssert r.ok, path
    r.body

  suite suiteName & " (idle loop)":
    test "live long timers do not wake an idle loop thread (#417)":
      check idleGet("/arm") == "armed"
      sleep(50)
      let c0 = parseBiggestInt(idleGet("/cpu"))
      sleep(2000)                        # idle: only the two long timers live
      let c1 = parseBiggestInt(idleGet("/cpu"))
      let cpu = float(c1 - c0) / 1e9
      # A 5 ms wake cap costs 0.019 to 0.036 s of loop CPU over this window,
      # depending on the host (0.094 s per 5 s measured); one wakeup per second
      # of idle wait costs under a millisecond (0.0008 s measured).
      echo "    loop thread CPU over 2 s idle: ", formatFloat(cpu, ffDecimal, 4),
        " s"
      check cpu < 0.003

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

    test "a no-length sendHead after an await answers a HEAD at once (#410)":
      # The head used to sit in the write buffer until the handler's future
      # completed (~3 s here, never for an endless loop).
      let s = connectTimeout(srv.port, 3000)
      defer: s.close()
      let t0 = epochTime()
      s.send("HEAD /headlate/30 HTTP/1.1\r\nHost: x\r\n\r\n")
      let head = s.recvAvailable(3000)
      let elapsed = epochTime() - t0
      check head.startsWith("HTTP/1.1 200")
      check head.endsWith("\r\n\r\n")       # head only, no body
      check "Transfer-Encoding: chunked" in head
      check "Content-Length" notin head
      check elapsed < 0.2
      # The connection moved on to the next request while the handler is
      # still looping; its writes on the stale handle reach nothing (#407).
      s.send("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      let next = s.readHttpResponse()
      check next.ok and next.body == "sync-in-async"
      check "tick" notin next.body

    test "the same route streams normally on a GET (#410)":
      let s = connectTimeout(srv.port, 3000)
      defer: s.close()
      s.send("GET /headlate/3 HTTP/1.1\r\nHost: x\r\n\r\n")
      let r = s.readHttpResponse()
      check r.ok
      check "Transfer-Encoding: chunked" in r.head
      check r.body == "tick".repeat(3)

    test "a buffered send from a detached task is flushed at once (#412)":
      # The response used to sit in the write buffer until the client sent
      # something else, and the request after it was never answered.
      let s = connectTimeout(srv.port, 3000)
      defer: s.close()
      let t0 = epochTime()
      s.send("GET /detached-buf HTTP/1.1\r\nHost: x\r\n\r\n")
      let a = s.readHttpResponse(2000)  # nothing else is sent meanwhile
      check a.ok and a.body == "detached buffered"
      check "Content-Length: 17" in a.head
      check epochTime() - t0 < 1.0
      s.send("GET /ping HTTP/1.1\r\nHost: x\r\n\r\n")
      let b = s.readHttpResponse(2000)
      check b.ok and b.body == "pong"

    proc readPipelined(s: Socket, want: int, timeoutMs = 2000): seq[string] =
      ## The bodies of `want` Content-Length responses read off one socket,
      ## fewer if it goes quiet for `timeoutMs` first.
      s.setRecvTimeout(timeoutMs)
      var raw = ""
      var tmp = newString(8192)
      while true:
        var pos = 0
        result.setLen(0)
        while true:
          let he = raw.find("\r\n\r\n", pos)
          if he < 0: break
          var clen = 0
          for line in raw[pos ..< he].split("\r\n"):
            if line.toLowerAscii.startsWith("content-length:"):
              clen = parseInt(line.split(':', 1)[1].strip)
          if he + 4 + clen > raw.len: break
          result.add raw[he + 4 ..< he + 4 + clen]
          pos = he + 4 + clen
        if result.len >= want: return
        let n = recv(s.getFd, addr tmp[0], tmp.len, cint(0))
        if n <= 0: return
        raw.add tmp.substr(0, n - 1)

    test "a detached buffered send answers, then serves the pipelined request (#412)":
      # /ping is already buffered behind /detached-buf, so no later read event
      # could have brought either response out.
      let s = connectTimeout(srv.port, 3000)
      defer: s.close()
      s.send("GET /detached-buf HTTP/1.1\r\nHost: x\r\n\r\n" &
             "GET /ping HTTP/1.1\r\nHost: x\r\n\r\n")
      check s.readPipelined(2) == @["detached buffered", "pong"]

    test "a detached buffered send answers a HEAD at once (#412)":
      let s = connectTimeout(srv.port, 3000)
      defer: s.close()
      s.send("HEAD /detached-buf HTTP/1.1\r\nHost: x\r\n\r\n")
      let head = s.recvAvailable(2000)
      check head.startsWith("HTTP/1.1 200")
      check "Content-Length: 17" in head
      check head.endsWith("\r\n\r\n")       # head only, no body
      s.send("GET /ping HTTP/1.1\r\nHost: x\r\n\r\n")
      let b = s.readHttpResponse(2000)
      check b.ok and b.body == "pong"

    test "a detached buffered send on Connection: close answers and closes (#412)":
      let s = connectTimeout(srv.port, 3000)
      defer: s.close()
      let t0 = epochTime()
      s.send("GET /detached-buf HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
      let raw = s.recvUntilClose(2000)
      check raw.startsWith("HTTP/1.1 200")
      check raw.endsWith("\r\n\r\ndetached buffered")
      check epochTime() - t0 < 1.0       # closed by the server, not a timeout

    test "a buffered send before the handler returns serves the next request at once (#412)":
      let s = connectTimeout(srv.port, 3000)
      defer: s.close()
      let t0 = epochTime()
      s.send("GET /send-linger HTTP/1.1\r\nHost: x\r\n\r\n" &
             "GET /ping HTTP/1.1\r\nHost: x\r\n\r\n")
      check s.readPipelined(2) == @["answered early", "pong"]
      check epochTime() - t0 < 0.25      # not after the handler's 300 ms linger
      sleep(350)                         # its completion kick finds a stale serial
      s.send("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      let c = s.readHttpResponse(2000)
      check c.ok and c.body == "sync-in-async"

    test "h2: a buffered send from a detached task is flushed at once (#412)":
      var c = newH2TestConn(srv.port)
      defer: c.close()
      var req = ""
      req.addRequest(1, {":method": "GET", ":scheme": "http",
                         ":path": "/detached-buf", ":authority": "localhost"})
      c.sendRaw(req)
      let t0 = epochTime()
      let frames = c.readFrames(2000, until = proc(f: seq[Frame]): bool =
        for x in f:
          if x.streamId == 1 and (x.flags and flagEndStream) != 0: return true
        false)
      check epochTime() - t0 < 1.0
      var body = ""
      var ended = false
      for f in frames:
        if f.streamId != 1: continue
        if f.typ == uint8(ftData): body.add f.payload
        if (f.flags and flagEndStream) != 0: ended = true
      check ended
      check body == "detached buffered"

    test "h2: fifty streams answered in one pump pass all arrive (#412)":
      # Every handler wakes on the same timer tick, so their sends land in one
      # pump pass; the loop holds their flushes to the pump's end and writes
      # them in one send() rather than one per stream.
      const n = 50
      var c = newH2TestConn(srv.port)
      defer: c.close()
      var req = ""
      for i in 0 ..< n:
        req.addRequest(uint32(1 + 2 * i), {":method": "GET", ":scheme": "http",
                       ":path": "/batch", ":authority": "localhost"})
      c.sendRaw(req)
      let t0 = epochTime()
      let frames = c.readFrames(3000, until = proc(f: seq[Frame]): bool =
        var done = 0
        for x in f:
          if (x.flags and flagEndStream) != 0 and x.streamId != 0: inc done
        done >= n)
      check epochTime() - t0 < 1.0
      var bodies = newSeq[string](n)
      var ended = 0
      for f in frames:
        if f.streamId == 0: continue
        let i = int(f.streamId - 1) div 2
        if f.typ == uint8(ftData): bodies[i].add f.payload
        if (f.flags and flagEndStream) != 0: inc ended
      check ended == n
      for b in bodies: check b == "batched"

    test "drained() after a write held by the pump flushes it at once (#412)":
      # Count-free check of the write-then-drained() throughput fix: with the
      # bytes on the socket the wait completes inside the call. Parked on the
      # drain kick instead, it cost a loop iteration per chunk.
      drainedAtOnce.store(-1)
      let s = connectTimeout(srv.port, 3000)
      defer: s.close()
      s.send("GET /drained-now HTTP/1.1\r\nHost: x\r\n\r\n")
      let r = s.readHttpResponse(2000)
      check r.ok and r.body == "d".repeat(1024)
      check drainedAtOnce.load == 1

    test "h2: drained() after a write held by the pump flushes it at once (#412)":
      drainedAtOnce.store(-1)
      var c = newH2TestConn(srv.port)
      defer: c.close()
      var req = ""
      req.addRequest(1, {":method": "GET", ":scheme": "http",
                         ":path": "/drained-now", ":authority": "localhost"})
      c.sendRaw(req)
      let frames = c.readFrames(2000, until = proc(f: seq[Frame]): bool =
        for x in f:
          if x.streamId == 1 and (x.flags and flagEndStream) != 0: return true
        false)
      var body = ""
      for f in frames:
        if f.streamId == 1 and f.typ == uint8(ftData): body.add f.payload
      check body == "d".repeat(1024)
      check drainedAtOnce.load == 1

    test "a raising onDrain from a held flush does not end the loop thread (#412)":
      # The pump's release of its flush hold ran the HTTP/1 drain callback
      # outside any guard: the exception escaped run(), the loop thread exited
      # and closed its listener, so a new connection was refused. The callback's
      # own connection is closed instead, as for a dispatch error.
      block:
        let s = connectTimeout(srv.port, 3000)
        defer: s.close()
        s.send("GET /raise-drain HTTP/1.1\r\nHost: x\r\n\r\n")
        let raw = s.recvUntilClose(2000)
        check raw.startsWith("HTTP/1.1 200")
      let s2 = connectTimeout(srv.port, 3000)
      defer: s2.close()
      s2.send("GET /ping HTTP/1.1\r\nHost: x\r\n\r\n")
      let b = s2.readHttpResponse(2000)
      check b.ok and b.body == "pong"

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

# A Connection: close request answered by a send while its handler keeps
# running, over TLS. The send kicks the connection at once: it flushes, queues
# close_notify, half-closes and arms the drain deadline (the linger close). The
# handler's completion kick follows 2.5 s later with the same request serial and
# must find nothing to do: resuming again flipped the connection back to
# csClosing and ran the linger close a second time (another close_notify and
# SHUT_WR, and a drain deadline re-armed from the late kick), so a client that
# keeps its socket open was held about 2.5 s past the drain timeout.
block:
  let (tlsCert, tlsKey) = makeCertPair("vortex_adapter_tls_")
  withServer(appRouter.toHandler,
             initVortexConfig(numThreads = 1, workerThreads = 2,
                              certFile = tlsCert, keyFile = tlsKey),
             appRouter.streamPredicate, srvT):
    suite suiteName & " over TLS (#412)":
      test "a late completion kick does not restart the linger close":
        let ctx = newContext(verifyMode = CVerifyNone)
        let s = newSocket(buffered = false)
        defer: s.close()
        s.connect("127.0.0.1", srvT.port)
        ctx.wrapConnectedSocket(s, handshakeAsClient, "localhost")
        s.send("GET /close-linger HTTP/1.1\r\nHost: x\r\n" &
               "Connection: close\r\n\r\n")
        let t0 = epochTime()
        s.setRecvTimeout(2000)
        var resp = ""
        var buf = newString(4096)
        while not resp.endsWith("linger-close"):
          var n = 0
          try: n = s.recv(addr buf[0], buf.len)
          except CatchableError: break
          if n <= 0: break
          resp.add buf[0 ..< n]
        check resp.startsWith("HTTP/1.1 200")
        check resp.endsWith("\r\n\r\nlinger-close")
        check epochTime() - t0 < 1.0
        # Keep the socket open and poke it with raw bytes below the TLS layer:
        # a draining server reads and discards them, a closed one answers with
        # a reset, which the next send or read reports.
        const noSig = when defined(linux): MSG_NOSIGNAL else: cint(0)
        let probe = "x"
        s.setRecvTimeout(20)             # each read below waits at most 20 ms
        var closedAfter = -1.0
        while epochTime() - t0 < 9.0:
          sleep(100)
          let w = posix.send(s.getFd, unsafeAddr probe[0], 1, noSig)
          var b: array[64, char]
          let r = posix.recv(s.getFd, addr b[0], b.len, cint(0))
          let err = errno
          if w < 0 or (r < 0 and err != EAGAIN and err != EWOULDBLOCK):
            closedAfter = epochTime() - t0
            break
        # The drain deadline is 5 s on a whole-second clock, armed at the send:
        # closed 4 to 5 s in. Re-armed by the late kick it was 6.5 s or more.
        check closedAfter > 0
        check closedAfter < 6.0
  removeDir(tlsCert.parentDir)

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

    suite suiteName & " over HTTP/3 (#412)":
      test "h3: a buffered send from a detached task is flushed at once":
        # It used to wait in the QUIC send buffer for the loop's next wakeup:
        # the selector's idle wait, about 1 s after the send. First on this
        # server, so no earlier test's QUIC connection (a killed curl's
        # retransmit timers) wakes the loop early and hides the stall.
        for i in 0 ..< 3:
          let (output, rc) = execCmdEx(h3curlBin & " -sk --http3-only -m 5 " &
            "-w '|%{time_appconnect}|%{time_starttransfer}' " &
            "https://localhost:" & $srv3.port & "/detached-buf")
          check rc == 0
          let parts = output.strip.split('|')
          check parts.len == 3
          if parts.len == 3:
            check parts[0] == "detached buffered"
            # From the handshake to the first response byte: the producer's
            # 110 ms plus a loopback round trip, not the idle wait.
            let waitS = parseFloat(parts[2]) - parseFloat(parts[1])
            check waitS < 0.6

      test "h3: a body streamed after an await is driven out at once":
        # sendHead, write and finish from the async pump left their bytes in
        # the QUIC send buffer for the selector's idle wait: about 1.1 s per
        # response instead of the handler's 60 ms.
        for i in 0 ..< 3:
          let (output, rc) = execCmdEx(h3curlBin & " -sk --http3-only -m 5 " &
            "-w '|%{time_appconnect}|%{time_total}' " &
            "https://localhost:" & $srv3.port & "/streamlate")
          check rc == 0
          let parts = output.strip.split('|')
          check parts.len == 3
          if parts.len == 3:
            check parts[0] == "late-stream"
            let waitS = parseFloat(parts[2]) - parseFloat(parts[1])
            check waitS < 0.6

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
