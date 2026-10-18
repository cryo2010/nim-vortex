## Awaitable outbound backpressure: a producer streams a large body and yields
## with `await res.drained()` when `res.write` reports the backlog is full. A
## deliberately slow-reading client forces the backpressure, and we assert both
## that the whole body arrives intact and that the producer actually suspended.

import std/[unittest, net, posix, strutils, httpcore, atomics]
from std/os import sleep
import vortex/[settings, request, server, routing]
import vortex/asyncdispatch
import ./helper

var drainCount: Atomic[int]

proc bigStream(req: Request, res: Response) {.async.} =
  res.sendHead(Http200, "application/octet-stream")
  let chunk = repeat('x', 8192)
  for i in 0 ..< 512:                    # 4 MiB
    # Low-level bool form on purpose (this test counts drains); a string arg
    # would resolve to the awaitable `await res.write`, so slice to openArray.
    if not res.write(chunk.toOpenArray(0, chunk.high)):
      drainCount.atomicInc
      await res.drained()                # yield until the socket drains
  res.finish()

proc drainedEveryWrite(req: Request, res: Response) {.async.} =
  ## `await res.drained()` after EVERY write, whatever the verdict (#403). A
  ## write that returns true can leave part of the chunk in the write buffer
  ## (the socket took the rest), and flushOut delivered a drain only to a
  ## response a false verdict had marked, so a wait registered there parked
  ## forever.
  res.sendHead(Http200, "application/octet-stream")
  let chunk = repeat('d', 32 * 1024)
  for i in 0 ..< 128:                    # 4 MiB
    discard res.write(chunk.toOpenArray(0, chunk.high))
    await res.drained()
  res.finish()

proc onDrainEveryWrite(req: Request, res: Response) {.gcsafe.} =
  ## The sync shape: resume from `res.onDrain` after every write, unmarked, often
  ## with nothing queued at all (#403).
  res.sendHead(Http200, "application/octet-stream")
  var n = 0
  proc pump(r: Response) {.gcsafe.} =
    if n >= 128:
      r.finish()
      return
    inc n
    discard r.write(repeat('o', 32 * 1024))
    r.onDrain(pump)
  pump(res)

type BeforeHead = ref object
  ## State of a producer whose first drain registration precedes its head.
  n: int                                 # 8 KiB chunks written so far
  resumed: bool                          # the first registration has fired
  done: Future[void]                     # completed after finish (async route)

const beforeHeadChunks = 512             # 4 MiB in 8 KiB writes

type DrainCb = proc (r: Response) {.gcsafe.}

proc beforeHeadPump(st: BeforeHead): DrainCb {.gcsafe.} =
  ## The drain callback: resume writing, re-registering on backpressure.
  result = proc (r: Response) {.gcsafe.} =
    st.resumed = true
    let chunk = repeat('b', 8192)
    while st.n < beforeHeadChunks:
      inc st.n
      if not r.write(chunk.toOpenArray(0, chunk.high)):
        r.onDrain(beforeHeadPump(st))
        return
    r.finish()
    if st.done != nil and not st.done.finished: complete(st.done)

proc beforeHeadWrite(st: BeforeHead, res: Response) =
  ## After the head: write until a write returns true but leaves a backlog, and
  ## stop there WITHOUT registering again. Only the registration made before
  ## sendHead can resume the producer, and the write buffer still holds bytes,
  ## so it is a drain event, not the kick, that has to deliver it.
  let chunk = repeat('b', 8192)
  while not st.resumed and st.n < beforeHeadChunks and res.bufferedAmount == 0:
    inc st.n
    discard res.write(chunk.toOpenArray(0, chunk.high))

proc onDrainBeforeHead(req: Request, res: Response) {.gcsafe.} =
  ## res.onDrain BEFORE res.sendHead, in the same call stack: the kick the
  ## registration queued runs after the head and the writes (#403 review).
  let st = BeforeHead()
  res.onDrain(beforeHeadPump(st))
  res.sendHead(Http200, "application/octet-stream")
  beforeHeadWrite(st, res)

proc onDrainBeforeHeadAsync(req: Request, res: Response) {.async.} =
  ## The same, with a loop pass between the registration and the head, so the
  ## kick runs while the response is not streaming yet and has nothing to fire.
  ## Awaits the producer's end: a future that completes mid-stream closes the
  ## connection (the response was left unfinished).
  let st = BeforeHead(done: newFuture[void]("beforeHead"))
  res.onDrain(beforeHeadPump(st))
  await sleepAsync(20)
  res.sendHead(Http200, "application/octet-stream")
  beforeHeadWrite(st, res)
  await st.done

var abandonedDone: Atomic[int]          # async producers that ran their finally
var abandonedParked: Atomic[int]        # async producers parked on a drain
var syncParked: Atomic[int]             # sync producer has a drain registered
var syncStop: Atomic[bool]              # the client is about to disconnect
var syncFiredAfterStop: Atomic[int]     # sync drains delivered after syncStop

proc abandonedStream(req: Request, res: Response) {.async.} =
  ## Streams far more than the client will ever read, then is abandoned
  ## mid-body. The teardown must resume the `await res.write` parked on the
  ## drain, or this coroutine (and its finally) never completes.
  try:
    res.sendHead(Http200, "application/octet-stream")
    let chunk = repeat('a', 64 * 1024)
    for i in 0 ..< 1024:                 # 64 MiB, never fully read
      if not req.isAlive: break
      if not res.write(chunk.toOpenArray(0, chunk.high)):
        abandonedParked.atomicInc
        await res.drained()
    res.finish()
  finally:
    abandonedDone.atomicInc

proc abandonedOnDrain(req: Request, res: Response) {.gcsafe.} =
  ## The sync shape: an `res.onDrain` producer left parked when the client goes.
  res.sendHead(Http200, "application/octet-stream")
  var n = 0
  proc pump(r: Response) {.gcsafe.} =
    syncParked.store(0)
    let chunk = repeat('s', 64 * 1024)
    if syncStop.load:
      syncFiredAfterStop.atomicInc     # the close delivered the parked drain
      # Keep producing from inside the teardown, as a naive producer would:
      # the write, the re-registration and the finish must all be no-ops on
      # the dying connection (no send, no selector re-arm, no re-entry).
      if not r.write(chunk.toOpenArray(0, chunk.high)):
        r.onDrain(pump)
      r.finish()
      return
    while n < 1024:                      # 64 MiB, never fully read
      inc n
      if not r.write(chunk.toOpenArray(0, chunk.high)):
        syncParked.store(1)
        r.onDrain(pump)
        return
    r.finish()
  pump(res)

var rt = newRouter()
rt.get("/abandoned", abandonedStream)
rt.get("/abandoned-ondrain", abandonedOnDrain)
rt.get("/big", bigStream)
rt.get("/drained-every", drainedEveryWrite)
rt.get("/ondrain-every", onDrainEveryWrite)
rt.get("/ondrain-before-head", onDrainBeforeHead)
rt.get("/ondrain-before-head-async", onDrainBeforeHeadAsync)

withServer(rt.toHandler, initVortexConfig(numThreads = 1), srv):
  let port = srv.port

  proc slowGet(path: string): string =
    ## Read the response slowly (small reads with pauses) so the server's write
    ## backlog fills and the producer has to await drained().
    let s = newSocket(buffered = false)
    defer: s.close()
    # Force TCP backpressure deterministically instead of racing timing: a small
    # receive buffer keeps the advertised window tiny, so the server cannot offload
    # the 4 MiB into kernel buffers (regardless of its SO_SNDBUF autotuning or of
    # ASan slowdown). Its app-level outbox then fills past the high water and the
    # producer must await drained(). Must be set before connect.
    var rcvbuf: cint = 16 * 1024
    discard setsockopt(s.getFd, SOL_SOCKET, SO_RCVBUF, addr rcvbuf,
                       SockLen(sizeof(rcvbuf)))
    s.connect("127.0.0.1", port)
    s.send("GET " & path & " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    s.setRecvTimeout(5000)
    var buf = newString(8192)
    var reads = 0
    while true:
      let k = recv(s.getFd, addr buf[0], buf.len, cint(0))
      if k <= 0: break
      result.add buf[0 ..< k]
      inc reads
      if reads mod 8 == 0: os.sleep(2)     # throttle the consumer
    discard result

  proc dechunk(body: string): string =
    var pos = 0
    while true:
      let nl = body.find("\r\n", pos)
      if nl < 0: break
      let size = parseHexInt(body[pos ..< nl].strip())
      pos = nl + 2
      if size == 0: break
      result.add body[pos ..< pos + size]
      pos += size + 2

  template checkBeforeHead(path: string) =
    ## A template so the checks mark the test FAILED.
    let resp = slowGet(path)
    let i = resp.find("\r\n\r\n")
    check i > 0
    if i > 0:
      let body = dechunk(resp[i + 4 .. ^1])
      check body.len == beforeHeadChunks * 8192
      let intact = body == repeat('b', beforeHeadChunks * 8192)
      check intact                       # not `check body == ...`: no 4 MiB dump

  proc abandonGet(path: string): bool =
    ## Read a little of a large streamed response, stop reading long enough for
    ## the server to back up and park its producer, then close with unread data
    ## queued (a RST), so the server sees the client go mid-body. Returns
    ## whether the sync producer had a drain registered just before the close.
    let s = newSocket(buffered = false)
    var rcvbuf: cint = 16 * 1024
    discard setsockopt(s.getFd, SOL_SOCKET, SO_RCVBUF, addr rcvbuf,
                       SockLen(sizeof(rcvbuf)))
    s.connect("127.0.0.1", port)
    s.send("GET " & path & " HTTP/1.1\r\nHost: x\r\n\r\n")
    s.setRecvTimeout(5000)
    var buf = newString(8192)
    var got = 0
    while got < 64 * 1024:
      let k = recv(s.getFd, addr buf[0], buf.len, cint(0))
      if k <= 0: break
      got += k
    os.sleep(300)                        # let the server's buffers fill
    result = syncParked.load == 1
    if path == "/abandoned-ondrain": syncStop.store(true)
    s.close()

  template eventually(cond: untyped, ms = 3000): bool =
    ## Poll `cond` until it holds or `ms` elapse.
    var ok = false
    for _ in 0 ..< ms div 10:
      if cond:
        ok = true
        break
      os.sleep(10)
    ok

  suite "awaitable outbound backpressure":
    test "await res.drained() streams a large body under a slow reader":
      let resp = slowGet("/big")
      let i = resp.find("\r\n\r\n")
      check "Transfer-Encoding: chunked" in resp[0 ..< i]
      let body = dechunk(resp[i + 4 .. ^1])
      check body.len == 512 * 8192
      check body == repeat('x', 512 * 8192)
      check drainCount.load > 0            # the producer actually suspended

    test "await res.drained() after every write completes (#403)":
      let resp = slowGet("/drained-every")
      let i = resp.find("\r\n\r\n")
      check i > 0
      if i > 0:
        let body = dechunk(resp[i + 4 .. ^1])
        check body.len == 128 * 32 * 1024
        let intact = body == repeat('d', 128 * 32 * 1024)
        check intact                     # not `check body == ...`: no 4 MiB dump

    test "res.onDrain after every write completes (#403)":
      let resp = slowGet("/ondrain-every")
      let i = resp.find("\r\n\r\n")
      check i > 0
      if i > 0:
        let body = dechunk(resp[i + 4 .. ^1])
        check body.len == 128 * 32 * 1024
        let intact = body == repeat('o', 128 * 32 * 1024)
        check intact                     # not `check body == ...`: no 4 MiB dump

    test "res.onDrain registered before sendHead fires once the body drains":
      # onDrain marked the h1 response for flushOut only once it was streaming,
      # and the kick skipped a response with bytes still queued without marking
      # it, so a registration made before the head was never delivered: the
      # body stopped at the first write that left a backlog (~400 KiB of 4 MiB).
      checkBeforeHead("/ondrain-before-head")

    test "res.onDrain before sendHead, with a loop pass in between":
      checkBeforeHead("/ondrain-before-head-async")

    test "client gone mid-body resumes an h1 producer parked in await res.drained()":
      # closeConn fired a parked onRespDrain only through h2NotifyClosed; an
      # HTTP/1.1 producer suspended on a drain when its client dropped never
      # resumed, leaking its Future, closure and request handles for good.
      discard abandonGet("/abandoned")
      check abandonedParked.load > 0     # it really was parked on a drain
      check eventually(abandonedDone.load == 1)

    test "client gone mid-body delivers a parked h1 res.onDrain exactly once":
      check abandonGet("/abandoned-ondrain")   # parked on a drain at the close
      check eventually(syncFiredAfterStop.load >= 1)
      os.sleep(200)
      check syncFiredAfterStop.load == 1

echo "server shut down cleanly"
