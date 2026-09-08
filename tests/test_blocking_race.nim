## ThreadSanitizer regression for C3 / IMP2: a `req.blocking:` worker must read
## a request SNAPSHOT, never live loop memory. Over HTTP/2 the old code had the
## worker call h2Field / h2Stream, materializing H2Conn/H2Stream refs and racing
## the loop's non-atomic ORC refcounts. This drives many concurrent h2c blocking
## requests across several loop threads + the worker pool; built under TSan by
## `nimble testrace`, TSan aborts on any data race.

import std/[net, atomics, unittest]
import vortex
import ./h2client
from vortex/http2/frames import FrameType, ftHeaders

const
  clients = 4
  itersPer = 15

proc handler(req: Request, res: Response) {.gcsafe.} =
  req.blocking:
    # On the worker: every one of these would touch live h2 state (h2Field /
    # h2Stream) in the pre-IMP2 code. They must now read the snapshot.
    let sink = req.method.int + req.path.len + req.header("x-test").len +
               req.body.len + req.remoteAddress.len + req.params.len +
               (if req.isSecure: 1 else: 0)
    doAssert sink >= 0        # worker thread: keep doAssert (check mutates
                              # unittest globals and would race under TSan)
    res.send(Http200, "ok")

var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 4)).start(0)
let port = srv.port

var okCount: Atomic[int]

proc clientThread(a: (Port, int)) {.thread.} =
  let (p, iters) = a
  {.cast(gcsafe).}:                        # test-only h2 client, per-thread conn
    for _ in 0 ..< iters:
      var c = newH2TestConn(p)
      c.sendHeaders(1)                     # GET / (static-table HPACK), END_STREAM
      let frames = c.readFrames(timeoutMs = 3000,
        until = proc(fs: seq[Frame]): bool = fs.count(ftHeaders) >= 1)
      if frames.count(ftHeaders) >= 1: okCount.atomicInc()
      c.close()

var threads: array[clients, Thread[(Port, int)]]
for i in 0 ..< clients:
  createThread(threads[i], clientThread, (port, itersPer))
joinThreads(threads)

srv.close()
check okCount.load == clients * itersPer
echo "blocking race regression ok (", okCount.load, " h2 blocking requests)"

# --- awaitable-emit double-release race (typed pin-release regression) ------
# An awaitable req.blocking task holds a pkAwait pin until its omBlockingDone
# message; any response the BODY emits on the worker must carry release=prNone
# (formerly keepPin=true). If that stamp is ever lost, the body's omHttp
# releases a pin the task does not own: the typed accounting doAsserts (the
# server aborts, every stream below fails), and pre-assert code would free the
# slot under the still-running worker (a use-after-free TSan catches when this
# file runs under `nimble testrace`). Drive many CONCURRENT h2 streams whose
# awaitable bodies emit inside the body -- so the prNone response and the
# prAwait omBlockingDone race through the outbox back to back -- and assert
# every stream completes and the server survives shutdown.

from vortex/request import dispatchBlockingResult, BlockingResultBox,
                           BlockingResultBase

proc emitBody(req: Request, res: Response, args: int) {.nimcall, gcsafe.} =
  # Worker thread: doAssert, not check (unittest globals race under TSan).
  doAssert args == 42
  doAssert req.path.len >= 1          # snapshot read on the worker
  res.send(Http200, "emitted")        # emits INSIDE the awaitable body

proc awaitEmitHandler(req: Request, res: Response) {.gcsafe.} =
  # Drive the awaitable machinery exactly as the async adapters' blockingRun
  # does, minus the future: the body responds itself (R = void), the shape
  # that used to rely on keepPin. onDone: nothing left to complete.
  let box = BlockingResultBox[int, void](body: emitBody, args: 42)
  box.onDone = proc (self: BlockingResultBase) {.gcsafe.} = discard
  dispatchBlockingResult(req, box)

var srv2 = newVortex(RequestHandler(awaitEmitHandler),
                     initVortexConfig(numThreads = 2)).start(0)
let port2 = srv2.port

const streamsPerConn = 8

var okCount2: Atomic[int]

proc awaitClientThread(a: (Port, int)) {.thread.} =
  let (p, iters) = a
  {.cast(gcsafe).}:                      # test-only h2 client, per-thread conn
    for _ in 0 ..< iters:
      var c = newH2TestConn(p)
      for i in 0 ..< streamsPerConn:     # all streams in flight at once
        c.sendHeaders(uint32(1 + 2 * i))
      let frames = c.readFrames(timeoutMs = 5000,
        until = proc(fs: seq[Frame]): bool =
          fs.count(ftHeaders) >= streamsPerConn)
      if frames.count(ftHeaders) >= streamsPerConn: okCount2.atomicInc()
      c.close()

var threads2: array[clients, Thread[(Port, int)]]
for i in 0 ..< clients:
  createThread(threads2[i], awaitClientThread, (port2, itersPer))
joinThreads(threads2)

srv2.close()
check okCount2.load == clients * itersPer
echo "awaitable-emit double-release race ok (",
     clients * itersPer * streamsPerConn, " h2 awaitable streams)"
