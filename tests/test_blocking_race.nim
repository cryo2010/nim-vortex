## ThreadSanitizer regression for C3 / IMP2: a `req.blocking:` worker must read
## a request SNAPSHOT, never live loop memory. Over HTTP/2 the old code had the
## worker call h2Field / h2Stream, materializing H2Conn/H2Stream refs and racing
## the loop's non-atomic ORC refcounts. This drives many concurrent h2c blocking
## requests across several loop threads + the worker pool; built under TSan by
## `nimble testrace`, TSan aborts on any data race.

import std/[net, atomics]
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
    doAssert sink >= 0
    res.send(Http200, "ok", "text/plain")

var srv = start(RequestHandler(handler),
                initSettings(port = Port(0), numThreads = 4))
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
doAssert okCount.load == clients * itersPer,
  "expected " & $(clients * itersPer) & " responses, got " & $okCount.load
echo "blocking race regression ok (", okCount.load, " h2 blocking requests)"
