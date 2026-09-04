## Worker-pool load shedding + bounded shutdown (the #204 follow-up):
##  * with maxBlockingQueue set, a saturated pool answers 503 instead of queuing
##    without bound (fail-fast, like a bounded executor / tokio's blocking pool).
##  * a `blocking:` handler that never returns cannot hang shutdown: close()
##    detaches the stuck worker/loop after shutdownHardTimeout and returns.

import std/[unittest, net, os, times, atomics]
import std/httpclient except Response
import vortex/[settings, request, server, routing]

proc slow(req: Request, res: Response) {.gcsafe.} =
  req.blocking:
    sleep(400)                    # occupy the single worker for a while
    res.send(Http200, "ok")

proc stuck(req: Request, res: Response) {.gcsafe.} =
  req.blocking:
    sleep(60_000)                 # never returns within the test: a wedged worker
    res.send(Http200, "unreachable")

suite "worker-pool load shedding (maxBlockingQueue)":
  test "a saturated pool answers 503 instead of queuing unbounded":
    # 1 worker + queue cap 1: one request runs, one queues, the rest are shed.
    let rt = newRouter()
    rt.get("/slow", slow)
    var srv = newVortex(rt.toHandler, initVortexConfig(
      numThreads = 1, workerThreads = 1, maxBlockingQueue = 1)).start(0)
    let base = "http://127.0.0.1:" & $srv.port

    const n = 6
    var codes: array[n, Atomic[int]]
    proc hit(a: (int, Port)) {.thread.} =
      let (i, p) = a
      var c = newHttpClient()
      try:
        let r = c.get("http://127.0.0.1:" & $p & "/slow")
        codes[i].store(r.code.int)
      except CatchableError:
        codes[i].store(-1)
      finally: c.close()

    var threads: array[n, Thread[(int, Port)]]
    for i in 0 ..< n: createThread(threads[i], hit, (i, srv.port))
    joinThreads(threads)

    var ok, shed = 0
    for i in 0 ..< n:
      if codes[i].load == 200: inc ok
      elif codes[i].load == 503: inc shed
    check ok >= 1          # at least the running + queued request succeed
    check shed >= 1        # the rest are load-shed with 503
    srv.close()

suite "bounded shutdown (never-returning blocking handler)":
  test "close() returns within the hard timeout instead of hanging":
    let rt = newRouter()
    rt.get("/stuck", stuck)
    var srv = newVortex(rt.toHandler, initVortexConfig(
      numThreads = 1, workerThreads = 1, shutdownGrace = 1,
      shutdownHardTimeout = 2)).start(0)
    # Fire a request that pins a worker in a 60s sleep, but don't read the reply.
    let s = newSocket()
    s.connect("127.0.0.1", srv.port)
    s.send("GET /stuck HTTP/1.1\r\nHost: x\r\n\r\n")
    sleep(300)                      # let the worker pick it up and pin the conn
    let t0 = epochTime()
    srv.close()                     # must NOT wait out the 60s sleep
    let elapsed = epochTime() - t0
    check elapsed < 6.0             # detached after ~shutdownHardTimeout (2s)
    s.close()

echo "blocking pool ok"
