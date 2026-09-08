## Worker-pool load shedding + bounded shutdown (the #204 follow-up):
##  * with maxBlockingQueue set, a saturated pool answers 503 instead of queuing
##    without bound (fail-fast, like a bounded executor / tokio's blocking pool).
##  * a `blocking:` handler that never returns cannot hang shutdown: close()
##    detaches the stuck worker/loop after shutdownHardTimeout and returns.

import std/[unittest, net, nativesockets, posix, os, times, atomics, strutils]
import std/httpclient except Response
import vortex/[settings, request, server, routing, staticfiles]
import helper

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

var bigFile: string           # set before start(); read-only afterwards

proc bigDownload(req: Request, res: Response) {.gcsafe.} =
  {.gcsafe.}:                 # bigFile is written once before the server starts
    res.sendFile(bigFile)

proc okNow(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "ok")

proc slowLong(req: Request, res: Response) {.gcsafe.} =
  req.blocking:
    sleep(1500)               # hold the single worker across the refusal window
    res.send(Http200, "ok")

suite "sendFile chunk pull vs a saturated pool (pin/filePinned balance)":
  test "a refused chunk read keeps the pin counters balanced and the server serving":
    # Regression for the filePinned saturation leak + clear() residue: a
    # sendFile whose mid-stream chunk read is refused by a saturated pool
    # (undoPinAnd503 releases the connection pin, but filePinned used to be
    # incremented unconditionally) left filePinned > pinned forever, and the
    # residue survived slot recycling (clear() never reset filePinned),
    # silently poisoning the h2 input-pause/resume gates of whatever
    # connection reused the slot. The leak itself is not client-visible on the
    # broken build (the poisoned gates corrupt pause bookkeeping, not this
    # response), so this test's hard tripwire is structural: it drives the
    # exact leak path, then recycles the slot and keeps serving -- the typed
    # pin accounting doAsserts totalPins == 0 on clear()/free, which aborts
    # the server here if the imbalance ever comes back.
    bigFile = getTempDir() / "vortex_pin_bigfile.bin"
    var payload = newString(8 * 1024 * 1024)   # > fileStreamThreshold: streams
    for i in 0 ..< payload.len: payload[i] = char(ord('a') + (i mod 23))
    writeFile(bigFile, payload)
    defer: removeFile(bigFile)

    let rt = newRouter()
    rt.get("/file", bigDownload)
    rt.get("/slow", slowLong)
    rt.get("/ok", okNow)
    var srv = newVortex(rt.toHandler, initVortexConfig(
      numThreads = 1, workerThreads = 1, maxBlockingQueue = 1)).start(0)

    # 1. Start the download but do NOT read: the server's write backlog fills
    #    (small client receive buffer forces backpressure fast) and the next
    #    chunk pull parks in onDrain.
    let a = newSocket(buffered = false)
    setSockOptInt(a.getFd, SOL_SOCKET.int, SO_RCVBUF.int, 16 * 1024)
    a.connect("127.0.0.1", srv.port)
    a.send("GET /file HTTP/1.1\r\nHost: x\r\n\r\n")
    sleep(500)                                 # let it back up and park

    # 2. Saturate the pool: one /slow runs on the single worker, a second
    #    fills the queue (cap 1). The parked chunk pull now has nowhere to go.
    let b = connectTimeout(srv.port, 4000)
    b.send("GET /slow HTTP/1.1\r\nHost: x\r\n\r\n")
    sleep(150)                                 # worker picks it up
    let c = connectTimeout(srv.port, 6000)
    c.send("GET /slow HTTP/1.1\r\nHost: x\r\n\r\n")
    sleep(150)                                 # it queues (queue now full)

    # 3. Drain the download: the backlog empties, onDrain fires, and the chunk
    #    read is refused by the saturated pool (the leak path). The stream
    #    stalls mid-body -- the refusal has no retry -- so the client sees a
    #    valid head but fewer body bytes than Content-Length.
    let got = a.recvUntilClose(1500)
    let headEnd = got.find("\r\n\r\n")
    check headEnd > 0
    check got.startsWith("HTTP/1.1 200")
    var contentLen = -1
    for line in got[0 ..< headEnd].splitLines:
      if line.toLowerAscii.startsWith("content-length:"):
        contentLen = parseInt(line.split(':')[1].strip)
    check contentLen == payload.len
    check got.len - (headEnd + 4) < contentLen   # stalled mid-stream: refusal hit
    a.close()                                    # server reaps the wedged conn

    # 4. The queued/running blocking requests still complete.
    var bResp = ""
    for _ in 0 ..< 12:
      bResp.add b.recvAvailable(500)
      if "200" in bResp: break
    check "200" in bResp
    var cResp = ""
    for _ in 0 ..< 16:
      cResp.add c.recvAvailable(500)
      if "200" in cResp: break
    check "200" in cResp
    b.close()
    c.close()
    sleep(200)                                   # let the loop reap socket A

    # 5. The slot recycles (likely onto A's freed fd) and the server keeps
    #    serving: with the leak, the recycled connection inherited poisoned
    #    pin counters (and under typed pins would abort in clear()).
    let followUp = rawExchange(srv.port,
      "GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    check "200" in followUp
    check followUp.endsWith("ok")
    # 6. Shutdown must be prompt. A refusal that leaks a pin (the bug shape
    #    under typed accounting) leaves the wedged connection pinned forever:
    #    its close is deferred, the drain prints the stuck-shutdown warning,
    #    and close() only returns via the hard-timeout detach -- well past this
    #    bound. Balanced counters close everything immediately.
    let t0 = epochTime()
    srv.close()
    check epochTime() - t0 < 5.0

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
