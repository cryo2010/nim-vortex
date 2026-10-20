## Graceful-drain shutdown: requestShutdown() stops accepting, lets in-flight
## requests finish (up to shutdownGrace), then exits. An idle keep-alive
## connection is closed promptly; a request already being handled still gets
## its full response.

import std/[unittest, net, strutils, httpcore, os, monotimes, times]
import vortex/[settings, request, server]
import ./helper

proc handler(req: Request, res: Response) {.gcsafe.} =
  case req.path
  of "/slow":
    req.blocking:                          # in-flight work on the worker pool
      sleep(300)
      res.send(Http200, "done after drain")
  else:
    res.send(Http200, "ok")

var srv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, workerThreads = 2, shutdownGrace = 5)).start(0)
let port = srv.port

proc connectSock(): Socket = connectTimeout(port, 4000)

suite "graceful shutdown":
  test "an in-flight request completes, then the server exits":
    # Warm up so the port is definitely serving.
    block:
      let w = connectSock()
      w.send("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
      check "200" in w.recvUntilClose()
      w.close()

    # Start a slow request, then ask the server to shut down while it runs.
    let s = connectSock()
    s.send("GET /slow HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    sleep(100)                             # let it reach the worker
    requestShutdown()                      # begin graceful drain
    let resp = s.recvUntilClose()          # the in-flight response must arrive
    s.close()
    check "done after drain" in resp

    # After the drain, new connections are refused (listener closed) ...
    var refused = false
    for i in 0 ..< 20:
      try:
        let n = newSocket(buffered = false)
        n.connect("127.0.0.1", port)
        n.send("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        if n.recvUntilClose().len == 0: refused = true
        n.close()
      except OSError:
        refused = true
      if refused: break
      sleep(50)
    check refused

    # ... and the loop threads exit (drain finished within the grace window).
    srv.waitFor()

  # An idle loop sleeps in its selector wait for up to 1 s. A stop request used
  # to only set the flag, so close() waited for every sleeping loop to wake on
  # its own: up to the full second, per server (#418). With 8 loops whose idle
  # waits are out of phase, at least one is nearly always far from its wakeup,
  # so without the wake this measures ~0.8-1 s; with it, a few poll ticks.
  const idleLoops = 8
  const promptStopMs = 200

  proc idleServer(): Vortex =
    result = newVortex(RequestHandler(handler),
      initVortexConfig(numThreads = idleLoops, workerThreads = 1,
                       shutdownGrace = 5)).start(0)
    # One request so a loop has been through a full pass, then let every loop
    # settle into its 1 s idle wait.
    let w = connectTimeout(result.port, 4000)
    w.send("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    doAssert "200" in w.recvUntilClose()
    w.close()
    sleep(1200)

  test "close() on an idle server wakes its sleeping loops (#418)":
    var v = idleServer()
    let t0 = getMonoTime()
    v.close()
    let ms = (getMonoTime() - t0).inMilliseconds
    echo "  idle close() took ", ms, " ms"
    check ms < promptStopMs

  test "the no-arg (signal) requestShutdown wakes sleeping loops (#418)":
    var v = idleServer()
    let t0 = getMonoTime()
    requestShutdown()          # what the SIGINT/SIGTERM handler calls
    v.waitFor()
    let ms = (getMonoTime() - t0).inMilliseconds
    echo "  signal-path stop took ", ms, " ms"
    check ms < promptStopMs

  # requestShutdown(server) from an application thread while the owner blocks
  # in waitFor (the documented serve() pattern) races the owner's teardown:
  # the loops can exit and the record and wakeup descriptors be freed while the
  # request is still between its flag store and its wake writes. The request
  # holds the registry slot's reader count, which teardown waits out, so it
  # never reads a freed record or writes to a closed (or reused) descriptor.
  # Unforced, the window is narrow; this runs the race repeatedly so a sanitizer
  # or an unlucky schedule can catch a regression.
  proc stopFromThread(p: pointer) {.thread.} =
    {.gcsafe.}:
      cast[Vortex](p).requestShutdown()

  test "requestShutdown(server) from another thread races waitFor safely (#418)":
    for cycle in 0 ..< 20:
      var v = newVortex(RequestHandler(handler),
        initVortexConfig(numThreads = 2, workerThreads = 1)).start(0)
      var th: Thread[pointer]
      createThread(th, stopFromThread, cast[pointer](v))
      let t0 = getMonoTime()
      v.waitFor()
      joinThread th
      check (getMonoTime() - t0).inMilliseconds < 2000

  test "a stale requestShutdown(server) never stops the server that reused its slot (#418)":
    # v1's registry slot is free once it is torn down, and the next server
    # takes it (possibly with a record at the same address). The Server keeps
    # its slot and a registration tag, so v1's late request finds the tag
    # changed and does nothing.
    let cfg = initVortexConfig(numThreads = 1, workerThreads = 1)
    var v1 = newVortex(RequestHandler(handler), cfg).start(0)
    v1.close()
    var v2 = newVortex(RequestHandler(handler), cfg).start(0)
    v1.requestShutdown()
    sleep(100)
    let w = connectTimeout(v2.port, 4000)
    w.send("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    check "200" in w.recvUntilClose()
    w.close()
    v2.close()

  test "a start that fails after registering frees its registry slot (#418)":
    # startServer registered the shutdown record ahead of the worker pool and
    # the TLS config, outside the unwind that frees it, so every start that
    # failed on a bad certificate kept one of the registry's 256 slots (and its
    # flag, pool and worker threads) for good. After 256 of them the registry
    # was full: the next server got no slot, and the no-arg (signal)
    # requestShutdown never reached it.
    var cfg = initVortexConfig(numThreads = 1, workerThreads = 1)
    cfg.certFile = "/nonexistent/vortex-test-cert.pem"
    cfg.keyFile = "/nonexistent/vortex-test-key.pem"
    var failed = 0
    for i in 0 ..< 300:
      try:
        var bad = newVortex(RequestHandler(handler), cfg).start(0)
        bad.close()
      except CatchableError:
        inc failed
    check failed == 300
    var v = newVortex(RequestHandler(handler),
      initVortexConfig(numThreads = 1, workerThreads = 1)).start(0)
    let p = v.port
    requestShutdown()          # what the SIGINT/SIGTERM handler calls
    # A stopped loop closes its listener as its drain begins.
    var stopped = false
    let t0 = getMonoTime()
    while not stopped and (getMonoTime() - t0).inMilliseconds < 1000:
      let s = newSocket()
      try: s.connect("127.0.0.1", p, 200)
      except CatchableError: stopped = true
      s.close()
      if not stopped: sleep(10)
    echo "  stop after 300 failed starts: ",
      (getMonoTime() - t0).inMilliseconds, " ms"
    check stopped
    v.close()

echo "server shut down cleanly"
