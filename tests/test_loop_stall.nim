## A starved loop thread must not reap connections whose peers did nothing wrong.
##
## Every per-connection deadline is an absolute monotonic stamp and sweepTimeouts
## only runs when the loop's coarse clock changes, so a loop thread that does not
## run for N seconds would otherwise fire, in one pass, every deadline that fell
## inside those N seconds. On an oversubscribed host that is the common case (the
## stress soaks measured loop threads descheduled for up to 33 s while the
## handshake budget is 10 s), and the peer sees an unexplained reset: no GOAWAY on
## h2, no alert mid-handshake, a truncated request or response otherwise.
##
## Here the stall is produced from inside the server instead of by the scheduler:
## with numThreads = 1 a handler that blocks holds the only loop thread exactly as
## a deschedule would, and the clock the deadlines are measured against keeps
## running. The other connection is idle and blameless throughout.

import std/[unittest, net, os, httpcore, strutils]
import vortex/[settings, request, server, routing]
import ./helper

const
  idleTimeout = 4       ## keepAliveTimeout: the blameless connection's budget
  stallSecs = 6         ## > idleTimeout, so the deadline falls inside the stall

proc hello(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "ok")

proc stall(req: Request, res: Response) {.gcsafe.} =
  ## Hold the (single) loop thread past idleTimeout, like a descheduled thread.
  sleep(stallSecs * 1000)
  res.send(Http200, "stalled")

proc get(s: Socket, path: string) =
  s.send("GET " & path & " HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n")

suite "loop-thread stall is not charged to the peer":
  setup:
    let rt = newRouter()
    rt.get("/", hello)
    rt.get("/stall", stall)

  test "an idle keep-alive connection survives a stall longer than keepAliveTimeout":
    var srv = newVortex(rt.toHandler,
      initVortexConfig(numThreads = 1, keepAliveTimeout = idleTimeout,
                       headerTimeout = 30)).start(0)
    defer: srv.close()

    # The blameless connection: one request, then idle. Its idle deadline is now
    # armed for idleTimeout seconds from here.
    let idle = newSocket(buffered = false)
    defer: idle.close()
    idle.connect("127.0.0.1", srv.port)
    idle.get("/")
    check "200" in idle.recvAvailable(3000)

    # Take the loop thread away for longer than that deadline.
    let blocker = newSocket(buffered = false)
    defer: blocker.close()
    blocker.connect("127.0.0.1", srv.port)
    blocker.get("/stall")
    check "200" in blocker.recvAvailable((stallSecs + 6) * 1000)

    # The idle connection was never at fault -- the server simply could not have
    # served it. It must still be usable, not reset for "going quiet".
    idle.get("/")
    check "200" in idle.recvAvailable(5000)

  test "a peer that really does go quiet is still reaped after the stall":
    # The credit must not turn the timeout off: the same idle connection, given no
    # stall to hide behind, is still closed once its budget elapses for real.
    var srv = newVortex(rt.toHandler,
      initVortexConfig(numThreads = 1, keepAliveTimeout = 1,
                       headerTimeout = 30)).start(0)
    defer: srv.close()
    let idle = newSocket(buffered = false)
    defer: idle.close()
    idle.connect("127.0.0.1", srv.port)
    idle.get("/")
    check "200" in idle.recvAvailable(3000)
    check idle.waitForClose(tries = 10, stepMs = 500)
