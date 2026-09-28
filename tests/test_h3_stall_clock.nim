## The clock HTTP/3 hands ngtcp2 must never go backwards.
##
## ngtcp2 arms its idle, keep-alive and loss-detection timers as absolute stamps
## on the clock the shim passes into every entry point (recv, pump, expiry,
## next-expiry), and it re-checks that clock on each of them:
##
##   stress_server: ngtcp2_conn.c:88: conn_update_timestamp:
##     Assertion `conn->log.last_ts <= ts' failed.
##
## So anything that withholds time from that clock -- notably crediting a
## loop-thread stall there the way the h1/h2 deadline wheel is credited
## (creditStall) -- aborts the whole process the next time a packet is pumped.
## Ordering cannot rescue it either: run() drives h3 *before* it ticks, so the
## drive that follows a stall has already handed ngtcp2 the full elapsed time
## before the gap is even measured, and a credit applied from the tick can only
## rewind it. A quiet h3 connection is kept alive at the protocol level instead
## (an idle window as wide as keepAliveTimeout, plus ngtcp2's keep-alive PING),
## which needs no clock lie.
##
## Two halves: the clock contract itself, then a live h3 connection across a real
## loop-thread stall -- the path from the crash traceback (run -> h3Drive ->
## ngReceive, and tick -> sweepWsIdle -> h3Drive -> ngPump). A regression there
## does not fail a `check`; it aborts this process, exactly as it aborted the
## stress server.

import std/[unittest, net, httpcore, os]
import vortex/[settings, request, server]
import ./helper

when not defined(plainHttp):
  import vortex/http3/ngtcp2/backend

  const
    stallMs = 3_000   ## longer than the loop's stall-credit threshold (2 s), so
                      ## the tick after it takes the creditStall branch for real
    samples = 500

  suite "the ngtcp2 clock is monotonic across a loop-thread stall":
    test "no stamp decreases, and the stall is not withheld from the clock":
      # ngNowNs is the single clock every ngtcp2 entry point is handed, so these
      # are the stamps ngtcp2 sees.
      var prev = ngNowNs()
      let first = prev
      for _ in 1 .. samples:
        let t = ngNowNs()
        check t >= prev
        prev = t

      sleep(stallMs)      # the loop thread was not running at all for stallMs

      # A stall credit used to be applied right here (the loop's creditStall
      # calling into the backend). Nothing may be: the next stamp ngtcp2 gets has
      # to be at least the last one it has already seen.
      let afterStall = ngNowNs()
      check afterStall >= prev
      prev = afterStall
      for _ in 1 .. samples:
        let t = ngNowNs()
        check t >= prev
        prev = t

      # And the stall has to be *in* the clock rather than carried as an offset
      # that only a later rewind could repay: the whole sleep must show up.
      check prev - first >= uint64(stallMs - 200) * 1_000_000'u64

  let h3curlBin = requireH3Curl()
  let (certPath, keyPath) = makeCertPair("nh3_stallclock_")

  proc handler(req: Request, res: Response) {.gcsafe.} =
    if req.path == "/stall":
      # On the loop thread deliberately: with numThreads = 1 this is exactly a
      # descheduled loop thread, and the loop's coarse clock keeps running while
      # no ngtcp2 entry point is driven.
      sleep(stallMs)
      res.send(Http200, "stalled")
    else:
      res.send(Http200, "ok")

  var srv = newVortex(RequestHandler(handler),
    initVortexConfig(numThreads = 1,
                     certFile = certPath, keyFile = keyPath)).start(0)
  let base = "https://localhost:" & $srv.port

  suite "h3 survives a loop-thread stall":
    test "a request that stalls the loop thread still completes":
      let (body, rc) = h3curl(h3curlBin, base & "/stall")
      check rc == 0
      check body == "stalled"

    test "h3 still serves after the stall":
      # These are the drives that a credit would have handed a rewound stamp, so
      # a clock that went backwards has already aborted the server by now.
      for _ in 1 .. 3:
        let (body, rc) = h3curl(h3curlBin, base & "/after")
        check rc == 0
        check body == "ok"

  srv.stop()
  removeDir(certPath.parentDir)
  echo "h3 stall clock ok"
else:
  echo "SKIP: HTTP/3 is not built (plainHttp)"
