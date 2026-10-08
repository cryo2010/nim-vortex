## HTTP/3 must not go silent on a live connection.
##
## QUIC closes an idle connection unilaterally, and RFC 9000 10.1 restarts an
## endpoint's idle timer on a packet it *receives* -- a peer that is only waiting
## for a response never refreshes its own. So an h3 connection whose application
## has nothing to send for the length of the idle window is torn down by whichever
## side notices first, reported as `Idle timeout`, against a server that is
## healthy and still serving every other connection. Two things used to make that
## reachable: the shim advertised a hardcoded 30 s window (half the h1/h2
## keepAliveTimeout, and narrower than the h3 drain grace), and ngtcp2's
## keep-alive was left at its default of disabled, so nothing ever filled a gap.
##
## The gap is ordinary: a handler that takes a while, a loop thread descheduled on
## an oversubscribed host, the shutdown drain. Here it is a `blocking:` worker --
## the response takes more than twice the whole idle window while the loop thread
## stays free.
##
## Scope, so this suite is not mistaken for more than it is. The exchanges below
## pin that keepAliveTimeout reaches the QUIC transport parameters and that a
## narrow window neither breaks a normal exchange nor truncates a slow one --
## but not, by themselves, that the server sends anything during the gap: curl's
## own QUIC stack sends keep-alive PINGs, and those refresh *our* idle timer just
## as ours refresh the peer's, so a slow response still arrives with the server's
## arming removed. The server's half is pinned instead by counting the PING
## frames we transmit, which the slow-exchange test does.
##
## That count comes from a test-only hook in the shim, built here by
## `test_h3_idle_keepalive.nims` (-d:vortexH3FrameLog): ngtcp2's frame logger is
## installed, the PINGs we transmit in a packet that carries no ACK are counted
## into a shim atomic, and `ngPingsSent()` reads it back -- the ones that rode
## with an ACK are counted apart, as `ngPingsSentWithAck()`. Removing the
## `ngtcp2_conn_set_keep_alive_timeout` call in the shim now fails this suite. A
## normal build installs no log callback at all, so none of this is in the
## server anyone ships.
##
## Why ACK-less, and what that leaves in. A PING we *received* is logged `rx`
## and never counts, which is what excludes curl's keep-alives. Of the PINGs we
## transmit, ngtcp2 writes one in three places: appended to a packet that would
## otherwise carry only non-ack-eliciting frames (a run of pure ACKs, which is
## what answering curl's keep-alives is -- it yielded two per quiet gap with the
## arming removed), at the keep-alive expiry, and as a PTO probe. The first
## rides *with* an ACK and is rejected; the other two are ACK-less. So the
## number is a LOWER bound on keep-alives, since one that fires while an ACK is
## pending rides in that packet and goes uncounted, and an UPPER bound once PTO
## probes are counted in. Both bounds are in the thresholds below: the gap
## asserts >= 3, above the two probes of a single PTO burst (six are observed,
## one per keepAliveTimeout / 3), and the fast exchange tolerates <= 2, exactly
## one burst. A burst is reachable in either window, because both of them end
## with the response, which leaves an ack-eliciting packet in flight for a late
## client ACK to probe. What is *not* reachable is a probe during the quiet gap
## itself, where the server has nothing in flight at all -- RFC 9002 6.2.1 arms
## the PTO timer only while an ack-eliciting packet is -- so the six are not
## probes.
##
## Two more things the count depends on rather than pins. It needs the client to
## write less often than keepAliveTimeout / 3 (1.33 s here): every ack-eliciting
## packet we send resets ngtcp2's keep-alive timer, and the appended PING makes
## our answer to a client PING ack-eliciting, so a chattier client suppresses
## our keep-alive altogether and this suite would read zero. curl PINGs at about
## half the idle window (2.7 s measured) -- two times the margin -- and
## `ngPingsSentWithAck()` is printed so that failure mode is recognisable rather
## than mysterious. The hook's build also turns PMTUD off, since its probes are
## padded PINGs, which is a transport config the shipped server never has: how a
## path-MTU probe and the keep-alive interact is outside what this suite says
## anything about. Still not pinned either: that the PING is what keeps a
## *non*-PINGing client alive end to end, which is what the h3 stress cells
## exercise.

import std/[unittest, net, httpcore, os, osproc, strutils]
import vortex/[settings, request, server]
import ./helper

when not defined(plainHttp):
  import vortex/http3/ngtcp2/backend   # ngPingsSent (-d:vortexH3FrameLog hook)

  when not defined(vortexH3FrameLog):
    # The sidecar .nims next to this file sets it. Without it ngPingsSent() is a
    # constant 0 and the keep-alive assertion below would fail for the wrong
    # reason, so say which knob is missing instead.
    {.error: "build this suite with -d:vortexH3FrameLog " &
             "(tests/test_h3_idle_keepalive.nims)".}

  let h3curlBin = requireH3Curl()

  # The idle window the server advertises (keepAliveTimeout), and a response
  # that takes more than twice as long to produce. Wide enough that a slow
  # handshake on a loaded machine is never mistaken for the thing under test,
  # narrow enough that the suite stays quick.
  const
    idleSec = 4
    slowMs = 9_000
    keepAliveMs = idleSec * 1000 div 3   # what the shim arms per connection

  let (certPath, keyPath) = makeCertPair("nh3_idle_")

  proc handler(req: Request, res: Response) {.gcsafe.} =
    case req.path
    of "/fast":
      res.send(Http200, "fast")
    of "/slow":
      # Off the loop thread: the loop keeps pumping QUIC (so the keep-alive can
      # fire) while nothing at all is written on this connection.
      req.blocking:
        sleep(slowMs)
        res.send(Http200, "slow done")
    else:
      res.send(Http404)

  var srv = newVortex(RequestHandler(handler),
    initVortexConfig(numThreads = 1, workerThreads = 2,
                     certFile = certPath, keyFile = keyPath,
                     keepAliveTimeout = idleSec)).start(0)
  let base = "https://localhost:" & $srv.port

  proc h3get(path: string, timeoutSec: int): (string, int) =
    ## Not helper's `h3curl`: that pins -m 10, and the point here is a response
    ## that legitimately takes longer than that.
    let (o, rc) = execCmdEx(h3curlBin & " -sk --http3-only -m " & $timeoutSec &
                            " " & base & path)
    (o.strip(), rc)

  proc pingDelta(before, after: uint64): uint64 =
    ## Both shim counters only ever increase, so this is belt and braces: were
    ## one ever to go backwards, the unsigned subtraction would wrap to an
    ## enormous number and satisfy any `>=` threshold by accident.
    if after <= before: 0'u64 else: after - before

  # The /fast exchange's PING deltas: taken around the first test's request and
  # asserted in the last one, so the suite spends one /fast request, not two.
  var fastPings, fastPingsWithAck: uint64

  suite "h3 idle timeout / keep-alive":
    test "a normal request still works with a narrow idle window":
      # Guards the plumbing: keepAliveTimeout now reaches the QUIC transport
      # parameters, and a small value must not break the handshake or the
      # exchange. The PING counters are read around it for the last test.
      let before = ngPingsSent()
      let beforeWithAck = ngPingsSentWithAck()
      let (body, rc) = h3get("/fast", 15)
      fastPings = pingDelta(before, ngPingsSent())
      fastPingsWithAck = pingDelta(beforeWithAck, ngPingsSentWithAck())
      check rc == 0
      check body == "fast"

    test "a response slower than the idle window still arrives":
      # Nothing is written on the connection for slowMs -- more than twice
      # idleSec -- and it must still complete rather than die as `Idle timeout`
      # (which curl reports by exiting non-zero and printing nothing).
      #
      # The same exchange is the pin on the server's half (#347): count the
      # ACK-less PING frames WE transmit across it. The keep-alive is armed at
      # keepAliveMs (1.33 s) and the gap is slowMs (9 s), so six are expected.
      # The assertion is >= 3: still clear of a loaded CI host that deschedules
      # the loop thread for seconds at a time, and above the two probes a single
      # PTO burst could contribute. Both counts and the gap are checkpointed so
      # a future failure can be triaged -- see the scope note above for what
      # each of them would mean.
      let before = ngPingsSent()
      let beforeWithAck = ngPingsSentWithAck()
      let (body, rc) = h3get("/slow", (slowMs div 1000) + 15)
      let pings = pingDelta(before, ngPingsSent())
      let pingsWithAck = pingDelta(beforeWithAck, ngPingsSentWithAck())
      checkpoint("gap " & $slowMs & " ms, keep-alive armed at " & $keepAliveMs &
                 " ms: ack-less tx PINGs " & $pings &
                 ", ack-companion tx PINGs " & $pingsWithAck)
      check rc == 0
      check body == "slow done"
      check pings >= 3'u64

    test "a fast exchange needs no PINGs":
      # The converse, so the count above is read as "the gap was filled" and not
      # as something every h3 connection emits: an exchange that is over in
      # milliseconds never reaches the keep-alive timer. These are the counters
      # taken around the first test's /fast request. The bound is <= 2 rather
      # than 0 because that window ends with the response too, so a late client
      # ACK can arm a PTO whose burst is two probes, and because a host loaded
      # enough to stall the exchange past 1.33 s would legitimately produce a
      # keep-alive. More than that would mean PINGs come from somewhere other
      # than a quiet gap, and the count above would stop meaning anything.
      checkpoint("fast exchange: ack-less tx PINGs " & $fastPings &
                 ", ack-companion tx PINGs " & $fastPingsWithAck)
      check fastPings <= 2'u64

  srv.stop()
  if programResult == 0:   # unittest sets it on a failed check
    echo "h3 idle keepalive ok"
else:
  echo "SKIP: HTTP/3 is not built (plainHttp)"
