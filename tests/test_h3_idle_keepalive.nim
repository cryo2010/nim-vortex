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
## Scope, so this suite is not mistaken for more than it is: it pins that
## keepAliveTimeout reaches the QUIC transport parameters and that a narrow window
## neither breaks a normal exchange nor truncates a slow one. It does *not* fail
## with the keep-alive arming removed, because curl's own QUIC stack sends
## keep-alive PINGs and those refresh our timer just as ours refresh the peer's.
## A client that does not PING -- aioquic, which is what the stress soak drives
## and what reported `Idle timeout` here -- is the only thing that can observe the
## server's half, so that half is validated by the h3 stress cells, not from here.

import std/[unittest, net, httpcore, os, osproc, strutils]
import vortex/[settings, request, server]
import ./helper

let h3curlBin = requireH3Curl()

# The idle window the server advertises (keepAliveTimeout), and a response that
# takes more than twice as long to produce. Wide enough that a slow handshake on
# a loaded machine is never mistaken for the thing under test, narrow enough that
# the suite stays quick.
const
  idleSec = 4
  slowMs = 9_000

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

suite "h3 idle timeout / keep-alive":
  test "a normal request still works with a narrow idle window":
    # Guards the plumbing: keepAliveTimeout now reaches the QUIC transport
    # parameters, and a small value must not break the handshake or the exchange.
    let (body, rc) = h3get("/fast", 15)
    check rc == 0
    check body == "fast"

  test "a response slower than the idle window still arrives":
    # Nothing is written on the connection for slowMs -- more than twice idleSec
    # -- and it must still complete rather than die as `Idle timeout` (which curl
    # reports by exiting non-zero and printing nothing).
    let (body, rc) = h3get("/slow", (slowMs div 1000) + 15)
    check rc == 0
    check body == "slow done"

srv.stop()
echo "h3 idle keepalive ok"
