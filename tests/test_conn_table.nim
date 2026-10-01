## #343: the per-loop connection table grows while a slot is pinned.
##
## `handleAccept` used to refuse an accepted fd beyond the table whenever any
## slot was pinned, because growing a flat `seq[Connection]` moves every element
## and a `blocking:` worker holds `addr conns[fd]` for the length of its handler.
## The connection was accepted and immediately closed with no log line, which
## from the client is an empty connect error. The table is segmented now, so
## growth appends a block, leaves the existing ones where they are, and the high
## fd is served.
##
## The suite is compiled with `-d:vortexConnBlock=8` (tests/test_conn_table.nims),
## so a handful of connections force several growth events and the scenario is
## reachable without touching the fd rlimit.

import std/[unittest, net, os, strutils, times, httpcore]
import vortex/[settings, request, server, routing, connection]
import ./helper

const blockSlots {.intdefine: "vortexConnBlock".} = 1024

# Long enough that opening and serving two dozen loopback connections is
# comfortably inside the window on a loaded host, so the growth really does
# happen under a live pin rather than after the worker woke up.
const pinMs = 5000

proc slow(req: Request, res: Response) {.gcsafe.} =
  ## Pins its connection on a worker: the loop thread keeps accepting meanwhile,
  ## and the worker's `ptr Connection` must survive every growth that follows.
  req.blocking:
    sleep(pinMs)
    res.send(Http200, "pinned-ok")

proc quick(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "served")

suite "ConnTable (structural)":
  test "the compile-time block size is in effect for this suite":
    check blockSlots == 8
    check initConnTable().blockSize == 8

  test "a block size is rounded up to a power of two":
    check initConnTable(8).blockSize == 8
    check initConnTable(5).blockSize == 8
    check initConnTable(1).blockSize == 1
    check initConnTable(1024).blockSize == 1024

  test "growth appends blocks and never moves a slot":
    # The invariant the fix rests on, asserted directly: a pointer taken into a
    # block stays valid, and the slot keeps its value (including a GC'd field,
    # which a payload copy would have duplicated) across later growth.
    var t = initConnTable(8)
    check t.len == 8
    let p = t.at(3)
    p.fd = 1234
    p.remoteAddr = "pinned"
    t.grow(100)
    check t.len == 104               # whole blocks only: 13 * 8
    check t.at(3) == p               # same address, not a copy
    check p.fd == 1234
    check p.remoteAddr == "pinned"
    t.grow(1000)
    check t.at(3) == p               # and again, through many more blocks
    check p.remoteAddr == "pinned"

  test "the index split addresses every slot distinctly":
    var t = initConnTable(8)
    t.grow(20)
    check t.len == 24
    for i in 0 ..< t.len: t.at(i).fd = int32(i)
    for i in 0 ..< t.len: check t.at(i).fd == int32(i)

  test "slots iterates every slot in fd order":
    var t = initConnTable(8)
    t.grow(20)
    var n = 0
    for c in t.slots:
      check c == t.at(n)
      inc n
    check n == t.len

suite "a pinned slot no longer blocks connection-table growth (#343)":
  test "high fds are served while a blocking: worker holds a pin":
    let rt = newRouter()
    rt.get("/slow", slow)
    rt.get("/quick", quick)
    withServer(rt.toHandler,
               initVortexConfig(numThreads = 1, workerThreads = 1), srv):
      let port = srv.port

      # 1. Take the pin: /slow dispatches to the worker pool and sleeps there.
      let pinned = connectTimeout(port, pinMs + 5000)
      pinned.send("GET /slow HTTP/1.1\r\nHost: x\r\n\r\n")
      sleep(300)                     # let the handler reach the worker

      # 2. With that pin held, open enough connections to walk the fd well past
      #    the 8-slot first block (several growth events). Every one of these is
      #    a connection the old code would have accepted and silently dropped.
      const extra = 24
      var socks: seq[Socket]
      let t0 = epochTime()
      for i in 0 ..< extra:
        let s = connectTimeout(port, 5000)
        socks.add s
        s.send("GET /quick HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
      var served = 0
      for s in socks:
        let resp = s.recvUntilClose(5000)
        if resp.startsWith("HTTP/1.1 200 OK") and "served" in resp: inc served
        s.close()
      let elapsed = epochTime() - t0
      check served == extra
      # The worker sleeps pinMs, so finishing inside that window is what makes
      # the growth above concurrent with the pin rather than after it.
      check elapsed < float(pinMs) / 1000.0

      # 3. The pinned request still completes, and on its own connection: the
      #    worker wrote its response through the `ptr Connection` it took before
      #    any of that growth.
      let pinnedResp = pinned.recvAvailable(pinMs + 5000)
      pinned.close()
      check pinnedResp.startsWith("HTTP/1.1 200 OK")
      check "pinned-ok" in pinnedResp

echo "conn table ok"
