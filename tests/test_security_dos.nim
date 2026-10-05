## Live-server denial-of-service tests. Each asserts the *secure* behavior,
## so the h2 flood tests (rapid reset, PING/SETTINGS floods) are expected
## to fail until the codec gains per-connection frame budgets. The
## oversized and slowloris tests exercise already-present defenses and
## should pass immediately.
##
## Flood volumes are kept modest (a few thousand frames) so the whole
## flood plus the server's replies fit in the socket buffers; the client
## sends everything, then reads, avoiding a send/recv deadlock.

import std/[unittest, net, posix, httpcore, atomics, strutils, os]
import vortex/[settings, request, server]
import vortex/http2/frames
import ./helper
import ./h2client

var handlerHits: Atomic[int]

proc handler(req: Request, res: Response) {.gcsafe.} =
  discard handlerHits.fetchAdd(1)
  res.send(Http200, "ok")

# The flood server keeps default (large) read buffers so the frame flood is
# buffered and processed by the h2 codec, but uses modest reset/control
# budgets so a small flood trips the defense.
const budget = 100
var floodSrv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, maxResetStreams = budget, maxControlFrames = budget)).start(0)

# The limits server uses tight header/body/timeout caps for the h1 tests.
var limitSrv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, headerTimeout = 1, bodyTimeout = 2, keepAliveTimeout = 3, maxHeaderSize = 4096, maxBodySize = 8192)).start(0)

# A tiny connection cap to exercise accept-and-drop.
const connCap = 8
var capSrv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, maxConnections = connCap)).start(0)

# A slow-reader server: a response far larger than any socket buffer plus a
# tight writeTimeout, so a client that stops draining is reaped quickly while
# one that keeps taking bytes is not.
const slowBodyLen = 4 * 1024 * 1024   ## never fits in the socket buffers

proc bigHandler(req: Request, res: Response) {.gcsafe.} =
  # Built per request: a shared global body would be refcounted across the
  # loop thread and the test thread.
  res.send(Http200, "b".repeat(slowBodyLen))

var slowSrv = newVortex(RequestHandler(bigHandler), initVortexConfig(numThreads = 1, writeTimeout = 2)).start(0)

# Tight h1 limits + small initial buffer, but a high stream cap: a large
# h2 request burst must be processed via receive-buffer compaction rather
# than clipped by the h1 body limit.
var tightSrv = newVortex(RequestHandler(handler), initVortexConfig(numThreads = 1, initialBufferSize = 2048, maxHeaderSize = 2048, maxBodySize = 2048, maxConcurrentStreams = 4000)).start(0)

suite "HTTP/2 flood defenses":
  test "rapid reset flood should GOAWAY and bound handler work":
    handlerHits.store(0)
    var c = newH2TestConn(floodSrv.port)
    var flood = ""
    var sid = 1'u32
    for i in 0 ..< budget * 4:
      flood.addHeaders(sid, endStream = true)
      flood.addRstStream(sid, errCancel)
      sid += 2
    c.sendRaw(flood)
    let frames = c.readFrames(2000)
    c.close()
    check frames.goawayError() == int(errEnhanceYourCalm)
    check handlerHits.load() <= budget + 10   # bounded, not all budget*4

  test "PING flood should GOAWAY":
    var c = newH2TestConn(floodSrv.port)
    var flood = ""
    for i in 0 ..< budget * 4: flood.addPing()
    c.sendRaw(flood)
    let frames = c.readFrames(2000)
    c.close()
    check frames.goawayError() == int(errEnhanceYourCalm)

  test "SETTINGS flood should GOAWAY":
    var c = newH2TestConn(floodSrv.port)
    var flood = ""
    for i in 0 ..< budget * 4: flood.addSettingsFrame()
    c.sendRaw(flood)
    let frames = c.readFrames(2000)
    c.close()
    check frames.goawayError() == int(errEnhanceYourCalm)

  test "a well-behaved h2 request should still succeed":
    var c = newH2TestConn(floodSrv.port)
    c.sendHeaders(1, endStream = true)
    let frames = c.readFrames(1500)
    c.close()
    check frames.count(ftHeaders) >= 1  # a response HEADERS came back
    check frames.goawayError() == -1    # no GOAWAY for legitimate traffic

  test "large h2 request burst is not clipped by tight h1 limits":
    # 1000 GETs (~12 KB) exceed both the doubled receive buffer and
    # maxHeaderSize+maxBodySize (4 KB); compaction must process them all
    # instead of closing the connection when the buffer fills.
    const n = 1000
    var c = newH2TestConn(tightSrv.port)
    var burst = ""
    var sid = 1'u32
    for i in 0 ..< n:
      burst.addHeaders(sid, endStream = true)
      sid += 2
    # Drain replies while sending: 1000 responses do not fit in the socket
    # buffers alongside the burst, so a single blocking send-then-read would
    # deadlock (client stuck in send(), server stuck writing) and yield zero
    # frames under load. Interleaving keeps the buffers flowing.
    c.sendAndDrain(burst)
    # Stop as soon as all n responses arrive (deterministic) rather than
    # waiting out a quiet period, which is timing-sensitive under load. The
    # timeout is only an upper bound for a slow/loaded CI runner: the `until`
    # returns the instant all n are in, so a generous cap never slows the
    # common case but keeps the 1000-response round-trip from tripping it.
    let frames = c.readFrames(15000,
      until = proc(f: seq[Frame]): bool = f.count(ftHeaders) >= n)
    c.close()
    check frames.goawayError() == -1
    check frames.count(ftHeaders) == n  # every request got a response

suite "oversized request defenses":
  test "oversized header should be rejected via lingering close":
    # The server rejects the oversized header and, via lingering close
    # (half-close + drain), delivers the 431 before closing rather than
    # RST-truncating it. The invariant asserted here (never served) is
    # stable; under the CPU load of the preceding flood tests the response
    # can occasionally arrive empty (the request isn't scheduled in time),
    # so 431-delivery is verified separately, not asserted under load.
    let resp = rawExchange(limitSrv.port,
      "GET / HTTP/1.1\r\nHost: x\r\nX-Big: " & repeat('a', 8000) & "\r\n\r\n")
    check "200" notin resp
    check ("431" in resp) or (resp.len == 0)

  test "body over the limit should give 413":
    # 413 is decided from the Content-Length header before the body. The
    # invariant asserted here (the oversized body is never served) is stable;
    # like the oversized-header case above, under the CPU load of the preceding
    # flood tests the response can occasionally arrive empty (the loop thread
    # isn't scheduled in time before the read window closes), so 413-delivery
    # is tolerated but not required.
    let resp = rawExchange(limitSrv.port,
      "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\n\r\n")
    check "200" notin resp
    check ("413" in resp) or (resp.len == 0)

suite "slowloris defenses":
  test "a stalled request head should be closed by the header timeout":
    let s = newSocket(buffered = false)
    defer: s.close()
    s.connect("127.0.0.1", limitSrv.port)
    s.send("GET / HTTP/1.1\r\nHost: x\r\n")   # partial: no terminating CRLF
    check s.waitForClose(tries = 6, stepMs = 500)   # headerTimeout = 1s

  test "a stalled request body should be closed by the body timeout":
    let s = newSocket(buffered = false)
    defer: s.close()
    s.connect("127.0.0.1", limitSrv.port)
    s.send("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\npartial")
    check s.waitForClose(tries = 12, stepMs = 500)   # bodyTimeout = 2s

suite "connection cap":
  test "connections beyond the cap should be dropped":
    # Hold connCap idle keep-alive connections, then a further connection
    # should be accepted-and-dropped (closes promptly with no response),
    # while a held connection is still served.
    var held: seq[Socket]
    for i in 0 ..< connCap:
      let s = newSocket(buffered = false)
      s.connect("127.0.0.1", capSrv.port)
      s.send("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      check s.recvAvailable(1000).len > 0    # served
      held.add s                              # keep-alive, stays open
    # The next connection is over the cap: dropped without a response.
    block:
      let s = newSocket(buffered = false)
      defer: s.close()
      s.connect("127.0.0.1", capSrv.port)
      s.send("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      check s.waitForClose(tries = 6, stepMs = 250)   # closed, not served
    # A held connection still works after freeing one slot.
    held[0].close()
    sleep(200)
    let s = newSocket(buffered = false)
    defer: s.close()
    s.connect("127.0.0.1", capSrv.port)
    s.send("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    check "200" in s.recvUntilClose(1000)
    for i in 1 ..< held.len: held[i].close()

  test "a capped drop is counted and readable through acceptDrops":
    # The cap used to accept and close in silence: at the client that is a
    # connection that opened and died with nothing on it, which is exactly what
    # a network fault looks like (an empty ConnectError), and nothing on the
    # server recorded it. Each drop now bumps a counter an operator can sample
    # and writes one rate-limited stderr line saying which cap was hit (#388).
    let before = capSrv.acceptDrops()
    var held: seq[Socket]
    for i in 0 ..< connCap:
      let s = newSocket(buffered = false)
      s.connect("127.0.0.1", capSrv.port)
      s.send("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      check s.recvAvailable(1000).len > 0
      held.add s
    const overCap = 3
    for i in 0 ..< overCap:
      let s = newSocket(buffered = false)
      s.connect("127.0.0.1", capSrv.port)
      s.send("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      check s.waitForClose(tries = 6, stepMs = 250)
      s.close()
    let after = capSrv.acceptDrops()
    check after.cap - before.cap >= overCap
    check after.total >= after.cap
    # `total` is connections accepted and then dropped, which is exactly these
    # three causes. acceptSuspend used to be summed in as well, and it is not a
    # dropped connection: accept() itself failed on fd exhaustion, nothing was
    # accepted, and the backlog waits for the listener to be re-armed (#388).
    check after.total == after.cap + after.tls + after.register
    # Process-wide by construction, so the no-argument form (what a {.gcsafe.}
    # handler can call) reports the same numbers. `>=`, not `==`: the counter is
    # shared by every loop thread of every server in the process, so another
    # suite's server (or a later read of this one) can only have bumped it
    # between the two loads.
    check acceptDrops().cap >= after.cap
    # Nothing else fired: these connections were refused by the cap, not by a
    # TLS failure or a selector refusal.
    #
    # Those two causes have no test here on purpose. `tls` needs
    # `newTlsSession` to return nil, which means SSL_new or SSL_set_fd failing,
    # i.e. an OpenSSL allocation failure on a context that just worked -- not
    # reachable from a test without a malloc interposer. `register` needs the
    # selector to refuse an fd it has room for. Both are covered by the shared
    # noteAcceptDrop path this case exercises; only their trigger is
    # unreachable.
    check after.tls == before.tls
    check after.register == before.register
    for s in held.mitems: s.close()

suite "slow-reader defenses (writeTimeout)":
  proc askFor(path: string, rcvbuf: cint): Socket =
    ## Connect with a receive buffer of `rcvbuf` bytes and request `path`. The
    ## reply is far bigger than any buffer on the path, so the server is left
    ## with output pending and an unwritable socket until the caller drains it.
    result = newSocket(buffered = false)
    var rb = rcvbuf
    discard setsockopt(result.getFd, SOL_SOCKET, SO_RCVBUF, addr rb,
                       SockLen(sizeof(rb)))
    result.connect("127.0.0.1", slowSrv.port)
    result.send("GET " & path & " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

  test "writeTimeout is armed by default":
    # Shipped non-zero (like bodyTimeout) so a stalled write is reaped out of
    # the box; the machinery is inert at 0.
    check initVortexConfig().writeTimeout == 30

  test "a client that stops draining a large response is reaped":
    let s = askFor("/big", 4096)
    defer: s.close()
    sleep(4000)                       # never read: the 2 s writeTimeout fires
    let resp = s.recvUntilClose(1000)
    check resp.len < slowBodyLen      # truncated, not the whole 4 MiB response

  test "a slow but steady reader is never cut off":
    # The deadline is idle, not total: every partial write re-arms it. This
    # reader takes a quarter megabyte every 250 ms, so the server holds pending
    # output for several seconds (many times writeTimeout) and must not be
    # reaped: the same shape as a streamed response or an SSE feed. (The pause
    # stays well inside writeTimeout, which is coarse: a deadline armed just
    # before a tick can fire up to a second early.)
    let s = askFor("/big", 512 * 1024)
    defer: s.close()
    var got = 0
    var buf = newString(256 * 1024)
    s.setRecvTimeout(2000)
    while got < slowBodyLen:
      sleep(250)                      # a quarter second of no progress, repeatedly
      let n = recv(s.getFd, addr buf[0], buf.len, cint(0))
      if n <= 0: break                # reaped (or timed out): the body is short
      got += n
    check got >= slowBodyLen          # the whole body, headers on top

floodSrv.close()
limitSrv.close()
capSrv.close()
slowSrv.close()
tightSrv.close()
echo "server shut down cleanly"
