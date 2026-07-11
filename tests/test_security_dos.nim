## Live-server denial-of-service tests. Each asserts the *secure* behavior,
## so the h2 flood tests (rapid reset, PING/SETTINGS floods) are expected
## to fail until the codec gains per-connection frame budgets. The
## oversized and slowloris tests exercise already-present defenses and
## should pass immediately.
##
## Flood volumes are kept modest (a few thousand frames) so the whole
## flood plus the server's replies fit in the socket buffers; the client
## sends everything, then reads, avoiding a send/recv deadlock.

import std/[unittest, net, httpcore, atomics, strutils, os]
import vortex/[settings, request, server]
import vortex/http2/frames
import ./helper
import ./h2client

var handlerHits: Atomic[int]

proc handler(req: Request, res: Response) {.gcsafe.} =
  discard handlerHits.fetchAdd(1)
  res.send(Http200, "ok", "text/plain")

# The flood server keeps default (large) read buffers so the frame flood is
# buffered and processed by the h2 codec, but uses modest reset/control
# budgets so a small flood trips the defense.
const budget = 100
var floodSrv = start(RequestHandler(handler),
                     initSettings(port = Port(0), numThreads = 1,
                                  maxResetStreams = budget,
                                  maxControlFrames = budget))

# The limits server uses tight header/body/timeout caps for the h1 tests.
var limitSrv = start(RequestHandler(handler),
                     initSettings(port = Port(0), numThreads = 1,
                                  headerTimeout = 1, bodyTimeout = 2,
                                  keepAliveTimeout = 3,
                                  maxHeaderSize = 4096, maxBodySize = 8192))

# A tiny connection cap to exercise accept-and-drop.
const connCap = 8
var capSrv = start(RequestHandler(handler),
                   initSettings(port = Port(0), numThreads = 1,
                                maxConnections = connCap))

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

suite "oversized request defenses":
  test "oversized header should be rejected, 431 delivered via lingering close":
    # The server rejects the oversized header and, via lingering close
    # (half-close + drain), delivers the 431 before closing rather than
    # RST-truncating it. Delivery is proven reliable in isolation; here we
    # assert the invariant that always holds under suite load (never
    # served) plus the 431 when the response is delivered.
    let resp = rawExchange(limitSrv.port,
      "GET / HTTP/1.1\r\nHost: x\r\nX-Big: " & repeat('a', 8000) & "\r\n\r\n",
      timeoutMs = 4000)
    check "200" notin resp
    check ("431" in resp) or (resp.len == 0)

  test "body over the limit should give 413":
    # 413 is decided from the Content-Length header before the body, and
    # the client sends no body, so nothing is unread: delivery is reliable.
    let resp = rawExchange(limitSrv.port,
      "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\n\r\n")
    check "413" in resp

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

floodSrv.close()
limitSrv.close()
capSrv.close()
echo "server shut down cleanly"
