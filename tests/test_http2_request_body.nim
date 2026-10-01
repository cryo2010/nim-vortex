## Frame-level regression coverage for the HTTP/2 request-body length
## reconciliation on streaming (onBody) routes (#237).
##
## A streaming route does not retain the body, so the buffered path's
## `body.len == content-length` check cannot be reused: the codec reconciles a
## running `bodyReceived` tally instead, at every point where the request can
## end (END_STREAM on DATA, a trailer section, and END_STREAM on the request
## HEADERS themselves) plus as soon as the tally passes the declared length.
## The last part is what makes the check useful for the smuggling scenario: a
## streaming route relays each chunk as it arrives, so excess bytes delivered
## to the sink and only *then* followed by a reset have already desynchronized
## an h1 upstream that was given the declared Content-Length.
##
## Every rejection is asserted twice: RST_STREAM(PROTOCOL_ERROR) on the wire
## (RFC 9113 8.1.1 malformed-message handling) and no response HEADERS. The
## handler answers from its EOF callback, so a response on the wire is the
## observable proof that the sink was told "body complete" while the stream was
## still live. A teardown still fires onBody(last=true) on a rejected stream so
## a suspended handler resumes (#232), but by then the stream is gone and that
## reply is discarded.

import std/[unittest, net, posix, httpcore, strutils, atomics, os]
import vortex/[settings, request, server, routing]
import vortex/http2/frames
import ./h2client

var sinkOpen: Atomic[int]    ## streaming handlers dispatched on /stream
var sinkBytes: Atomic[int]   ## body bytes handed to the streaming sink
var sinkEof: Atomic[int]     ## onBody(last=true) deliveries (clean or teardown)
var bufDone: Atomic[int]     ## buffered handlers that ran on /buffered

proc hStream(req: Request, res: Response) {.gcsafe.} =
  ## Streaming route: count what the sink receives and answer on EOF, including
  ## any trailers, so both the byte count and the trailer section are visible to
  ## the test from the wire.
  discard sinkOpen.fetchAdd(1)
  let acc = new(int)
  req.onBody proc(chunk: openArray[char], last: bool) {.gcsafe.} =
    acc[] += chunk.len
    discard sinkBytes.fetchAdd(chunk.len)
    if last:
      discard sinkEof.fetchAdd(1)
      var tr = ""
      for (n, v) in req.trailers: tr.add "|" & n & "=" & v
      res.send(Http200, "done:" & $acc[] & tr)

proc hBuffered(req: Request, res: Response) {.gcsafe.} =
  ## Buffered control route: the path that always reconciled, so the tests can
  ## show the streaming path now behaves the same way.
  discard bufDone.fetchAdd(1)
  var tr = ""
  for (n, v) in req.trailers: tr.add "|" & n & "=" & v
  res.send(Http200, "buffered:" & $req.body.len & tr)

var rt = newRouter()
rt.post("/stream", hStream, streaming = true)
rt.post("/buffered", hBuffered)

var srv = newVortex(rt.toHandler,
                    initVortexConfig(numThreads = 1,
                                     maxBodySize = 1024 * 1024),
                    rt.streamPredicate).start(0)

proc head(path: string,
          extra: openArray[(string, string)] = []): seq[(string, string)] =
  result = @[(":method", "POST"), (":scheme", "http"), (":path", path),
             (":authority", "localhost")]
  for kv in extra: result.add kv

proc sendAll(c: var H2TestConn, data: string) =
  ## posix send with correct partial-write handling: std/net's `send` re-sends
  ## from offset 0 after a partial write (duplicating bytes on the wire) and then
  ## spins forever if the peer has gone.
  var off = 0
  while off < data.len:
    let n = posix.send(c.sock.getFd, unsafeAddr data[off], data.len - off, 0)
    if n <= 0: return
    off += n

proc waitFor(cond: proc(): bool {.gcsafe.}, ms = 2000): bool =
  ## Poll a loop-thread side effect for up to `ms` milliseconds.
  for _ in 0 ..< ms div 10:
    if cond(): return true
    sleep(10)
  cond()

proc bodyOf(frames: seq[Frame], sid: uint32): string =
  for f in frames:
    if f.typ == uint8(ftData) and f.streamId == sid: result.add f.payload

proc settle(c: var H2TestConn, sid: uint32): seq[Frame] =
  ## Read until the stream is either reset or answered, so the outcome is read
  ## deterministically instead of by waiting out a quiet period.
  c.readFrames(1500, until = proc(fs: seq[Frame]): bool =
    fs.rstError(sid) >= 0 or fs.hasResponse(sid))

proc openStream(c: var H2TestConn, sid: uint32, cl: string): int =
  ## Send the request HEADERS (no END_STREAM) on their own write and wait for
  ## the handler to register its sink, then report the sink's delivered-byte
  ## count. Sending the body in a later read batch is what makes "did the excess
  ## reach the sink?" observable: a stream reset in the same batch as its
  ## HEADERS is never dispatched at all.
  let opened = sinkOpen.load()
  var f = ""
  f.addRequest(sid, head("/stream", [("content-length", cl)]),
               endStream = false)
  c.sendAll(f)
  check waitFor(proc(): bool = sinkOpen.load() > opened)
  sinkBytes.load()

suite "HTTP/2 streaming-route content-length reconciliation (#237)":
  test "DATA past content-length is rejected without waiting for END_STREAM":
    # The smuggling shape: the excess arrives in a DATA frame that does NOT
    # carry END_STREAM, so a reconciliation that only runs at the end of the
    # message hands all 1000 bytes to the sink (and never resets the stream at
    # all while the client keeps it open).
    var c = newH2TestConn(srv.port)
    discard c.readFrames(300)               # drain the server hello
    let fed = c.openStream(1, "10")
    var d = ""
    d.addData(1, 'x'.repeat(1000), endStream = false)
    c.sendAll(d)
    let fs = c.settle(1)
    check fs.rstError(1) == int(errProtocol)
    check not fs.hasResponse(1)
    check sinkBytes.load() == fed
    check fs.goawayError() == -1           # a stream error, not a teardown
    c.close()

  test "DATA longer than content-length with END_STREAM is rejected":
    var c = newH2TestConn(srv.port)
    discard c.readFrames(300)
    let fed = c.openStream(1, "10")
    var d = ""
    d.addData(1, 'x'.repeat(1000), endStream = true)
    c.sendAll(d)
    let fs = c.settle(1)
    check fs.rstError(1) == int(errProtocol)
    check not fs.hasResponse(1)
    check sinkBytes.load() == fed
    c.close()

  test "DATA shorter than content-length is rejected at END_STREAM":
    var c = newH2TestConn(srv.port)
    discard c.readFrames(300)
    let fed = c.openStream(1, "10")
    var d = ""
    d.addData(1, "ab", endStream = false)  # relayed on arrival, as it must be
    d.addData(1, "", endStream = true)     # and only now is it short
    c.sendAll(d)
    let fs = c.settle(1)
    check fs.rstError(1) == int(errProtocol)
    check not fs.hasResponse(1)
    # A short body can only be known at the end, so these two bytes do reach
    # the sink; what must not happen is a clean completion on top of them.
    check sinkBytes.load() == fed + 2
    c.close()

  test "DATA matching content-length is delivered and answered":
    var c = newH2TestConn(srv.port)
    discard c.readFrames(300)
    discard c.openStream(1, "10")
    var d = ""
    d.addData(1, "0123456789", endStream = true)
    c.sendAll(d)
    let fs = c.settle(1)
    check fs.rstError(1) == -1
    check fs.hasResponse(1)
    check fs.bodyOf(1) == "done:10"
    c.close()

  test "a mismatch revealed by a trailer section is rejected":
    var c = newH2TestConn(srv.port)
    discard c.readFrames(300)
    discard c.openStream(1, "10")
    var d = ""
    d.addData(1, "ab", endStream = false)  # END_STREAM arrives on the trailers
    d.addRequest(1, @[("x-checksum", "abc")], endStream = true)
    c.sendAll(d)
    let fs = c.settle(1)
    check fs.rstError(1) == int(errProtocol)
    check not fs.hasResponse(1)
    c.close()

  test "a matching body ended by a trailer section still completes":
    var c = newH2TestConn(srv.port)
    discard c.readFrames(300)
    discard c.openStream(1, "4")
    var d = ""
    d.addData(1, "body", endStream = false)
    d.addRequest(1, @[("x-checksum", "abc")], endStream = true)
    c.sendAll(d)
    let fs = c.settle(1)
    check fs.rstError(1) == -1
    check fs.bodyOf(1) == "done:4|x-checksum=abc"
    c.close()

  test "content-length with END_STREAM on the HEADERS is rejected undispatched":
    # No DATA frame and no trailer section ever arrives, so neither of the other
    # reconciliation sites runs; the handler must not even be dispatched, since
    # registering onBody would immediately flush a clean last=true.
    var c = newH2TestConn(srv.port)
    discard c.readFrames(300)
    let opened = sinkOpen.load()
    var f = ""
    f.addRequest(1, head("/stream", [("content-length", "10")]),
                 endStream = true)
    c.sendAll(f)
    let fs = c.settle(1)
    check fs.rstError(1) == int(errProtocol)
    check not fs.hasResponse(1)
    check sinkOpen.load() == opened
    c.close()

  test "content-length: 0 with END_STREAM on the HEADERS completes":
    var c = newH2TestConn(srv.port)
    discard c.readFrames(300)
    var f = ""
    f.addRequest(1, head("/stream", [("content-length", "0")]),
                 endStream = true)
    c.sendAll(f)
    let fs = c.settle(1)
    check fs.rstError(1) == -1
    check fs.bodyOf(1) == "done:0"
    c.close()

  test "content-length: 0 followed by DATA never reaches the sink":
    var c = newH2TestConn(srv.port)
    discard c.readFrames(300)
    let fed = c.openStream(1, "0")
    var d = ""
    d.addData(1, "xx", endStream = false)
    c.sendAll(d)
    let fs = c.settle(1)
    check fs.rstError(1) == int(errProtocol)
    check not fs.hasResponse(1)
    check sinkBytes.load() == fed
    c.close()

  test "the sink is always terminated, rejected streams included":
    # The reconciliation must not introduce a path that resets the stream
    # without firing onBody(last=true): a handler suspended in await req.read()
    # would never resume and its reader entry would leak (#232).
    var c = newH2TestConn(srv.port)
    discard c.readFrames(300)
    let eofs = sinkEof.load()
    discard c.openStream(1, "10")
    var d = ""
    d.addData(1, 'x'.repeat(64), endStream = true)
    c.sendAll(d)
    check c.settle(1).rstError(1) == int(errProtocol)
    check waitFor(proc(): bool = sinkEof.load() > eofs)
    c.close()

  test "a buffered route reconciles the same way (the #237 asymmetry)":
    var c = newH2TestConn(srv.port)
    discard c.readFrames(300)
    let ran = bufDone.load()
    var f = ""
    f.addRequest(1, head("/buffered", [("content-length", "10")]),
                 endStream = false)
    f.addData(1, 'x'.repeat(1000), endStream = true)
    c.sendAll(f)
    let fs = c.settle(1)
    check fs.rstError(1) == int(errProtocol)
    check not fs.hasResponse(1)
    check bufDone.load() == ran
    c.close()

  test "a buffered route with a matching body still succeeds":
    var c = newH2TestConn(srv.port)
    discard c.readFrames(300)
    var f = ""
    f.addRequest(1, head("/buffered", [("content-length", "4")]),
                 endStream = false)
    f.addData(1, "body", endStream = true)
    c.sendAll(f)
    let fs = c.settle(1)
    check fs.rstError(1) == -1
    check fs.bodyOf(1) == "buffered:4"
    c.close()

echo "http2 request body ok"
