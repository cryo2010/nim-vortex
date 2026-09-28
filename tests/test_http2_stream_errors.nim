## Frame-level regression tests for the error SCOPE of three stream-level
## conditions (#239). Each used to be escalated to a connection error, so one
## stream's problem sent GOAWAY and aborted every other in-flight request on the
## connection:
##   1. a trailer section without END_STREAM -- RFC 9113 8.1 makes that a
##      malformed request, which is a STREAM error PROTOCOL_ERROR;
##   2. HEADERS on a half-closed(remote) stream still in the table -- RFC 9113
##      5.1 mandates a STREAM error STREAM_CLOSED;
##   3. HEADERS racing the server's own early close: the handler answered before
##      the client finished sending, so the stream was deleted while the client's
##      legally in-flight DATA and trailers were still on the wire. RFC 9113 5.1
##      requires tolerating those for a period, so they earn RST_STREAM.
## Every test also asserts the connection survives (no GOAWAY) and that a
## concurrent request on the same connection is still answered.

import std/[unittest, net, httpcore]
import vortex/[settings, request, server, streaming]
import vortex/http2/frames
import ./h2client

proc handler(req: Request, res: Response) {.gcsafe.} =
  if req.path == "/early":
    res.send(Http403, "no")      # a final response before the body has arrived
  else:
    res.send(Http200, "ok")

let routes = newStreamRoutes()
routes.streamPath("/early")      # dispatch at headers-complete, body via onBody

var srv = newVortex(RequestHandler(handler),
                    initVortexConfig(numThreads = 1),
                    routes.predicate()).start(0)

const
  getHead = @[(":method", "GET"), (":scheme", "http"), (":path", "/"),
              (":authority", "localhost")]
  postHead = @[(":method", "POST"), (":scheme", "http"), (":path", "/"),
               (":authority", "localhost")]
  earlyHead = @[(":method", "POST"), (":scheme", "http"), (":path", "/early"),
                (":authority", "localhost"), ("content-length", "10")]
  trailerSection = @[("x-trailer", "v")]

suite "HTTP/2 stream-level error scope":
  test "trailers without END_STREAM reset only that stream (RFC 9113 8.1)":
    var c = newH2TestConn(srv.port)
    var f = ""
    f.addRequest(1, postHead, endStream = false)        # body still open
    f.addRequest(1, trailerSection, endStream = false)  # trailers, no END_STREAM
    f.addRequest(3, getHead, endStream = true)          # concurrent request
    c.sendRaw(f)
    let frames = c.readFrames(1500,
      until = proc(fs: seq[Frame]): bool =
        fs.rstError(1) >= 0 and fs.hasResponse(3))
    check frames.rstError(1) == int(errProtocol)
    check frames.goawayError() == -1
    check frames.hasResponse(3)
    c.close()

  test "HEADERS on a half-closed(remote) stream reset only it (RFC 9113 5.1)":
    var c = newH2TestConn(srv.port)
    var f = ""
    # A zero initial window parks the response body, so stream 1 stays in the
    # table after END_STREAM instead of completing and being deleted.
    f.addSettingFrame(setInitialWindowSize, 0)
    f.addRequest(1, getHead, endStream = true)
    c.sendRaw(f)
    discard c.readFrames(1500,
      until = proc(fs: seq[Frame]): bool = fs.hasResponse(1))
    var g = ""
    g.addRequest(1, trailerSection, endStream = true)   # HEADERS after END_STREAM
    g.addRequest(3, getHead, endStream = true)
    c.sendRaw(g)
    let frames = c.readFrames(1500,
      until = proc(fs: seq[Frame]): bool =
        fs.rstError(1) >= 0 and fs.hasResponse(3))
    check frames.rstError(1) == int(errStreamClosed)
    check frames.goawayError() == -1
    check frames.hasResponse(3)
    c.close()

  test "frames racing an early final response reset only that stream (#239)":
    var c = newH2TestConn(srv.port)
    var f = ""
    f.addRequest(1, earlyHead, endStream = false)  # streaming route: dispatched now
    c.sendRaw(f)
    let early = c.readFrames(1500,
      until = proc(fs: seq[Frame]): bool = fs.hasResponse(1))
    check early.hasResponse(1)      # 403 without reading the body: stream closed
    # The rest of the client's request was already on the wire when the server
    # deleted the stream; it is correct client behavior, not a violation.
    var g = ""
    g.addData(1, "0123456789")
    g.addRequest(1, trailerSection, endStream = true)
    g.addRequest(3, getHead, endStream = true)     # unrelated concurrent request
    c.sendRaw(g)
    let frames = c.readFrames(1500,
      until = proc(fs: seq[Frame]): bool = fs.hasResponse(3))
    check frames.goawayError() == -1               # the connection survives
    check frames.rstError(1) == int(errStreamClosed)
    check frames.hasResponse(3)
    c.close()

srv.close()
echo "http2 stream error scope ok"
