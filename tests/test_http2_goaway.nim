## HTTP/2 closes the server decides on its own must announce themselves with a
## GOAWAY first (#342). A bare TCP close is indistinguishable from a network
## fault, so a client cannot tell a server-side timeout from a broken link and
## will not retry even an idempotent request it knows was never processed. The
## GOAWAY carries the last stream id this server handled, which makes everything
## above it known-unhandled (and the error code says why the connection went).

import std/[unittest, net, httpcore]
import vortex/[settings, request, server]
import vortex/http2/frames
import ./h2client

proc handler(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "ok")

# Tight idle/body timeouts so the sweep fires within the test's read window.
var srv = newVortex(RequestHandler(handler),
                    initVortexConfig(numThreads = 1, headerTimeout = 2,
                                     bodyTimeout = 1,
                                     keepAliveTimeout = 1)).start(0)

suite "HTTP/2 timeout closes announce a GOAWAY":
  test "an idle connection is closed with GOAWAY(NO_ERROR) naming the last stream":
    var c = newH2TestConn(srv.port)
    c.sendHeaders(1)                      # one request, then go idle
    let frames = c.readFrames(4000)       # returns on the timeout close (EOF)
    c.close()
    check frames.count(ftHeaders) == 1    # the request really was served
    check frames.goawayError() == int(errNoError)
    check frames.goawayLastStreamId() == 1  # stream 1 was processed, retry above it
    check frames[^1].typ == uint8(ftGoaway)   # last frame before EOF

  test "a stalled request body is closed with GOAWAY, not a bare EOF":
    var c = newH2TestConn(srv.port)
    c.sendHeaders(1, endStream = false)   # promise a body, then send nothing
    let frames = c.readFrames(4000)       # bodyTimeout closes the connection
    c.close()
    check frames.count(ftHeaders) == 0    # the handler never ran
    check frames.goawayError() == int(errNoError)
    check frames.goawayLastStreamId() == 1

srv.close()
echo "server shut down cleanly"
