## Regression for h2spec 6.9.2: changing SETTINGS_INITIAL_WINDOW_SIZE after
## a stream exists must resize that stream's send window and flush any DATA
## the larger window unblocks (RFC 7540 6.9.2).

import std/[unittest, net, httpcore]
import vortex/[settings, request, server]
import vortex/http2/frames
import ./h2client

proc handler(req: Request, res: Response) {.gcsafe.} =
  res.send(Http200, "hello h2", "text/plain")     # 8-byte body

var srv = start(RequestHandler(handler),
                initSettings(port = Port(0), numThreads = 1))

proc addInitialWindow(buf: var string, value: uint32) =
  var payload = ""
  payload.addSetting(setInitialWindowSize, value)
  buf.addFrameHeader(payload.len, ftSettings, 0, 0)
  buf.add payload

suite "HTTP/2 flow control":
  test "raising INITIAL_WINDOW_SIZE flushes DATA blocked on a zero window":
    var c = newH2TestConn(srv.port)

    # Pin the initial window to 0, then open a stream. The response body is
    # blocked: HEADERS arrive, DATA cannot.
    var open = ""
    open.addInitialWindow(0)
    open.addHeaders(1)                              # :path / , END_STREAM
    c.sendRaw(open)

    var frames = c.readFrames(800)
    check frames.count(ftHeaders) >= 1             # response headers sent
    check frames.count(ftData) == 0                # body withheld (window 0)

    # Grow the window; the previously blocked DATA must now be delivered.
    var grow = ""
    grow.addInitialWindow(100)
    c.sendRaw(grow)

    frames = c.readFrames(1500,
      until = proc(fr: seq[Frame]): bool = fr.count(ftData) >= 1)
    check frames.count(ftData) == 1
    var payload = ""
    var endStream = false
    for fr in frames:
      if fr.typ == uint8(ftData):
        payload = fr.payload
        endStream = (fr.flags and flagEndStream) != 0
    check payload == "hello h2"
    check endStream                                # stream completes
    c.close()

srv.close()
echo "server shut down cleanly"
